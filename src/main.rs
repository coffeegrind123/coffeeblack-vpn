use awg_easy_rs::{activity, api, config, db, firewall, init_setup, wg};

use std::net::SocketAddr;
use std::sync::OnceLock;
use axum::{Router, routing::get, response::Response, http::{header, HeaderMap, StatusCode}};
use tracing_subscriber::EnvFilter;

// Embedded frontend
const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");
const FAVICON_PNG: &[u8] = include_bytes!("../static/favicon.png");
const FAVICON_AWG_ICO: &[u8] = include_bytes!("../static/favicon-amnezia.ico");
const LOGO_PNG: &[u8] = include_bytes!("../static/logo.png");
const LOGO_AWG_SVG: &[u8] = include_bytes!("../static/logo-amnezia.svg");
const APPLE_ICON: &[u8] = include_bytes!("../static/apple-touch-icon.png");
const APPLE_ICON_AWG: &[u8] = include_bytes!("../static/apple-touch-icon-amnezia.png");
const MANIFEST_JSON: &[u8] = include_bytes!("../static/manifest.json");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // `--privileged-helper` runs the root side and nothing else: no database,
    // no HTTP listener, no supervisors. Handled before any of that is set up
    // precisely so the privileged process carries none of it — the whole point
    // is that the code holding CAP_NET_ADMIN is small enough to audit.
    if std::env::args().any(|a| a == "--privileged-helper") {
        let cfg = awg_easy_rs::privhelper::HelperConfig {
            socket_path: awg_easy_rs::privhelper::socket_path()
                .unwrap_or_else(|| awg_easy_rs::privhelper::DEFAULT_SOCKET.into()),
            interface: std::env::var("WG_EASY_HELPER_INTERFACE")
                .unwrap_or_else(|_| "awg0".to_string()),
            conf_dir: config::CONFIG.wg_conf_dir.clone().into(),
            allow_gid: std::env::var("WG_EASY_HELPER_GID")
                .ok()
                .and_then(|g| g.parse().ok()),
        };
        return awg_easy_rs::privhelper::serve(cfg);
    }

    db::init_db()?;
    tracing::info!("Database initialized");

    // In-memory mode promises "entirely in RAM". The DB and the bundled
    // binaries honour that on their own (`:memory:` + memfd), but the
    // generated configs, the AmneziaWG `.conf`, and tor's data directory
    // still live under the runtime dirs — so those must be on a tmpfs for
    // the promise to hold. Warn (don't fail) when they aren't: a misconfig
    // here silently reintroduces the disk dependency the operator is trying
    // to escape.
    if config::CONFIG.in_memory {
        // Check every directory that receives a rendered credential, not just
        // the WireGuard one. Each bundled transport writes its own config
        // holding its own secrets — the Reality private key and client UUIDs,
        // the MTProxy user secrets, the DNS-tunnel encryption key — and each
        // has its own configurable path, so checking one dir and reporting
        // "RAM-backed" was answering for files it does not contain.
        for (label, dir) in [
            ("WireGuard", &config::CONFIG.wg_conf_dir),
            ("Xray (Reality key, client UUIDs)", &config::CONFIG.xray_dir),
            ("MTProxy (user secrets)", &config::CONFIG.mtproxy_dir),
            ("MasterDnsVPN (tunnel key)", &config::CONFIG.mdnsvpn_dir),
            ("DNS bundle", &config::CONFIG.dns_dir),
        ] {
            match awg_easy_rs::memexec::is_ram_backed(dir) {
                Some(true) => {
                    tracing::info!("IN_MEMORY: {label} dir {dir} is tmpfs (RAM-backed)")
                }
                Some(false) => tracing::warn!(
                    "IN_MEMORY is set but the {label} dir {dir} is NOT tmpfs — the \
                     credentials rendered there reach a block device. Mount it as \
                     tmpfs (the bundled docker-compose does). The files are written \
                     0600, so this is a persistence concern rather than an access one."
                ),
                None => {}
            }
        }
    }

    if let Err(e) = run_init_setup() {
        tracing::warn!("INIT_ENABLED auto-setup failed (non-fatal): {e}");
    }

    // Scrub the admin bootstrap password from our own environment now that
    // `CONFIG` has captured it and `run_init_setup` has consumed it. Otherwise
    // it lingers in `/proc/self/environ` and is inherited by every subprocess
    // we later spawn (Xray, tor, dnscrypt-proxy, telemt, MasterDnsVPN, and even
    // `awg`/`nft`), each of which would expose the operator's credential via
    // `/proc/<child>/environ`. Done here — before any child is spawned and
    // while the process is still effectively single-threaded for env purposes.
    std::env::remove_var("INIT_PASSWORD");

    if let Err(e) = wg::startup() {
        tracing::warn!("AmneziaWG startup failed (non-fatal): {e}");
        tracing::warn!("Web UI will still be available. Fix AmneziaWG and use Restart from admin panel.");
    } else {
        tracing::info!("AmneziaWG started");
    }

    // iptables-legacy compat: on hosts running the xt_tables backend
    // (typically RHEL/CentOS 7 vintage), our nft `accept` is invisible
    // to the legacy FORWARD chain. Mirror the three "let AWG through"
    // rules into iptables-legacy so the verdicts compose. Idempotent;
    // no-op on every modern (iptables-nft) host.
    if let Ok(iface) = db::get_interface() {
        if let Err(e) = firewall::ensure_legacy_compat(
            &iface.name,
            iface.port,
            !config::CONFIG.disable_ipv6,
        ) {
            tracing::warn!("iptables-legacy compat startup failed (non-fatal): {e}");
        }
    }

    // Bring Browsing-mode Xray online if it's been enabled. Non-fatal:
    // operators who haven't set up Reality keys yet will see Status::Disabled
    // in the admin UI rather than a startup crash.
    #[cfg(xray_bundled)]
    if let Err(e) = awg_easy_rs::xray::supervisor::ensure_running().await {
        tracing::warn!("Xray supervisor startup failed (non-fatal): {e}");
    }

    // Bring the bundled DNS stack online if it's been enabled. Same
    // non-fatal contract as Xray — operators who haven't toggled the
    // master switch see Status::Disabled, not a crash. Tor stays off
    // independently of the master switch (see DnsBundle.tor_enabled).
    #[cfg(dns_bundled)]
    if let Err(e) = awg_easy_rs::dns::supervisor::ensure_running().await {
        tracing::warn!("DNS bundle supervisor startup failed (non-fatal): {e}");
    }

    // Bring telemt (Telegram MTProxy) online if it's been enabled.
    // Disabled by default; the supervisor's ensure_running is a no-op
    // when the inbound row is off. Any spawn failure is non-fatal so a
    // misconfigured tls_domain doesn't block the rest of the server.
    #[cfg(telemt_bundled)]
    if let Err(e) = awg_easy_rs::mtproxy::supervisor::ensure_running().await {
        tracing::warn!("MTProxy supervisor startup failed (non-fatal): {e}");
    }

    // Bring MasterDnsVPN (DNS-tunnel mode) online if it's been enabled.
    // Disabled by default — the supervisor declines to start until the
    // operator generates an encryption key, sets at least one
    // NS-delegated domain, and flips the toggle. Failures are non-fatal
    // (matches the Xray / telemt / DNS-bundle posture).
    #[cfg(mdnsvpn_bundled)]
    if let Err(e) = awg_easy_rs::mdnsvpn::supervisor::ensure_running().await {
        tracing::warn!("MasterDnsVPN supervisor startup failed (non-fatal): {e}");
    }

    // Bring the in-process DPI-imitation proxy online if it's been enabled.
    // AmneziaWG has already been brought up on its effective ListenPort by
    // `wg::startup` (loopback backend port when the proxy is enabled), so
    // here we lock that backend port down to loopback and bind the proxy on
    // the public port. Non-fatal — a bind failure surfaces as Status::Crashed
    // in the admin UI rather than a startup crash.
    if let Ok(iface) = db::get_interface() {
        if let Err(e) = firewall::apply_proxy_lockdown(&iface) {
            tracing::warn!("proxy backend lockdown failed (non-fatal): {e}");
        }
    }
    if let Err(e) = awg_easy_rs::proxy::supervisor::ensure_running().await {
        tracing::warn!("DPI proxy startup failed (non-fatal): {e}");
    }

    let app_state = api::AppState::new();

    // In-memory mode with a configured durable path: snapshot the RAM
    // database to disk on a fixed cadence so a planned restart restores the
    // full roster. Runs on `spawn_blocking` (rusqlite + disk I/O are sync)
    // and swallows every error — a dying NVMe degrades us to "no fresh
    // snapshot", never to a stalled or crashed data plane. Periodic
    // snapshots are skipped when the interval is 0; shutdown still snapshots.
    if config::CONFIG.in_memory {
        if let Some(path) = config::CONFIG.persist_db_path.clone() {
            let interval = config::CONFIG.persist_interval_secs;
            if interval > 0 {
                tokio::spawn(async move {
                    let mut tick =
                        tokio::time::interval(std::time::Duration::from_secs(interval));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    // First tick fires immediately — skip it so we don't
                    // snapshot the just-restored DB redundantly at boot.
                    tick.tick().await;
                    loop {
                        tick.tick().await;
                        let p = path.clone();
                        match tokio::task::spawn_blocking(move || db::snapshot_to(&p)).await {
                            Ok(Ok(())) => tracing::debug!("DB snapshot written to {path}"),
                            Ok(Err(e)) => tracing::warn!("DB snapshot failed (non-fatal): {e:#}"),
                            Err(e) => tracing::warn!("DB snapshot task join error: {e}"),
                        }
                    }
                });
                tracing::info!(
                    "In-memory DB snapshots every {interval}s → {}",
                    config::CONFIG.persist_db_path.as_deref().unwrap_or("")
                );
            }
        }
    }

    // Surface the secret-encryption mode in the journal, and upgrade any
    // TOTP secret still stored as plaintext now that a key is available.
    // Ordering matters: this has to run after the DB is open and before the
    // first login can read a secret.
    awg_easy_rs::crypto::log_status();
    if awg_easy_rs::privhelper::is_enabled() {
        // Verify the socket answers before anything depends on it, so a
        // misconfigured deployment fails at startup with a clear message
        // rather than at the first peer change with a confusing one.
        match awg_easy_rs::privhelper::call(&awg_easy_rs::privhelper::Request::Ping) {
            Ok(_) => tracing::info!(
                "privileged helper: connected — this process needs no CAP_NET_ADMIN"
            ),
            Err(e) => tracing::error!(
                "privileged helper configured but unreachable ({e:#}); \
                 interface and firewall changes will fail"
            ),
        }
    }
    match db::encrypt_plaintext_secrets() {
        Ok(0) => {}
        Ok(n) => tracing::info!("encrypted {n} secret(s) previously stored as plaintext"),
        Err(e) => tracing::error!("secret encryption migration failed (non-fatal): {e:#}"),
    }

    // Start the activity poller: samples `awg show dump` every 30s into the
    // per-client lifetime totals and the daily rollup behind the heatmap.
    // Runs unconditionally — it re-reads `activity_retention_days` on every
    // tick, so an operator toggling the feature off (or back on) in the admin
    // UI takes effect within one interval without a restart.
    match db::get_interface() {
        Ok(iface) => activity::spawn(iface.name),
        Err(e) => tracing::warn!("activity poller not started (interface read failed): {e}"),
    }

    // Start background cron job (every 60 seconds): expire clients/one-time
    // links and sweep expired sessions out of the in-memory store.
    let cron_state = app_state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            if let Err(e) = wg::cron_job() {
                tracing::error!("Cron job failed: {e}");
            }
            match db::get_general() {
                Ok(g) => api::prune_expired_sessions(&cron_state, g.session_timeout),
                Err(e) => tracing::error!("session prune skipped (general read failed): {e}"),
            }
        }
    });

    // Static asset routes
    let static_routes = Router::new()
        .route("/app.js", get(|h: HeaderMap| async move { js_response(h, APP_JS) }))
        .route("/favicon.png", get(|h: HeaderMap| async move { png_response(h, FAVICON_PNG, asset_etag("favicon.png", FAVICON_PNG)) }))
        .route("/favicon-amnezia.ico", get(|h: HeaderMap| async move { ico_response(h, FAVICON_AWG_ICO, asset_etag("favicon-amnezia.ico", FAVICON_AWG_ICO)) }))
        .route("/favicon.ico", get(|h: HeaderMap| async move { ico_response(h, FAVICON_AWG_ICO, asset_etag("favicon-amnezia.ico", FAVICON_AWG_ICO)) }))
        .route("/logo.png", get(|h: HeaderMap| async move { png_response(h, LOGO_PNG, asset_etag("logo.png", LOGO_PNG)) }))
        .route("/logo-amnezia.svg", get(|h: HeaderMap| async move { svg_response(h, LOGO_AWG_SVG, asset_etag("logo-amnezia.svg", LOGO_AWG_SVG)) }))
        .route("/apple-touch-icon.png", get(|h: HeaderMap| async move { png_response(h, APPLE_ICON, asset_etag("apple-touch-icon.png", APPLE_ICON)) }))
        .route("/apple-touch-icon-amnezia.png", get(|h: HeaderMap| async move { png_response(h, APPLE_ICON_AWG, asset_etag("apple-touch-icon-amnezia.png", APPLE_ICON_AWG)) }))
        .route("/manifest.json", get(|h: HeaderMap| async move { json_response(h, MANIFEST_JSON, asset_etag("manifest.json", MANIFEST_JSON)) }));

    let app = api::build_router(app_state)
        .merge(static_routes)
        .fallback(|h: HeaderMap| async move {
            html_response(h, INDEX_HTML)
        });

    let addr = SocketAddr::from(([0, 0, 0, 0], config::CONFIG.port));
    tracing::info!("awg-easy-rs starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Graceful shutdown future: SIGTERM (docker compose down, systemd stop)
    // or SIGINT (Ctrl-C in foreground) flips the future. axum stops
    // accepting new connections and drains in-flight ones.
    let shutdown = async {
        let mut sigterm = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
                unreachable!();
            }
        };
        let mut sigint = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::interrupt(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "failed to install SIGINT handler");
                std::future::pending::<()>().await;
                unreachable!();
            }
        };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM received; shutting down"),
            _ = sigint.recv()  => tracing::info!("SIGINT received; shutting down"),
        }
    };
    // Serve with connect-info so handlers can read the real peer socket
    // address (used by the login rate limiter when TRUST_PROXY is off).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;

    // Post-serve cleanup. Order matters: stop Xray + DNS + MTProxy
    // supervisor children first so they're reaped before we tear down
    // firewall state, then peel back any iptables-legacy compat rules
    // we inserted at startup.
    #[cfg(xray_bundled)]
    awg_easy_rs::xray::supervisor::shutdown_for_exit().await;
    #[cfg(dns_bundled)]
    awg_easy_rs::dns::supervisor::shutdown_for_exit().await;
    #[cfg(telemt_bundled)]
    awg_easy_rs::mtproxy::supervisor::shutdown_for_exit().await;
    #[cfg(mdnsvpn_bundled)]
    awg_easy_rs::mdnsvpn::supervisor::shutdown_for_exit().await;
    awg_easy_rs::proxy::supervisor::shutdown_for_exit().await;

    if let Ok(iface) = db::get_interface() {
        firewall::remove_legacy_compat(
            &iface.name,
            iface.port,
            !config::CONFIG.disable_ipv6,
        );
    }

    // Final durable snapshot on graceful shutdown so a clean stop never
    // loses the work done since the last periodic snapshot. Best-effort —
    // a failure here must not turn a clean shutdown into a non-zero exit.
    if config::CONFIG.in_memory {
        if let Some(path) = config::CONFIG.persist_db_path.as_deref() {
            match db::snapshot_to(path) {
                Ok(()) => tracing::info!("Final DB snapshot written to {path}"),
                Err(e) => tracing::warn!("Final DB snapshot failed (non-fatal): {e:#}"),
            }
        }
    }

    tracing::info!("awg-easy-rs exited cleanly");
    Ok(())
}

// ---------------------------------------------------------------------------
// ETag-backed cache validation. Each asset gets a content-derived ETag
// computed once at startup; browsers cache aggressively but always revalidate
// (Cache-Control: no-cache). When the binary is rebuilt the ETag changes, so
// stale clients automatically pick up the new asset on next page load.
// ---------------------------------------------------------------------------

fn etag_for_bytes(content: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    content.hash(&mut h);
    format!("\"{:016x}\"", h.finish())
}

/// Per-asset ETag cache. Keyed by asset name so each route owns its slot.
fn asset_etag(name: &'static str, content: &'static [u8]) -> &'static str {
    static CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<&'static str, &'static str>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut g = cache.lock().expect("etag cache lock");
    if let Some(v) = g.get(name) {
        return v;
    }
    let leaked: &'static str = Box::leak(etag_for_bytes(content).into_boxed_str());
    g.insert(name, leaked);
    leaked
}

fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok())
        .map(|v| v.split(',').map(str::trim).any(|t| t == etag || t == "*"))
        .unwrap_or(false)
}

fn not_modified(etag: &str) -> Response {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(header::ETAG, etag)
        .header(header::CACHE_CONTROL, "no-cache")
        .body(axum::body::Body::empty())
        .unwrap()
}

fn binary_response(headers: HeaderMap, content_type: &'static str, data: &'static [u8], etag: &'static str) -> Response {
    if matches_etag(&headers, etag) {
        return not_modified(etag);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::ETAG, etag)
        .body(axum::body::Body::from(data))
        .unwrap()
}

fn png_response(headers: HeaderMap, data: &'static [u8], etag: &'static str) -> Response {
    binary_response(headers, "image/png", data, etag)
}

fn ico_response(headers: HeaderMap, data: &'static [u8], etag: &'static str) -> Response {
    binary_response(headers, "image/x-icon", data, etag)
}

fn svg_response(headers: HeaderMap, data: &'static [u8], etag: &'static str) -> Response {
    binary_response(headers, "image/svg+xml", data, etag)
}

fn json_response(headers: HeaderMap, data: &'static [u8], etag: &'static str) -> Response {
    binary_response(headers, "application/json", data, etag)
}

fn js_response(headers: HeaderMap, data: &'static str) -> Response {
    let etag = asset_etag("app.js", data.as_bytes());
    if matches_etag(&headers, etag) {
        return not_modified(etag);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/javascript; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::ETAG, etag)
        .header("X-Content-Type-Options", "nosniff")
        .body(axum::body::Body::from(data))
        .unwrap()
}

fn html_response(headers: HeaderMap, data: &'static str) -> Response {
    let etag = asset_etag("index.html", data.as_bytes());
    if matches_etag(&headers, etag) {
        return not_modified(etag);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::ETAG, etag)
        .body(axum::body::Body::from(data))
        .unwrap()
}

/// Honour the INIT_* environment variables when set: auto-create the admin
/// user, set the host/port, and complete the setup wizard. Idempotent — does
/// nothing once a user already exists or `init_enabled` is false.
fn run_init_setup() -> anyhow::Result<()> {
    let cfg = &*config::CONFIG;
    if !cfg.init_enabled {
        return Ok(());
    }
    let user_count = db::get_user_count().unwrap_or(0);
    if user_count > 0 {
        tracing::debug!("INIT_ENABLED set but admin user already exists — skipping");
        return Ok(());
    }
    let username = cfg
        .init_username
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("INIT_USERNAME is required when INIT_ENABLED=true"))?;
    let password = cfg
        .init_password
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("INIT_PASSWORD is required when INIT_ENABLED=true"))?;

    let params = init_setup::InitSetupParams {
        username,
        password,
        host: cfg.init_host.as_deref(),
        port: cfg.init_port,
        ipv4_cidr: cfg.init_ipv4_cidr.as_deref(),
        ipv6_cidr: cfg.init_ipv6_cidr.as_deref(),
        dns: cfg.init_dns.as_deref(),
        allowed_ips: cfg.init_allowed_ips.as_deref(),
    };

    if init_setup::provision_initial_setup(&params)? {
        tracing::info!("INIT_ENABLED: created admin user '{username}' and completed setup");
    }
    Ok(())
}
