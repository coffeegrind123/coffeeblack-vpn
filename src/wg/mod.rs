//! AmneziaWG/AmneziaWG orchestration module.
//!
//! Pure AmneziaWG — binary is always `awg`/`awg-quick`.

pub mod cb3;
pub mod cli;
pub mod config_gen;
pub mod kernel;
pub mod params;

use anyhow::Result;

/// Generate a new AmneziaWG keypair via `awg genkey` / `awg pubkey`.
///
/// Avoids shelling out via `bash -c` — uses Command stdin instead so the
/// (already-validated) base64 private key never touches a shell parser.
pub fn generate_keypair() -> Result<(String, String)> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if !cfg!(target_os = "linux") {
        return Ok((String::new(), String::new()));
    }
    let private = cli::run("awg", &["genkey"])?;
    if private.is_empty() {
        return Ok((private, String::new()));
    }
    let mut child = Command::new("awg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut sin) = child.stdin.take() {
        sin.write_all(private.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "awg pubkey failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let public = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((private, public))
}

/// Generate a new pre-shared key.
pub fn generate_psk() -> Result<String> {
    cli::run("awg", &["genpsk"])
}

/// Full AmneziaWG startup sequence.
pub fn startup() -> Result<()> {
    let mut iface = crate::db::get_interface()?;
    crate::info!("Starting AmneziaWG interface {}", iface.name);

    // Generate keys if default placeholder
    if iface.private_key == "---default---" {
        crate::info!("Generating new AmneziaWG keypair...");
        let (priv_key, pub_key) = generate_keypair()?;
        crate::db::update_key_pair(&pub_key, &priv_key)?;
        iface = crate::db::get_interface()?;
    }

    // Generate random AWG obfuscation params on first run
    if iface.h1.is_empty() || iface.h1 == "0" {
        crate::info!("Generating random AmneziaWG obfuscation parameters...");
        let cb_params = params::generate_cb_params();
        crate::db::update_interface_cb_params(&cb_params)?;
        iface = crate::db::get_interface()?;
    }

    // Write config and bring up interface
    save_config().ok();
    // If the DPI proxy is active, install the backend-port firewall
    // lockdown BEFORE AmneziaWG binds that port, so the raw listener is
    // never briefly WAN-reachable during bring-up. No-op when inactive.
    if let Err(e) = crate::firewall::apply_proxy_lockdown(&iface) {
        crate::warn!("proxy backend lockdown at startup failed (non-fatal): {e}");
    }
    cli::cb_down(&iface.name).ok(); // ignore if not yet up
    cli::cb_up(&iface.name)?;
    cli::cb_sync(&iface.name)?;

    // Apply firewall rules
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules().ok();
    }

    crate::info!("AmneziaWG interface {} started successfully", iface.name);
    Ok(())
}

/// Save AmneziaWG config to disk and sync to running interface.
///
/// With the privileged helper enabled the rendered text is handed to the
/// helper instead, which owns both the write and the sync. That keeps the web
/// process without write access to `/etc/coffeeblack/conf` — where the server private
/// key lives — as well as without `CAP_NET_ADMIN`.
pub fn save_config() -> Result<()> {
    let iface = crate::db::get_interface()?;
    let config = render_server_config()?;

    if crate::privhelper::is_enabled() {
        // The helper renders the firewall hooks itself; we only supply the
        // addresses, which it re-validates as CIDRs before substituting them
        // into its own constant templates.
        crate::privhelper::call(&crate::privhelper::Request::WgSync {
            config,
            firewall: Some(crate::privhelper::FirewallParams {
                ipv4_cidr: iface.ipv4_cidr.clone(),
                ipv6_cidr: iface.ipv6_cidr.clone(),
                port: iface.port as u16,
            }),
        })?;
        return Ok(());
    }

    let path = format!("{}/{}.conf", crate::config::CONFIG.wg_conf_dir, iface.name);
    // Create with 0600 rather than writing and chmod'ing afterwards: this file
    // carries the server private key and every peer's preshared key, and
    // `fs::write` creates with the process umask, leaving it world-readable
    // for the duration of the write. `.mode()` is applied by open(2) itself,
    // so there is no window. Mirrors `privhelper::wg_sync`.
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(crate::secretfile::SECRET_FILE_MODE)
            .open(&path)?;
        f.write_all(config.as_bytes())?;
        // An existing file keeps its old mode through O_CREAT, so still
        // enforce it for a config written by an older version.
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(crate::secretfile::SECRET_FILE_MODE),
        )?;
    }
    #[cfg(not(unix))]
    std::fs::write(&path, &config)?;

    cli::cb_sync(&iface.name)?;
    Ok(())
}

/// Drop the two AmneziaWG 3 knobs that the DPI-imitation proxy cannot carry.
///
/// The admin API refuses to enable either one while the proxy is on (and
/// vice versa), so reaching this with a conflict set means the DB was
/// changed some other way — a hand-edited row, a restored snapshot from a
/// proxy-less deployment. Rendering it anyway would produce a tunnel that
/// looks configured and passes no traffic, so drop them here as well and
/// say so loudly. Like the `Jc`/`I1–I5` suppression above this only
/// touches the rendered copy; the stored row is untouched and comes back
/// the moment the proxy is turned off.
///
/// See `wg::cb3::proxy_conflict` for why each is incompatible.
fn suppress_cb3_conflicts(gen_iface: &mut crate::db::Interface) {
    if let Some(reason) = crate::wg::cb3::proxy_conflict(
        &gen_iface.header_protection_key,
        gen_iface.random_trailers,
    ) {
        crate::warn!(
            "dropping an AmneziaWG 3 setting from the rendered config while the \
             DPI-imitation proxy is active: {reason}"
        );
        gen_iface.header_protection_key.clear();
        gen_iface.random_trailers = false;
    }
}

/// Render the full server `.conf` (interface block plus every enabled peer).
///
/// Split out of [`save_config`] so the same text can either be written here or
/// handed to the privileged helper, with exactly one implementation of what
/// the config should contain.
pub fn render_server_config() -> Result<String> {
    let iface = crate::db::get_interface()?;
    let clients = crate::db::get_all_clients()?;
    let hooks = crate::db::get_hooks()?;

    // When the DPI-imitation proxy is fronting the port, drop AmneziaWG's
    // own pre-handshake junk from the *effective* config: the `Jc` dummy
    // datagrams and `I1–I5` templated packets are separate datagrams the
    // proxy doesn't imitate, so they'd cross the wire as un-imitated
    // random/templated UDP and re-expose the fingerprint the proxy erases
    // (audit finding F1). S1–S4 padding and H1–H4 headers are kept — the
    // proxy consumes them. The stored DB row is untouched, so disabling the
    // proxy restores native junk on the next render.
    let mut gen_iface = iface.clone();
    if crate::proxy::supervisor::suppress_native_junk() {
        gen_iface.j_c = 0;
        gen_iface.i1.clear();
        gen_iface.i2.clear();
        gen_iface.i3.clear();
        gen_iface.i4.clear();
        gen_iface.i5.clear();
        suppress_cb3_conflicts(&mut gen_iface);
    }

    // In privileged-helper mode the hooks are rendered by the helper, from its
    // own compiled-in templates and validated network parameters — see
    // `privhelper::FirewallParams`. Emitting them here too would just be
    // rejected: `awg-quick` runs hook text as root, so the helper refuses to
    // accept any that crossed the socket.
    let hooks = if crate::privhelper::is_enabled() {
        crate::db::Hooks {
            pre_up: String::new(),
            post_up: String::new(),
            pre_down: String::new(),
            post_down: String::new(),
            ..hooks
        }
    } else {
        hooks
    };

    let mut config = config_gen::generate_server_interface(&gen_iface, &hooks)?;

    // When the DPI-imitation proxy is fronting the public port, AmneziaWG
    // must move to the loopback backend port so the proxy can bind the
    // public port. The hook-opened `{{port}}` (== iface.port) stays as-is
    // because that's the port the proxy now listens on. Only the interface
    // ListenPort line moves.
    let effective_port = crate::proxy::supervisor::effective_listen_port(&iface);
    if effective_port != iface.port {
        config = config.replace(
            &format!("ListenPort = {}", iface.port),
            &format!("ListenPort = {}", effective_port),
        );
    }

    for client in &clients {
        if client.enabled {
            config.push_str("\n\n");
            config.push_str(&config_gen::generate_server_peer(client)?);
        }
    }
    config.push('\n');

    Ok(config)
}

/// Generate a client's `.conf` file contents.
pub fn get_client_config(client_id: i64) -> Result<String> {
    let client = crate::db::get_client(client_id)?;
    if !client.has_private_key() {
        // Under `never` retention the key was handed over once at creation
        // and not kept, so there is nothing to re-render. Fail loudly rather
        // than emitting a config with an empty `PrivateKey =` line, which
        // would look valid, import cleanly, and then silently never connect.
        return Err(anyhow::anyhow!(
            "private key for client {client_id} is not retained on this server; \
             rotate the peer to issue a new configuration"
        ));
    }
    build_client_config(client_id, None)
}

/// Render a client config, optionally supplying the private key rather than
/// reading it from the database.
///
/// The override is what makes one-time issuance possible: the create and
/// rotate flows hold a freshly generated key in memory just long enough to
/// render the config the operator walks away with, and never persist it.
pub fn build_client_config(client_id: i64, private_key_override: Option<&str>) -> Result<String> {
    let iface = crate::db::get_interface()?;
    let user_config = crate::db::get_user_config()?;
    let mut client = crate::db::get_client(client_id)?;
    if let Some(pk) = private_key_override {
        client.private_key = pk.to_string();
    }

    // Mirror the server-side F1 suppression on the client config: with the
    // proxy active, a client that emits native `Jc`/`I1–I5` junk toward the
    // server sends un-imitated datagrams on the client→server path too.
    // Zero them so the client's wire image is the clean S-padded stream the
    // proxy (and a WireSock 3.5+ client) imitates. Reversible — the DB is
    // untouched; regenerating with the proxy off restores the junk.
    let mut gen_iface = iface.clone();
    let mut gen_client = client.clone();
    if crate::proxy::supervisor::suppress_native_junk() {
        gen_iface.j_c = 0;
        gen_client.j_c = Some(0);
        gen_client.i1 = None;
        gen_client.i2 = None;
        gen_client.i3 = None;
        gen_client.i4 = None;
        gen_client.i5 = None;
        suppress_cb3_conflicts(&mut gen_iface);
    }
    config_gen::generate_client_config(&gen_iface, &user_config, &gen_client)
}

/// Dump running AmneziaWG status for all peers.
pub fn dump_peers(iface_name: &str) -> Result<Vec<cli::PeerDump>> {
    cli::cb_dump(iface_name)
}

// ---------------------------------------------------------------------------
// Async offload wrappers
// ---------------------------------------------------------------------------
//
// `save_config`, `dump_peers`, and `restart` shell out to `awg`/`awg-quick`
// (and write the config file), which can take hundreds of milliseconds. These
// wrappers run that work on `spawn_blocking` so an async request handler never
// parks a tokio worker thread on a subprocess. The in-process SQLite layer is
// deliberately left synchronous: it's a single global connection behind a
// `Mutex`, so offloading individual queries would add lock churn without any
// parallelism gain.

fn join_err<T>(r: std::result::Result<Result<T>, tokio::task::JoinError>) -> Result<T> {
    r.map_err(|e| anyhow::anyhow!("blocking task failed: {e}"))?
}

/// `spawn_blocking` wrapper around [`save_config`].
pub async fn save_config_async() -> Result<()> {
    join_err(tokio::task::spawn_blocking(save_config).await)
}

/// `spawn_blocking` wrapper around [`dump_peers`].
pub async fn dump_peers_async(iface_name: String) -> Result<Vec<cli::PeerDump>> {
    join_err(tokio::task::spawn_blocking(move || dump_peers(&iface_name)).await)
}

/// `spawn_blocking` wrapper around [`restart`].
pub async fn restart_async() -> Result<()> {
    join_err(tokio::task::spawn_blocking(restart).await)
}

/// Background cron job — expire clients.
pub fn cron_job() -> Result<()> {
    let clients = crate::db::get_all_clients()?;
    let mut needs_save = false;
    let now = crate::datetime::now_utc();

    for client in &clients {
        if !client.enabled {
            continue;
        }
        if let Some(ref expires) = client.expires_at {
            if let Some(exp) = crate::datetime::parse_expiry(expires) {
                if now > exp {
                    crate::info!("Client {} ({}) expired, disabling", client.id, client.name);
                    crate::db::toggle_client(client.id, false)?;
                    needs_save = true;
                }
            }
        }
    }

    if needs_save {
        save_config()?;
    }
    Ok(())
}

/// Graceful shutdown — take down the AmneziaWG interface.
pub fn shutdown() -> Result<()> {
    let iface = crate::db::get_interface()?;
    cli::cb_down(&iface.name).ok();
    Ok(())
}

/// Restart the AmneziaWG interface.
pub fn restart() -> Result<()> {
    let iface = crate::db::get_interface()?;
    cli::cb_down(&iface.name).ok();
    cli::cb_up(&iface.name)?;
    Ok(())
}
