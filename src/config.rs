use std::env;
use std::sync::LazyLock;

pub static CONFIG: LazyLock<Config> = LazyLock::new(Config::load);

pub struct Config {
    pub port: u16,
    pub host: String,
    pub insecure: bool,
    /// When true, honour `X-Forwarded-For` / `X-Real-IP` for the per-source-IP
    /// login rate limiter. Only safe behind a trusted reverse proxy that
    /// overwrites these headers — otherwise any client can forge them to evade
    /// the per-IP bucket. Default false: the rate limiter uses the real peer
    /// socket address instead.
    pub trust_proxy: bool,
    pub disable_ipv6: bool,
    pub init_enabled: bool,
    pub init_username: Option<String>,
    pub init_password: Option<String>,
    pub init_host: Option<String>,
    pub init_port: Option<u16>,
    pub init_dns: Option<Vec<String>>,
    pub init_ipv4_cidr: Option<String>,
    pub init_ipv6_cidr: Option<String>,
    pub init_allowed_ips: Option<Vec<String>>,
    pub db_path: String,
    pub wg_conf_dir: String,
    pub wg_binary: String,
    /// Directory where the bundled Xray ELF, generated `server.json`, and
    /// other Xray runtime files live. Defaults to `<wg_conf_dir>/xray`.
    pub xray_dir: String,
    /// Operator escape hatch: when set, the Xray supervisor uses this path
    /// instead of extracting the bundled binary. Lets advanced operators
    /// track upstream Xray independently of coffeeblack-vpn releases.
    pub xray_binary_override: Option<String>,
    /// Directory where the bundled DNS-stack ELFs (dnscrypt-proxy, tor,
    /// lyrebird, snowflake, webtunnel) are extracted, plus generated
    /// configs (`dnscrypt-proxy.toml`, `torrc`, etc.) and tor's data
    /// directory. Defaults to `<wg_conf_dir>/dns`. Persist this on a
    /// docker volume so binaries don't re-extract on every restart.
    pub dns_dir: String,
    /// Directory where the bundled telemt ELF is extracted, plus the
    /// generated `config.toml`, telemt's PID file, and the `tlsfront`
    /// cache it builds at first start (real TLS records fetched from the
    /// masking domain). Defaults to `<wg_conf_dir>/mtproxy`. Same
    /// persistence story as `dns_dir` — dropping it on every restart
    /// works but means the tlsfront cache rebuilds and the binary
    /// re-extracts.
    pub mtproxy_dir: String,
    /// Directory where the bundled MasterDnsVPN ELF is extracted, plus
    /// the generated `server_config.toml` and the `encrypt_key.txt`
    /// keyfile the server reads at startup. Defaults to
    /// `<wg_conf_dir>/mdnsvpn`. Persisting this on a docker volume
    /// avoids re-extracting the binary on every restart.
    pub mdnsvpn_dir: String,
    /// Run entirely in RAM. When `true`:
    ///
    /// - the SQLite database is opened with `:memory:` (no DB file is
    ///   touched on the request path), optionally seeded from and
    ///   snapshotted to `persist_db_path`;
    /// - every bundled subprocess ELF (Xray, telemt, MasterDnsVPN,
    ///   dnscrypt-proxy, tor) is decompressed into an anonymous
    ///   `memfd_create(2)` object and exec'd via `/proc/self/fd/N`, so
    ///   the binary never lands on any filesystem.
    ///
    /// The generated config files, the AmneziaWG `.conf`, tor's data
    /// directory, and tor's pluggable-transport plugins still need real
    /// paths (tor `exec`s its PT plugins by path), so point `wg_conf_dir`
    /// and friends at a `tmpfs` mount to keep those in RAM too. The
    /// container image does exactly that (see `docker-compose.yml`).
    ///
    /// Defaults to `true` (any value other than `IN_MEMORY=false` enables
    /// it): RAM-resident operation is the project's intended mode. An
    /// operator who wants a durable on-disk database opts out explicitly
    /// with `IN_MEMORY=false`.
    pub in_memory: bool,
    /// Durable file the in-memory database is snapshotted to (and
    /// restored from on boot). `None` disables persistence entirely —
    /// pure RAM, state lost on restart. When set, a background task
    /// copies the live RAM database here every `persist_interval_secs`
    /// and once more on graceful shutdown, using SQLite's online-backup
    /// API. All snapshot I/O is best-effort and off the request path: a
    /// failing or read-only disk degrades to "no snapshot", never to a
    /// stalled or crashed data plane. Only consulted when `in_memory`.
    pub persist_db_path: Option<String>,
    /// How often (seconds) the background task snapshots the RAM database
    /// to `persist_db_path`. Ignored when persistence is off. `0`
    /// disables periodic snapshots while still snapshotting on shutdown.
    pub persist_interval_secs: u64,
}

pub fn get_env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Config {
    pub fn load() -> Self {
        let port: u16 = env::var("PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(51821);
        let host = get_env("HOST", "0.0.0.0");
        let insecure = get_env("INSECURE", "false").to_lowercase() == "true";
        let trust_proxy = get_env("TRUST_PROXY", "false").to_lowercase() == "true";
        let disable_ipv6 = get_env("DISABLE_IPV6", "false").to_lowercase() == "true";
        let init_enabled = get_env("INIT_ENABLED", "false").to_lowercase() == "true";

        let init_username = env::var("INIT_USERNAME").ok().filter(|s| !s.is_empty());
        let init_password = env::var("INIT_PASSWORD").ok().filter(|s| !s.is_empty());
        let init_host = env::var("INIT_HOST").ok().filter(|s| !s.is_empty());
        let init_port = env::var("INIT_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok());

        let init_dns = env::var("INIT_DNS").ok().filter(|s| !s.is_empty()).map(|s| {
            s.split(',')
                .map(|part| part.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        });

        let init_ipv4_cidr = env::var("INIT_IPV4_CIDR")
            .ok()
            .filter(|s| !s.is_empty());
        let init_ipv6_cidr = env::var("INIT_IPV6_CIDR")
            .ok()
            .filter(|s| !s.is_empty());

        let init_allowed_ips = env::var("INIT_ALLOWED_IPS")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.split(',')
                    .map(|part| part.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            });

        let db_path = get_env("COFFEEBLACK_DB_PATH", "/etc/coffeeblack/conf/coffeeblack.db");
        let wg_conf_dir = get_env("COFFEEBLACK_CONF_DIR", "/etc/coffeeblack/conf");
        let xray_dir =
            env::var("COFFEEBLACK_XRAY_DIR").unwrap_or_else(|_| format!("{}/xray", wg_conf_dir));
        let xray_binary_override = env::var("XRAY_BIN_PATH").ok().filter(|s| !s.is_empty());
        let dns_dir =
            env::var("COFFEEBLACK_DNS_DIR").unwrap_or_else(|_| format!("{}/dns", wg_conf_dir));
        let mtproxy_dir = env::var("COFFEEBLACK_MTPROXY_DIR")
            .unwrap_or_else(|_| format!("{}/mtproxy", wg_conf_dir));
        let mdnsvpn_dir = env::var("COFFEEBLACK_MDNSVPN_DIR")
            .unwrap_or_else(|_| format!("{}/mdnsvpn", wg_conf_dir));

        // Default ON: the data plane is RAM-resident unless the operator
        // explicitly opts back into a durable on-disk database with
        // IN_MEMORY=false.
        let in_memory = get_env("IN_MEMORY", "true").to_lowercase() != "false";
        let persist_db_path = env::var("COFFEEBLACK_PERSIST_DB").ok().filter(|s| !s.is_empty());
        let persist_interval_secs = env::var("COFFEEBLACK_PERSIST_INTERVAL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30);

        Config {
            port,
            host,
            insecure,
            trust_proxy,
            disable_ipv6,
            init_enabled,
            init_username,
            init_password,
            init_host,
            init_port,
            init_dns,
            init_ipv4_cidr,
            init_ipv6_cidr,
            init_allowed_ips,
            db_path,
            wg_conf_dir,
            wg_binary: "awg".to_string(),
            xray_dir,
            xray_binary_override,
            dns_dir,
            mtproxy_dir,
            mdnsvpn_dir,
            in_memory,
            persist_db_path,
            persist_interval_secs,
        }
    }
}
