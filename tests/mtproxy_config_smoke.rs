//! Smoke test that verifies our generated `config.toml` parses and
//! launches under the real bundled telemt binary.
//!
//! Marked `#[ignore]` because it spawns a child process and binds a
//! high port — run with:
//!
//!   cargo test --test mtproxy_config_smoke -- --ignored
//!
//! Two ways the test locates the telemt binary, in order:
//!
//!   1. `vendor/telemt-linux-amd64.gz` — the canonical artifact
//!      `scripts/build.sh` produces. We decompress to a temp file
//!      and chmod +x. This is what runs in the local-build flow.
//!   2. `/tmp/telemt-vendor/telemt` — legacy path the manual smoke
//!      script in this repo's history left behind. Kept as a
//!      fallback so existing developer environments still work.
//!
//! If neither exists, the test skips with a clear message rather
//! than failing — running it requires `scripts/build.sh
//! --vendor-only` first.

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use coffeeblack_vpn::db::MtproxyInbound;
use coffeeblack_vpn::mtproxy::config;

#[test]
#[ignore = "spawns real telemt subprocess; needs vendor/telemt-linux-amd64.gz on disk"]
fn generated_config_parses_and_telemt_starts() {
    let dir = format!(
        "/tmp/coffeeblack-vpn-mtproxy-cfg-smoke-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0),
    );
    std::fs::create_dir_all(&dir).expect("mkdir");

    let bin = match resolve_telemt_binary(&dir) {
        Some(p) => p,
        None => {
            eprintln!(
                "skipping: vendor/telemt-linux-amd64.gz not present and \
                 /tmp/telemt-vendor/telemt missing — run \
                 `scripts/build.sh --vendor-only --skip xray --skip dnscrypt-proxy \
                 --skip tor --skip lyrebird --skip snowflake --skip webtunnel` \
                 to materialise just the telemt blob"
            );
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
    };

    let inbound = MtproxyInbound {
        id: "mtproxy0".into(),
        // High random port so the test doesn't fight other listeners.
        port: 18000 + (std::process::id() % 1000) as i64,
        public_host: String::new(),
        public_port: 0,
        tls_domain: "www.cloudflare.com".into(),
        mask_enabled: true,
        modes_classic: false,
        modes_secure: false,
        modes_tls: true,
        use_middle_proxy: true,
        ad_tag: String::new(),
        additional_config: String::new(),
        enabled: true,
        created_at: "n".into(),
        updated_at: "n".into(),
    };

    let toml = config::generate(&inbound, std::path::Path::new(&dir))
        .expect("config::generate");
    let cfg_path = format!("{dir}/config.toml");
    std::fs::write(&cfg_path, &toml).expect("write config.toml");

    // Spawn telemt in foreground; if our generated config.toml has a
    // parse error, telemt exits within a few hundred ms and we
    // panic with the captured stderr so the failure is actionable.
    let mut child = Command::new(&bin)
        .arg("run")
        .arg("--pid-file")
        .arg(format!("{dir}/telemt.pid"))
        .arg(&cfg_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn telemt");

    let pid = child.id();
    eprintln!("spawned telemt pid {pid}");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stderr = child
                    .stderr
                    .take()
                    .map(|s| {
                        let mut buf = String::new();
                        let _ = io::BufReader::new(s).read_to_string(&mut buf);
                        buf
                    })
                    .unwrap_or_default();
                let _ = std::fs::remove_dir_all(&dir);
                panic!(
                    "telemt exited with {status} during the 10s smoke window — \
                     our generated config.toml didn't parse. stderr:\n{stderr}"
                );
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => panic!("waitpid: {e}"),
        }
    }

    // Clean up.
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Find the telemt binary or extract one from `vendor/telemt-linux-amd64.gz`
/// into a fresh path under `dir`. Returns `None` if no source is
/// available — the test then skips gracefully.
fn resolve_telemt_binary(dir: &str) -> Option<PathBuf> {
    // Path 1: a pre-built copy at the legacy /tmp location, kept by
    // historical smoke scripts. If it's there and executable, use it
    // directly without copying.
    let legacy = PathBuf::from("/tmp/telemt-vendor/telemt");
    if legacy.is_file() && is_executable(&legacy) {
        return Some(legacy);
    }

    // Path 2: vendor/telemt-linux-amd64.gz. Tests run from the crate
    // root, so the relative path is well-defined.
    let blob = PathBuf::from("vendor/telemt-linux-amd64.gz");
    if !blob.is_file() {
        return None;
    }
    let extracted = PathBuf::from(format!("{dir}/telemt"));
    let raw = std::fs::File::open(&blob).ok()?;
    let mut decoder = flate2::read::GzDecoder::new(raw);
    let mut out = std::fs::File::create(&extracted).ok()?;
    std::io::copy(&mut decoder, &mut out).ok()?;
    drop(out);
    chmod_executable(&extracted).ok()?;
    Some(extracted)
}

fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn chmod_executable(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}
