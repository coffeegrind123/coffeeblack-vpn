//! Smoke test that verifies our generated `server_config.toml` parses
//! and launches under the real bundled MasterDnsVPN binary.
//!
//! Marked `#[ignore]` because it spawns a child process and binds a
//! high UDP port — run with:
//!
//!   cargo test --test mdnsvpn_config_smoke -- --ignored
//!
//! Two ways the test locates the mdnsvpn binary, in order:
//!
//!   1. `vendor/mdnsvpn-linux-amd64.gz` — the canonical artifact
//!      `scripts/build.sh` produces. We decompress to a temp file
//!      and chmod +x.
//!   2. `MDNSVPN_BIN_PATH` env var pointing at an existing binary
//!      (useful for developer environments without the vendor blob).
//!
//! If neither exists, the test skips with a clear message rather
//! than failing.

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use coffeeblack_vpn::db::MdnsvpnInbound;
use coffeeblack_vpn::mdnsvpn::{config, keys};

#[test]
#[ignore = "spawns real mdnsvpn subprocess; needs vendor/mdnsvpn-linux-amd64.gz on disk"]
fn generated_config_parses_and_mdnsvpn_starts() {
    let dir = format!(
        "/tmp/coffeeblack-vpn-mdnsvpn-cfg-smoke-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0),
    );
    std::fs::create_dir_all(&dir).expect("mkdir");

    let bin = match resolve_mdnsvpn_binary(&dir) {
        Some(p) => p,
        None => {
            eprintln!(
                "skipping: vendor/mdnsvpn-linux-amd64.gz not present and \
                 MDNSVPN_BIN_PATH unset — run `scripts/build.sh \
                 --vendor-only --skip xray --skip dnscrypt-proxy --skip tor \
                 --skip lyrebird --skip snowflake --skip webtunnel --skip telemt` \
                 to materialise just the mdnsvpn blob"
            );
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
    };

    // Write the key file separately — mdnsvpn reads
    // `ENCRYPTION_KEY_FILE` at startup.
    let key = keys::generate_key();
    let key_path = format!("{dir}/encrypt_key.txt");
    std::fs::write(&key_path, &key).expect("write encrypt_key.txt");

    let inbound = MdnsvpnInbound {
        id: "mdnsvpn0".into(),
        domains: r#"["smoke.test.local"]"#.into(),
        // High port so we don't fight :53 on the host (which usually
        // needs cap_net_bind_service / root).
        port: 21000 + (std::process::id() % 1000) as i64,
        bind: "127.0.0.1".into(),
        encryption_method: 1,
        encryption_key: key.clone(),
        protocol_type: "SOCKS5".into(),
        dns_upstream_servers: r#"["1.1.1.1:53","1.0.0.1:53"]"#.into(),
        forward_ip: String::new(),
        forward_port: 0,
        use_external_socks5: false,
        socks5_auth: false,
        socks5_user: String::new(),
        socks5_pass: String::new(),
        additional_config: String::new(),
        enabled: true,
        created_at: "n".into(),
        updated_at: "n".into(),
    };

    let toml = config::generate(&inbound, std::path::Path::new(&dir))
        .expect("config::generate");
    let cfg_path = format!("{dir}/server_config.toml");
    std::fs::write(&cfg_path, &toml).expect("write server_config.toml");

    // Spawn mdnsvpn; if our generated config.toml has a parse error,
    // mdnsvpn exits within a few hundred ms and we panic with the
    // captured stderr so the failure is actionable.
    //
    // -nowait stops the binary from prompting for input on stdin during
    // fatal errors (which would dead-lock the test).
    let mut child = Command::new(&bin)
        .arg("-config")
        .arg(&cfg_path)
        .arg("-nowait")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mdnsvpn");

    let pid = child.id();
    eprintln!("spawned mdnsvpn pid {pid}");

    // 4s smoke window — long enough to see a parse-time fatal exit
    // (which happens within ~200 ms upstream), short enough that the
    // test stays snappy.
    let deadline = Instant::now() + Duration::from_secs(4);
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
                let stdout = child
                    .stdout
                    .take()
                    .map(|s| {
                        let mut buf = String::new();
                        let _ = io::BufReader::new(s).read_to_string(&mut buf);
                        buf
                    })
                    .unwrap_or_default();
                let _ = std::fs::remove_dir_all(&dir);
                panic!(
                    "mdnsvpn exited with {status} during the 4s smoke window — \
                     our generated server_config.toml didn't parse.\n\
                     stdout:\n{stdout}\n\
                     stderr:\n{stderr}"
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

/// Find the mdnsvpn binary or extract one from
/// `vendor/mdnsvpn-linux-amd64.gz` into a fresh path under `dir`.
fn resolve_mdnsvpn_binary(dir: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("MDNSVPN_BIN_PATH") {
        let candidate = PathBuf::from(&p);
        if candidate.is_file() && is_executable(&candidate) {
            return Some(candidate);
        }
    }
    let blob = PathBuf::from("vendor/mdnsvpn-linux-amd64.gz");
    if !blob.is_file() {
        return None;
    }
    let extracted = PathBuf::from(format!("{dir}/mdnsvpn"));
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
