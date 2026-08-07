//! Verifies the hand-rolled ZIP writer against *real* extractors.
//!
//! `src/mdnsvpn/bundle.rs` writes the archive byte-by-byte with no zip crate
//! (see its module docs for why). Unit tests there assert the records look
//! right, but "looks right to the code that wrote it" is exactly the assumption
//! a format bug hides behind — a wrong CRC, size, or offset produces an archive
//! that our own parser reads back happily and `unzip` rejects.
//!
//! So this test hands the bytes to whatever extractor the machine has
//! (`unzip -t`, then Python's `zipfile`) and skips with a message if neither is
//! installed, rather than silently passing.

use std::process::Command;

use awg_easy_rs::db::{MdnsvpnClient, MdnsvpnInbound};
use awg_easy_rs::mdnsvpn::bundle;

fn fixture_inbound() -> MdnsvpnInbound {
    MdnsvpnInbound {
        id: "mdnsvpn0".into(),
        domains: r#"["v.example.com"]"#.into(),
        port: 53,
        bind: "0.0.0.0".into(),
        encryption_method: 5,
        encryption_key: "deadbeefcafebabe1234567890abcdef".into(),
        protocol_type: "SOCKS5".into(),
        dns_upstream_servers: r#"["1.1.1.1:53"]"#.into(),
        forward_ip: String::new(),
        forward_port: 0,
        use_external_socks5: false,
        socks5_auth: false,
        socks5_user: String::new(),
        socks5_pass: String::new(),
        additional_config: String::new(),
        enabled: true,
        created_at: "now".into(),
        updated_at: "now".into(),
    }
}

fn fixture_client() -> MdnsvpnClient {
    MdnsvpnClient {
        id: 1,
        user_id: None,
        inbound_id: "mdnsvpn0".into(),
        name: "alice".into(),
        resolvers: String::new(),
        listen_port: 18000,
        socks5_user: String::new(),
        socks5_pass: String::new(),
        expires_at: None,
        additional_config_toml: None,
        enabled: true,
        created_at: "now".into(),
        updated_at: "now".into(),
    }
}

fn have(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn archive_passes_real_extractors() {
    let zip = bundle::build(&fixture_inbound(), &fixture_client()).expect("build bundle");

    let dir = std::env::temp_dir().join(format!("awg-bundle-zip-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("bundle.zip");
    std::fs::write(&path, &zip).expect("write zip");

    let mut checked = 0;

    // 1) Info-ZIP: verifies CRCs and every structural offset.
    if have("unzip") {
        let out = Command::new("unzip")
            .arg("-t")
            .arg(&path)
            .output()
            .expect("run unzip -t");
        assert!(
            out.status.success(),
            "unzip -t rejected the archive:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("No errors detected"),
            "unzip -t did not report a clean archive: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        checked += 1;
    }

    // 2) Python zipfile: an independent implementation. Also confirms the
    //    contents come back out intact, not merely that the records parse.
    if have("python3") {
        let script = r#"
import sys, zipfile
p = sys.argv[1]
with zipfile.ZipFile(p) as z:
    bad = z.testzip()
    assert bad is None, "corrupt entry: %s" % bad
    names = sorted(z.namelist())
    assert names == ["README.txt", "client_config.toml", "client_resolvers.txt", "run.cmd", "run.sh"], names
    cfg = z.read("client_config.toml").decode()
    assert "ENCRYPTION_KEY" in cfg, "config missing key"
    assert "RESOLVERS =" not in cfg, "dead RESOLVERS key is back"
    res = z.read("client_resolvers.txt").decode()
    assert "8.8.8.8" in res, "resolver list missing"
    sh = z.read("run.sh").decode()
    assert "-resolvers client_resolvers.txt" in sh, "launcher does not pass the resolver file"
    # run.sh must be executable once extracted.
    mode = z.getinfo("run.sh").external_attr >> 16
    assert mode & 0o111 == 0o111, "run.sh not executable: %o" % mode
print("ok")
"#;
        let out = Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg(&path)
            .output()
            .expect("run python3");
        assert!(
            out.status.success(),
            "python zipfile rejected the archive:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        checked += 1;
    }

    let _ = std::fs::remove_dir_all(&dir);

    if checked == 0 {
        eprintln!("skipping: neither `unzip` nor `python3` available to validate the archive");
    }
}
