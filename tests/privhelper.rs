//! Privileged-helper tests.
//!
//! These drive a real helper over a real Unix socket in a temp directory. The
//! commands it shells out to (`awg`, `nft`) are absent in the test
//! environment, so operations that exec fail — which is fine and is itself
//! worth asserting: what matters here is the boundary, not whether nftables is
//! installed. The properties under test are that the allowlist cannot be
//! escaped, that request fields cannot redirect an operation, and that the
//! socket is not world-reachable.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use coffeeblack_vpn::privhelper::{self, HelperConfig, Request, Response};
use serial_test::serial;

/// Spawn a helper on a fresh socket and return its path plus the conf dir it
/// is pinned to. The thread is left running; the process exits at test end.
fn start_helper(name: &str) -> (PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("coffeeblack-helper-test-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let socket = base.join("helper.sock");
    let conf_dir = base.join("wg");
    std::fs::create_dir_all(&conf_dir).unwrap();

    let cfg = HelperConfig {
        socket_path: socket.clone(),
        interface: "cb0".to_string(),
        conf_dir: conf_dir.clone(),
        allow_gid: None,
    };
    std::thread::spawn(move || {
        let _ = privhelper::serve(cfg);
    });

    // The listener binds on the helper thread; wait for the socket to appear
    // rather than racing it with a fixed sleep.
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(socket.exists(), "helper socket never appeared");
    (socket, conf_dir)
}

/// Send a raw line and read the raw response, bypassing the typed client so a
/// test can send things the client would never construct.
fn raw(socket: &PathBuf, line: &str) -> Response {
    let stream = UnixStream::connect(socket).expect("connect helper");
    (&stream).write_all(line.as_bytes()).unwrap();
    (&stream).write_all(b"\n").unwrap();
    (&stream).flush().unwrap();
    let mut reader = BufReader::new(&stream);
    let mut resp = String::new();
    reader.read_line(&mut resp).unwrap();
    serde_json::from_str(resp.trim()).expect("helper response is JSON")
}

#[test]
fn ping_round_trips() {
    let (socket, _) = start_helper("ping");
    let resp = raw(&socket, r#"{"op":"ping"}"#);
    assert!(resp.ok);
    assert_eq!(resp.output.as_deref(), Some("pong"));
}

#[test]
fn socket_is_not_world_accessible() {
    let (socket, _) = start_helper("perms");
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    // No group and no other bits: with no gid configured, only root may
    // connect. A helper reachable by any local account would hand every user
    // on the box control of the tunnel.
    assert_eq!(mode, 0o600, "socket mode was {mode:o}");
}

#[test]
fn unknown_operations_are_refused() {
    let (socket, _) = start_helper("unknown");
    // The allowlist is the request enum, so an op outside it cannot even be
    // parsed — there is no path from the wire to an arbitrary command.
    for line in [
        r#"{"op":"exec","argv":["sh","-c","id"]}"#,
        r#"{"op":"run","cmd":"cat /etc/shadow"}"#,
        r#"{"op":"WgUp"}"#,
        r#"{"op":123}"#,
        r#"not json at all"#,
        r#"{}"#,
    ] {
        let resp = raw(&socket, line);
        assert!(!resp.ok, "should have refused: {line}");
        assert!(
            resp.error.unwrap_or_default().contains("malformed request"),
            "{line} should be rejected at parse time"
        );
    }
}

#[test]
fn extra_request_fields_cannot_redirect_an_operation() {
    let (socket, conf_dir) = start_helper("redirect");
    // A caller trying to point wg_sync at another path. The helper derives the
    // path from its own fixed interface + conf dir, so the extra fields are
    // inert — the write lands where the helper decided, never where the
    // request asked.
    let escape = "/tmp/coffeeblack-helper-escape-target.conf";
    std::fs::remove_file(escape).ok();
    let resp = raw(
        &socket,
        &format!(
            r#"{{"op":"wg_sync","config":"[Interface]\nPrivateKey = x\n","path":"{escape}","interface":"eth0","conf_dir":"/tmp"}}"#
        ),
    );
    // The write itself succeeds; the sync may or may not, depending on whether
    // `awg` exists. Either way the file must be in the helper's own directory.
    let _ = resp;
    assert!(
        !std::path::Path::new(escape).exists(),
        "helper must not write to a path supplied in the request"
    );
    assert!(
        conf_dir.join("cb0.conf").exists(),
        "helper should have written its own fixed path"
    );
}

#[test]
fn written_config_is_owner_only() {
    let (socket, conf_dir) = start_helper("confperms");
    raw(
        &socket,
        r#"{"op":"wg_sync","config":"[Interface]\nPrivateKey = secret\n"}"#,
    );
    let path = conf_dir.join("cb0.conf");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    // The file carries the server private key.
    assert_eq!(mode, 0o600, "conf mode was {mode:o}");
    assert!(std::fs::read_to_string(&path).unwrap().contains("PrivateKey = secret"));
}

#[test]
fn operations_that_need_missing_binaries_fail_cleanly() {
    let (socket, _) = start_helper("nobin");
    // `nft` and `awg` are not installed in the test environment. The helper
    // must answer with a structured error rather than hanging, panicking, or
    // dropping the connection — the caller has to be able to tell "refused"
    // from "unreachable".
    for line in [
        r#"{"op":"nft_list"}"#,
        r#"{"op":"nft_apply","ruleset":"table inet t {}"}"#,
        r#"{"op":"wg_up"}"#,
        r#"{"op":"wg_down"}"#,
        r#"{"op":"wg_show"}"#,
    ] {
        let resp = raw(&socket, line);
        assert!(!resp.ok, "{line} should report failure without nft/awg present");
        assert!(resp.error.is_some());
    }
}

#[test]
fn helper_survives_a_malformed_connection() {
    let (socket, _) = start_helper("survive");
    // Garbage, then a valid request on a new connection. A helper that died on
    // bad input would take the interface's only control path with it.
    raw(&socket, "\u{0}\u{1}garbage");
    let resp = raw(&socket, r#"{"op":"ping"}"#);
    assert!(resp.ok, "helper must still serve after a malformed request");
}

// These two mutate COFFEEBLACK_HELPER_SOCKET, which `is_enabled()` reads live, so
// they must not run alongside each other.
#[test]
#[serial(helper_env)]
fn client_is_disabled_unless_the_socket_env_var_is_set() {
    // The default must remain the original single-process behaviour: an
    // upgrade should change nothing until the operator opts in.
    std::env::remove_var("COFFEEBLACK_HELPER_SOCKET");
    assert!(!privhelper::is_enabled());
    assert!(privhelper::socket_path().is_none());
}

#[test]
#[serial(helper_env)]
fn typed_client_round_trips_against_a_real_helper() {
    let (socket, _) = start_helper("client");
    std::env::set_var("COFFEEBLACK_HELPER_SOCKET", &socket);
    assert!(privhelper::is_enabled());
    let out = privhelper::call(&Request::Ping).expect("ping via typed client");
    assert_eq!(out, "pong");

    // A failing op surfaces as an Err, not a silent empty success.
    assert!(privhelper::call(&Request::NftList).is_err());
    std::env::remove_var("COFFEEBLACK_HELPER_SOCKET");
}

#[test]
fn socket_is_owner_only_regardless_of_ambient_umask() {
    // The helper narrows the umask across `bind()`, because that call applies
    // the process umask and the socket is therefore briefly mode 0755 under a
    // default 0022 — long enough for a local user to connect and drive the
    // tunnel.
    //
    // Honest scope: this asserts the END STATE, which catches the chmod being
    // dropped or weakened. It does NOT catch the transient window — observing
    // that would mean racing bind(), and manipulating the process umask to
    // widen the window is itself unsafe here, because umask(2) is per-process
    // and would leak into every other test creating a file concurrently. The
    // umask narrowing in `serve` is verified by inspection; this guards the
    // rest.
    let (socket, _) = start_helper("umask");
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket mode was {mode:o}");
}

#[test]
fn config_is_owner_only_regardless_of_ambient_umask() {
    // Same class, higher stakes: this file holds the server private key. Here
    // the end-state assertion is stronger than for the socket, because the
    // file is created with `.mode(0o600)` on `open(2)` — there is no
    // create-then-fix sequence to have a window in the first place.
    let (socket, conf_dir) = start_helper("confumask");
    raw(&socket, r#"{"op":"wg_sync","config":"[Interface]\nPrivateKey = k\n"}"#);
    let mode = std::fs::metadata(conf_dir.join("cb0.conf"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "conf mode was {mode:o}");
}
