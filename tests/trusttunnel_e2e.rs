//! End-to-end check of the generated TrustTunnel config against the real,
//! bundled `trusttunnel_endpoint`.
//!
//! Unit tests pin key names and shapes; only the upstream binary can say
//! whether it actually accepts them. This test drives the supervisor the way
//! the API does, then speaks the protocol at the endpoint over its HTTP/1.1
//! listener (raw `CONNECT`, the same probe upstream's own
//! `lib/tests/authentication.rs` uses):
//!
//! 1. it starts and answers `/health-check` on the metrics listener;
//! 2. it presents the certificate we issued for the hostname we chose;
//! 3. a generated user's credentials open a tunnel that carries bytes;
//! 4. wrong credentials get the configured auth-failure status;
//! 5. `/clients` reports the user, and our RAM store folds it in;
//! 6. a roster change restarts it and the *new* credentials work.
//!
//! Compiled only when the endpoint is bundled (`trusttunnel_bundled`).

#![cfg(trusttunnel_bundled)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use coffeeblack_vpn::db;
use coffeeblack_vpn::trusttunnel::{stats, supervisor};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const HOSTNAME: &str = "tt.e2e.test";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn connector(chain_pem: &str) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(chain_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(cfg))
}

/// TLS to the endpoint, `CONNECT dest`, return the status and the stream.
async fn connect(
    tls: &TlsConnector,
    port: u16,
    user: &str,
    pass: &str,
    dest: &str,
) -> (u16, tokio_rustls::client::TlsStream<TcpStream>) {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let name = ServerName::try_from(HOSTNAME.to_string()).unwrap();
    // Certificate verification against our pinned chain is part of the
    // test: a hostname/SAN mismatch fails here.
    let mut stream = tls.connect(name, tcp).await.expect("TLS handshake with the pinned certificate");
    let auth = coffeeblack_vpn::encoding::b64_encode(format!("{user}:{pass}"));
    let req = format!("CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\nProxy-Authorization: Basic {auth}\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read_exact(&mut byte).await {
            Ok(_) => head.push(byte[0]),
            Err(_) => return (0, stream),
        }
        assert!(head.len() < 16 * 1024, "unterminated response head");
    }
    let line = String::from_utf8_lossy(&head);
    let code = line.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (code, stream)
}

async fn wait_running() {
    for _ in 0..80 {
        if let supervisor::Status::Running { healthy: true, .. } = supervisor::status().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("endpoint never became healthy: {:?}", supervisor::status().await);
}

async fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(db)]
async fn real_endpoint_accepts_generated_config_and_credentials() {
    common::seed();
    let port = free_port();
    let metrics = free_port();
    let mut f = db::UpdateMap::new();
    f.insert("enabled".into(), "1".into());
    f.insert("hostname".into(), HOSTNAME.into());
    f.insert("port".into(), port.to_string());
    f.insert("metrics_port".into(), metrics.to_string());
    f.insert("listen_http1".into(), "1".into());
    // The echo target is on loopback, which the endpoint refuses by default.
    f.insert("allow_private_network".into(), "1".into());
    f.insert("auth_failure_status_code".into(), "404".into());
    db::update_trusttunnel_inbound(&f).unwrap();

    let mk = |name: &str| db::CreateTrustTunnelUserParams {
        user_id: None,
        name: name.into(),
        username: name.into(),
        password: coffeeblack_vpn::trusttunnel::keys::generate_password(),
        client_random_prefix: String::new(),
        expires_at: None,
        enabled: true,
    };
    let alice = db::create_trusttunnel_user(&mk("alice")).unwrap();

    supervisor::ensure_running().await.expect("supervisor starts the endpoint");
    wait_running().await;

    let inbound = db::get_trusttunnel_inbound().unwrap();
    assert_eq!(inbound.tls_cert_hostname, HOSTNAME, "self-signed certificate issued on start");
    let tls = connector(&inbound.tls_chain_pem);
    let echo = echo_server().await;
    let dest = format!("127.0.0.1:{echo}");

    let alice_pw = db::get_trusttunnel_user(alice).unwrap().password;
    let (code, mut tunnel) = connect(&tls, port, "alice", &alice_pw, &dest).await;
    assert_eq!(code, 200, "generated credentials must authenticate");
    tunnel.write_all(b"coffeeblack-e2e").await.unwrap();
    let mut back = [0u8; 15];
    tokio::time::timeout(Duration::from_secs(5), tunnel.read_exact(&mut back))
        .await
        .expect("echo through the tunnel")
        .unwrap();
    assert_eq!(&back, b"coffeeblack-e2e");
    drop(tunnel);

    let (code, _) = connect(&tls, port, "alice", "wrong-password-0000000", &dest).await;
    assert_eq!(code, 404, "configured auth_failure_status_code");

    let rows = stats::fetch_clients(metrics).await.expect("/clients with per_client_metrics");
    let row = rows.iter().find(|r| r.username == "alice").expect("alice listed");
    assert!(row.inbound > 0 || row.outbound > 0, "per-user counters moved: {row:?}");
    stats::record(&rows, "now");
    assert!(stats::get("alice").rx_bytes > 0 || stats::get("alice").tx_bytes > 0);

    // Roster change → restart → the new user works, the removed one does not.
    let bob = db::create_trusttunnel_user(&mk("bob")).unwrap();
    db::delete_trusttunnel_user(alice).unwrap();
    supervisor::ensure_running().await.expect("restart with the new roster");
    wait_running().await;
    let bob_pw = db::get_trusttunnel_user(bob).unwrap().password;
    let (code, _) = connect(&tls, port, "bob", &bob_pw, &dest).await;
    assert_eq!(code, 200, "new user after restart");
    let (code, _) = connect(&tls, port, "alice", &alice_pw, &dest).await;
    assert_eq!(code, 404, "deleted user is refused");

    supervisor::stop().await.unwrap();
    assert!(matches!(supervisor::status().await, supervisor::Status::Disabled { .. }));
}
