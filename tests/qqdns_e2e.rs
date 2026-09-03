//! End-to-end loopback test for the QQ-Tunnel engine.
//!
//! Stands up the full pipeline on localhost with no root and no port 53:
//!
//! ```text
//!  app ─▶ client-engine ─▶ resolver_rs ─▶ server-engine ─▶ fake-WG (echo)
//!   ▲                                                          │
//!   └──── client-engine ◀─ resolver_rc ◀─ server-engine ◀──────┘
//! ```
//!
//! A datagram sent by the "app" to the client engine must traverse both DNS
//! tunnels (each direction is DNS queries relayed by a trivial forwarder
//! standing in for a recursive resolver) and come back echoed by the fake
//! AmneziaWG server. This exercises everything the byte-parity tests don't:
//! the socket plumbing, the send-queue workers, address learning, the fixed
//! server target, and reassembly across the live path.

use std::time::Duration;

use awg_easy_rs::qqdns::engine::{start, EngineConfig};
use tokio::net::UdpSocket;

/// Grab a free UDP port on loopback (bind :0, read it back, drop). Good
/// enough for a loopback test; the window before the engine rebinds it is tiny.
async fn free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.local_addr().unwrap().port()
}

/// A trivial "resolver": forward every datagram it receives to `target`
/// (discarding the authoritative side's NOERROR response — tunnel data rides
/// only in the queries, in both directions).
async fn spawn_resolver(listen_port: u16, target_port: u16) {
    let sock = UdpSocket::bind(("127.0.0.1", listen_port)).await.unwrap();
    let target: std::net::SocketAddr = ([127, 0, 0, 1], target_port).into();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, _from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], target).await;
        }
    });
}

/// Fake AmneziaWG server: echo every datagram back to its sender.
async fn spawn_fake_wg(port: u16) {
    let sock = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
}

fn cfg_common() -> EngineConfig {
    EngineConfig {
        dns_ips: vec![],
        send_interface_ip: "127.0.0.1".into(),
        receive_interface_ip: "127.0.0.1".into(),
        receive_port: 0,
        send_domains: vec![],
        recv_domains: vec![],
        h_in_address: String::new(),
        h_out_address: None,
        max_domain_len: 253,
        max_sub_len: 63,
        retries: 0,
        send_query_type: 1,
        packets_send_interval: Duration::ZERO,
        packets_wait_time_limit: Duration::from_secs(5),
        send_sock_numbers: 1,
    }
}

#[tokio::test]
async fn end_to_end_udp_over_dns_roundtrip() {
    // Allocate the four engine-bound ports plus the three test-owned ones.
    let client_h_in = free_port().await;
    let client_recv = free_port().await;
    let server_h_in = free_port().await;
    let server_recv = free_port().await;
    let wg_port = free_port().await;
    let rs_port = free_port().await; // resolver: client -> server
    let rc_port = free_port().await; // resolver: server -> client

    // Middle boxes.
    spawn_fake_wg(wg_port).await;
    spawn_resolver(rs_port, server_recv).await;
    spawn_resolver(rc_port, client_recv).await;

    // Server engine (fixed target = fake WG).
    let server_cfg = EngineConfig {
        dns_ips: vec![format!("127.0.0.1:{rc_port}")],
        receive_port: server_recv,
        send_domains: vec!["client.test".into()],
        recv_domains: vec!["server.test".into()],
        h_in_address: format!("127.0.0.1:{server_h_in}"),
        h_out_address: Some(format!("127.0.0.1:{wg_port}")),
        ..cfg_common()
    };
    let server = start(server_cfg).await.expect("server engine starts");

    // Client engine (learns the app address).
    let client_cfg = EngineConfig {
        dns_ips: vec![format!("127.0.0.1:{rs_port}")],
        receive_port: client_recv,
        send_domains: vec!["server.test".into()],
        recv_domains: vec!["client.test".into()],
        h_in_address: format!("127.0.0.1:{client_h_in}"),
        h_out_address: None,
        ..cfg_common()
    };
    let client = start(client_cfg).await.expect("client engine starts");

    // Give the tasks a moment to be scheduled on their sockets.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // The "app": send a datagram to the client engine, expect it echoed back.
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.connect(("127.0.0.1", client_h_in)).await.unwrap();
    let payload = b"hello-amneziawg-over-dns";

    // Retry a few times — the very first packets can race socket readiness.
    let mut got = None;
    for _ in 0..20 {
        app.send(payload).await.unwrap();
        let mut buf = [0u8; 256];
        match tokio::time::timeout(Duration::from_millis(400), app.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                got = Some(buf[..n].to_vec());
                break;
            }
            _ => continue,
        }
    }

    server.stop();
    client.stop();

    assert_eq!(
        got.as_deref(),
        Some(payload.as_slice()),
        "datagram did not survive the round trip through both DNS tunnels"
    );
}

#[tokio::test]
async fn end_to_end_multi_fragment_roundtrip() {
    // A payload large enough to fragment across several QNAMEs, to exercise
    // the reassembler on the live path in both directions.
    let client_h_in = free_port().await;
    let client_recv = free_port().await;
    let server_h_in = free_port().await;
    let server_recv = free_port().await;
    let wg_port = free_port().await;
    let rs_port = free_port().await;
    let rc_port = free_port().await;

    spawn_fake_wg(wg_port).await;
    spawn_resolver(rs_port, server_recv).await;
    spawn_resolver(rc_port, client_recv).await;

    // Small max_domain_len forces many fragments even for a modest payload.
    let base = EngineConfig {
        max_domain_len: 80,
        packets_wait_time_limit: Duration::from_secs(8),
        ..cfg_common()
    };

    let server = start(EngineConfig {
        dns_ips: vec![format!("127.0.0.1:{rc_port}")],
        receive_port: server_recv,
        send_domains: vec!["client.test".into()],
        recv_domains: vec!["server.test".into()],
        h_in_address: format!("127.0.0.1:{server_h_in}"),
        h_out_address: Some(format!("127.0.0.1:{wg_port}")),
        ..base.clone()
    })
    .await
    .expect("server starts");

    let client = start(EngineConfig {
        dns_ips: vec![format!("127.0.0.1:{rs_port}")],
        receive_port: client_recv,
        send_domains: vec!["server.test".into()],
        recv_domains: vec!["client.test".into()],
        h_in_address: format!("127.0.0.1:{client_h_in}"),
        h_out_address: None,
        ..base
    })
    .await
    .expect("client starts");

    tokio::time::sleep(Duration::from_millis(150)).await;

    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.connect(("127.0.0.1", client_h_in)).await.unwrap();
    // ~600 bytes → many fragments at max_domain_len=80.
    let payload: Vec<u8> = (0..600u32).map(|i| (i * 7 + 3) as u8).collect();

    let mut got = None;
    for _ in 0..25 {
        app.send(&payload).await.unwrap();
        let mut buf = vec![0u8; 2048];
        match tokio::time::timeout(Duration::from_millis(500), app.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                got = Some(buf[..n].to_vec());
                break;
            }
            _ => continue,
        }
    }

    server.stop();
    client.stop();

    assert_eq!(
        got.as_deref(),
        Some(payload.as_slice()),
        "multi-fragment datagram did not survive the round trip"
    );
}
