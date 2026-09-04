//! Wire-level tests for the in-house HTTP/1.1 server.
//!
//! These drive raw TCP bytes at a real listener, because the parsing rules are
//! the security boundary: an admin panel that can be desynchronised from the
//! reverse proxy in front of it is a request-smuggling hole. Every case here
//! is a shape a proxy and a back end could otherwise disagree about, plus the
//! ordinary behaviours (keep-alive, HEAD, chunked bodies, limits) the panel
//! depends on.

use std::net::SocketAddr;
use std::time::Duration;

use coffeeblack_vpn::http::{
    routing::{get, post},
    Body, Json, Router,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Start the test server, returning its address and a shutdown trigger.
async fn start() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let app: Router<()> = Router::new()
        .route("/ping", get(|| async { "pong" }))
        .route(
            "/echo",
            post(|body: Body| async move {
                String::from_utf8(body.as_bytes().to_vec()).unwrap_or_default()
            }),
        )
        .route(
            "/json",
            get(|| async { Json(serde_json::json!({"ok": true})) }),
        )
        .route(
            "/peer",
            get(
                |coffeeblack_vpn::http::ConnectInfo(addr): coffeeblack_vpn::http::ConnectInfo<SocketAddr>| async move {
                    addr.to_string()
                },
            ),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = coffeeblack_vpn::http::serve(listener, app, async {
            let _ = rx.await;
        })
        .await;
    });
    (addr, tx)
}

/// Send raw bytes and read everything the server sends back.
async fn roundtrip(addr: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    stream.flush().await.unwrap();
    let mut out = Vec::new();
    // The server closes the connection on every error path; for keep-alive
    // responses the read ends when the peer goes idle.
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or("")
}

#[tokio::test]
async fn serves_a_simple_request() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 200 OK"), "{res}");
    assert!(res.contains("content-length: 4"), "{res}");
    assert!(res.ends_with("pong"), "{res}");
}

#[tokio::test]
async fn keeps_the_connection_alive_for_a_second_request() {
    let (addr, _shutdown) = start().await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let first = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(first.contains("200 OK"), "{first}");
    assert!(first.contains("connection: keep-alive"), "{first}");

    // The same connection must answer again.
    stream
        .write_all(b"GET /json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut rest)).await;
    let second = String::from_utf8_lossy(&rest).into_owned();
    assert!(second.contains("200 OK"), "{second}");
    assert!(second.contains(r#"{"ok":true}"#), "{second}");
}

#[tokio::test]
async fn head_returns_headers_without_a_body() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(
        addr,
        b"HEAD /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 200"), "{res}");
    assert!(res.contains("content-length: 4"), "{res}");
    assert!(!res.contains("pong"), "a HEAD response must carry no body: {res}");
}

#[tokio::test]
async fn reads_a_body_by_content_length() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(
        addr,
        b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 200"), "{res}");
    assert!(res.ends_with("hello"), "{res}");
}

#[tokio::test]
async fn reads_a_chunked_body() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(
        addr,
        b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
          5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 200"), "{res}");
    assert!(res.ends_with("hello world"), "{res}");
}

#[tokio::test]
async fn rejects_content_length_together_with_transfer_encoding() {
    // The canonical request-smuggling shape: a front end frames by one header
    // and a back end by the other.
    let (addr, _shutdown) = start().await;
    let res = roundtrip(
        addr,
        b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n\
          0\r\n\r\nGET /ping HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 400"), "{res}");
    assert!(!res.contains("pong"), "the smuggled request must not run: {res}");
}

#[tokio::test]
async fn rejects_conflicting_content_length_headers() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(
        addr,
        b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 400"), "{res}");
}

#[tokio::test]
async fn rejects_a_content_length_list_that_disagrees() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(
        addr,
        b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 6\r\n\r\nhello!",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 400"), "{res}");
}

#[tokio::test]
async fn rejects_an_unsupported_transfer_encoding() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(
        addr,
        b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 400"), "{res}");
}

#[tokio::test]
async fn rejects_obsolete_line_folding() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: x\r\nX-Fold: one\r\n  two\r\n\r\n",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 400"), "{res}");
}

#[tokio::test]
async fn rejects_whitespace_before_the_header_colon() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: x\r\nContent-Length : 0\r\n\r\n",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 400"), "{res}");
}

#[tokio::test]
async fn rejects_a_non_origin_form_target() {
    let (addr, _shutdown) = start().await;
    for line in [
        &b"GET http://evil.example/ping HTTP/1.1\r\nHost: x\r\n\r\n"[..],
        &b"CONNECT evil.example:443 HTTP/1.1\r\nHost: x\r\n\r\n"[..],
        &b"GET ping HTTP/1.1\r\nHost: x\r\n\r\n"[..],
    ] {
        let res = roundtrip(addr, line).await;
        assert!(status_line(&res).starts_with("HTTP/1.1 400"), "{res}");
    }
}

#[tokio::test]
async fn rejects_a_malformed_request_line() {
    let (addr, _shutdown) = start().await;
    for line in [
        &b"GET\r\n\r\n"[..],
        &b"GET /ping\r\n\r\n"[..],
        &b"GET /ping HTTP/9.9\r\n\r\n"[..],
        &b"GET /ping HTTP/1.1 extra\r\n\r\n"[..],
    ] {
        let res = roundtrip(addr, line).await;
        assert!(status_line(&res).starts_with("HTTP/1.1 400"), "{res}");
    }
}

#[tokio::test]
async fn rejects_oversized_headers() {
    let (addr, _shutdown) = start().await;
    let mut request = Vec::from(&b"GET /ping HTTP/1.1\r\nHost: x\r\n"[..]);
    for i in 0..200 {
        request.extend_from_slice(format!("X-Pad-{i}: {}\r\n", "a".repeat(200)).as_bytes());
    }
    request.extend_from_slice(b"\r\n");
    let res = roundtrip(addr, &request).await;
    assert!(status_line(&res).starts_with("HTTP/1.1 431"), "{res}");
}

#[tokio::test]
async fn rejects_an_oversized_body() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(
        addr,
        b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4194304\r\n\r\n",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 413"), "{res}");
}

#[tokio::test]
async fn answers_expect_100_continue_before_the_body() {
    let (addr, _shutdown) = start().await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n",
        )
        .await
        .unwrap();
    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("server must answer the expectation")
        .unwrap();
    let interim = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(interim.starts_with("HTTP/1.1 100 Continue"), "{interim}");

    stream.write_all(b"hello").await.unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut rest)).await;
    let res = String::from_utf8_lossy(&rest).into_owned();
    assert!(res.contains("200 OK"), "{res}");
    assert!(res.ends_with("hello"), "{res}");
}

#[tokio::test]
async fn unknown_paths_and_methods_get_the_right_status() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(addr, b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    assert!(status_line(&res).starts_with("HTTP/1.1 404"), "{res}");

    let res = roundtrip(
        addr,
        b"DELETE /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(status_line(&res).starts_with("HTTP/1.1 405"), "{res}");
    assert!(res.to_ascii_lowercase().contains("allow:"), "{res}");
}

#[tokio::test]
async fn the_peer_address_reaches_the_handler() {
    let (addr, _shutdown) = start().await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let local = stream.local_addr().unwrap();
    stream
        .write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut out)).await;
    let res = String::from_utf8_lossy(&out).into_owned();
    assert!(res.ends_with(&local.to_string()), "{res} should end with {local}");
}

#[tokio::test]
async fn http_1_0_closes_unless_keep_alive_is_asked_for() {
    let (addr, _shutdown) = start().await;
    let res = roundtrip(addr, b"GET /ping HTTP/1.0\r\nHost: x\r\n\r\n").await;
    assert!(res.contains("connection: close"), "{res}");

    let res = roundtrip(
        addr,
        b"GET /ping HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
    )
    .await;
    assert!(res.contains("connection: keep-alive"), "{res}");
}

#[tokio::test]
async fn shutdown_stops_the_listener() {
    let (addr, shutdown) = start().await;
    // Works before shutdown.
    let res = roundtrip(addr, b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    assert!(res.contains("200 OK"), "{res}");

    shutdown.send(()).unwrap();
    // Give the accept loop a moment to unwind.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let connected = TcpStream::connect(addr).await;
    if let Ok(mut stream) = connected {
        // The socket may still accept a connection from the backlog, but no
        // response can come back.
        let _ = stream
            .write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await;
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_millis(500), stream.read_to_end(&mut out)).await;
        assert!(
            !String::from_utf8_lossy(&out).contains("200 OK"),
            "server answered after shutdown"
        );
    }
}
