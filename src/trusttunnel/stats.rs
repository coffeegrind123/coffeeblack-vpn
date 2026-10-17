//! Per-user TrustTunnel traffic — **RAM only**, same rule as
//! [`crate::activity`]: who moved how much is connection history, so it has
//! no code path to SQLite or any file.
//!
//! The endpoint keeps per-user byte counters (`per_client_metrics = true`,
//! served as JSON on `127.0.0.1:<metrics_port>/clients`), but they are
//! lifetime-of-process totals, and every roster change restarts the process
//! (credentials are read once, at startup). Reading them directly would
//! reset each user's figures whenever anyone else is added. So this module
//! folds each poll into monotonic totals from clamped deltas: a counter
//! that went *down* means the process restarted, and the new value is the
//! delta.
//!
//! The endpoint also reports each user's source IP. That is never stored.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Poll cadence of the supervisor's metrics loop.
pub const POLL_INTERVAL: Duration = Duration::from_secs(30);

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Plenty for a few thousand users' summaries.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// One `/clients` row (upstream `ClientSummary`). `inbound` is bytes the
/// client sent, `outbound` bytes it received. `ip` is not deserialised.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientSummary {
    pub username: String,
    #[serde(default)]
    pub sessions: u64,
    #[serde(default)]
    pub inbound: u64,
    #[serde(default)]
    pub outbound: u64,
}

/// What the API reports for one user.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UserTraffic {
    /// Bytes sent by the client, accumulated across endpoint restarts.
    pub rx_bytes: u64,
    /// Bytes received by the client, accumulated across endpoint restarts.
    pub tx_bytes: u64,
    /// Live tunnel sessions at the last poll.
    pub sessions: u64,
    /// RFC 3339 time of the last poll that saw traffic or a session.
    pub last_active: Option<String>,
}

#[derive(Debug, Default)]
struct Entry {
    traffic: UserTraffic,
    last_raw_in: u64,
    last_raw_out: u64,
}

static STORE: LazyLock<RwLock<HashMap<String, Entry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Fold one poll into the totals. Returns how many users moved bytes.
pub fn record(rows: &[ClientSummary], now_rfc3339: &str) -> usize {
    let mut store = STORE.write().unwrap_or_else(|p| p.into_inner());
    let mut active = 0;
    for row in rows {
        let e = store.entry(row.username.clone()).or_default();
        // Clamped delta: a lower raw value means the endpoint restarted and
        // counts from zero again, so the whole raw value is new traffic.
        let d_in = if row.inbound >= e.last_raw_in { row.inbound - e.last_raw_in } else { row.inbound };
        let d_out = if row.outbound >= e.last_raw_out { row.outbound - e.last_raw_out } else { row.outbound };
        e.last_raw_in = row.inbound;
        e.last_raw_out = row.outbound;
        e.traffic.rx_bytes = e.traffic.rx_bytes.saturating_add(d_in);
        e.traffic.tx_bytes = e.traffic.tx_bytes.saturating_add(d_out);
        e.traffic.sessions = row.sessions;
        if d_in > 0 || d_out > 0 || row.sessions > 0 {
            e.traffic.last_active = Some(now_rfc3339.to_string());
            if d_in > 0 || d_out > 0 {
                active += 1;
            }
        }
    }
    active
}

/// The endpoint process is gone: its counters will restart from zero, and
/// nobody holds a session any more.
pub fn mark_endpoint_restarted() {
    let mut store = STORE.write().unwrap_or_else(|p| p.into_inner());
    for e in store.values_mut() {
        e.last_raw_in = 0;
        e.last_raw_out = 0;
        e.traffic.sessions = 0;
    }
}

pub fn get(username: &str) -> UserTraffic {
    let store = STORE.read().unwrap_or_else(|p| p.into_inner());
    store.get(username).map(|e| e.traffic.clone()).unwrap_or_default()
}

/// Drop history for users no longer in the roster.
pub fn retain(usernames: &[String]) {
    let mut store = STORE.write().unwrap_or_else(|p| p.into_inner());
    store.retain(|k, _| usernames.iter().any(|u| u == k));
}

pub fn forget(username: &str) {
    let mut store = STORE.write().unwrap_or_else(|p| p.into_inner());
    store.remove(username);
}

// ---------------------------------------------------------------------------
// Metrics listener client
// ---------------------------------------------------------------------------

/// GET `path` from the loopback metrics listener. Returns `(status, body)`.
/// The listener answers with `Content-Length`, which is honoured so the
/// read never depends on the server closing the connection. `head_only`
/// returns as soon as the status line is in (the body is empty).
async fn get_raw(port: u16, path: &str, head_only: bool) -> Result<(u16, Vec<u8>)> {
    let fut = async move {
        let addr = ("127.0.0.1", port);
        let mut stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connect to TrustTunnel metrics on 127.0.0.1:{port}"))?;
        let head = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: coffeeblack-vpn\r\n\
             Connection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes()).await.context("write request")?;

        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 8192];
        loop {
            if let Some((status, body_start, len)) = parse_head(&buf)? {
                if head_only {
                    return Ok((status, Vec::new()));
                }
                if let Some(len) = len {
                    let want = body_start.saturating_add(len);
                    if want > MAX_RESPONSE_BYTES {
                        bail!("TrustTunnel metrics response exceeds {MAX_RESPONSE_BYTES} bytes");
                    }
                    if buf.len() >= want {
                        return Ok((status, buf[body_start..want].to_vec()));
                    }
                }
                // No Content-Length: the body runs to EOF, handled below.
            }
            let n = stream.read(&mut tmp).await.context("read response")?;
            if n == 0 {
                return match parse_head(&buf)? {
                    Some((status, start, _)) => Ok((status, buf[start..].to_vec())),
                    None => Err(anyhow!("TrustTunnel metrics closed before a full response head")),
                };
            }
            if buf.len() + n > MAX_RESPONSE_BYTES {
                bail!("TrustTunnel metrics response exceeds {MAX_RESPONSE_BYTES} bytes");
            }
            buf.extend_from_slice(&tmp[..n]);
        }
    };
    timeout(REQUEST_TIMEOUT, fut)
        .await
        .map_err(|_| anyhow!("TrustTunnel metrics GET {path} timed out after {REQUEST_TIMEOUT:?}"))?
}

/// `Some((status, body_offset, content_length))` once the head is complete.
fn parse_head(buf: &[u8]) -> Result<Option<(u16, usize, Option<usize>)>> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };
    let head = std::str::from_utf8(&buf[..end]).context("response head is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| anyhow!("malformed status line {status_line:?}"))?;
    let mut length = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                length = Some(v.trim().parse::<usize>().context("bad Content-Length")?);
            }
            if k.trim().eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
                bail!("TrustTunnel metrics used chunked encoding, which this client does not parse");
            }
        }
    }
    Ok(Some((status, end + 4, length)))
}

/// `true` when `/health-check` answers 200.
pub async fn healthy(port: u16) -> bool {
    matches!(get_raw(port, "/health-check", true).await, Ok((200, _)))
}

/// Poll until healthy or `deadline` passes.
pub async fn wait_until_healthy(port: u16, deadline: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if healthy(port).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Fetch `/clients`.
pub async fn fetch_clients(port: u16) -> Result<Vec<ClientSummary>> {
    let (status, body) = get_raw(port, "/clients", false).await?;
    if status != 200 {
        bail!("TrustTunnel /clients answered HTTP {status} (is per_client_metrics on?)");
    }
    serde_json::from_slice(&body).with_context(|| {
        format!("decode TrustTunnel /clients JSON ({} bytes)", body.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(user: &str, sessions: u64, inbound: u64, outbound: u64) -> ClientSummary {
        ClientSummary { username: user.into(), sessions, inbound, outbound }
    }

    // One test owns the global store end to end, so parallel tests cannot
    // interleave with it.
    #[test]
    fn totals_survive_endpoint_restarts_and_ignore_ip() {
        retain(&[]);
        assert_eq!(record(&[row("st-a", 1, 100, 1000)], "t1"), 1);
        assert_eq!(record(&[row("st-a", 1, 150, 1500)], "t2"), 1);
        assert_eq!(get("st-a").rx_bytes, 150);
        assert_eq!(get("st-a").tx_bytes, 1500);

        // The endpoint restarted: raw counters fell back below the last read.
        assert_eq!(record(&[row("st-a", 0, 20, 30)], "t3"), 1);
        let t = get("st-a");
        assert_eq!((t.rx_bytes, t.tx_bytes, t.sessions), (170, 1530, 0));
        assert_eq!(t.last_active.as_deref(), Some("t3"));

        // An explicit restart notice followed by an idle poll adds nothing.
        mark_endpoint_restarted();
        assert_eq!(record(&[row("st-a", 0, 0, 0)], "t4"), 0);
        assert_eq!(get("st-a").rx_bytes, 170);
        assert_eq!(get("st-a").last_active.as_deref(), Some("t3"));

        retain(&["other".into()]);
        assert_eq!(get("st-a"), UserTraffic::default());
    }

    #[test]
    fn clients_json_decodes_and_ip_is_dropped() {
        let body = br#"[{"username":"alice","ip":"203.0.113.9","sessions":2,"inbound":10,"outbound":20}]"#;
        let rows: Vec<ClientSummary> = serde_json::from_slice(body).unwrap();
        assert_eq!(rows[0].username, "alice");
        assert_eq!((rows[0].sessions, rows[0].inbound, rows[0].outbound), (2, 10, 20));
    }

    #[test]
    fn response_head_parsing() {
        let r = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n[]";
        assert_eq!(parse_head(r).unwrap(), Some((200, r.len() - 2, Some(2))));
        assert_eq!(parse_head(b"HTTP/1.1 200 OK\r\n").unwrap(), None);
        assert!(parse_head(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n").is_err());
        assert!(parse_head(b"garbage\r\n\r\n").is_err());
    }
}
