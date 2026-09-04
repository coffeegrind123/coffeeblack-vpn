//! Minimal HTTP/1.1 client for telemt's loopback control plane.
//!
//! Telemt exposes a JSON HTTP API on `127.0.0.1:9091` (configurable in
//! `[server.api]`). We use it for:
//!
//! - `GET  /v1/health` / `GET /v1/health/ready` — wait-for-ready after spawn
//! - `GET  /v1/users`             — list users (with rendered tg:// links)
//! - `GET  /v1/users/{name}`      — read one user
//! - `POST /v1/users`             — create user
//! - `PATCH /v1/users/{name}`     — update user (ad_tag, etc.)
//! - `DELETE /v1/users/{name}`    — delete user
//! - `POST /v1/users/{name}/rotate-secret`  — rotate, server returns new secret
//! - `POST /v1/users/{name}/reset-quota`    — reset traffic counters
//! - `GET  /v1/stats/summary`     — aggregate stats
//! - `GET  /v1/stats/users`       — per-user stats
//!
//! Pulling in a full HTTP client (hyper, reqwest) for a localhost JSON
//! API of half-a-dozen endpoints isn't worth the build-time +
//! binary-size cost. This module is a tight, focused HTTP/1.1 client
//! over a `tokio::net::TcpStream`: writes one request with
//! `Connection: close`, reads everything until EOF, parses status +
//! headers + body. No chunked encoding, no keep-alive, no compression
//! — telemt's hyper server speaks plain `Content-Length` responses for
//! everything we hit.
//!
//! Hard cap on response size protects against a runaway server: we
//! refuse to allocate more than `MAX_RESPONSE_BYTES`.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Telemt's loopback API host:port. Locked to localhost in the
/// generated config.toml — `[server.api]` whitelist is also
/// `127.0.0.1/32` + `::1/128`. Matches the hard-coded `listen` line
/// in `mtproxy::config::generate`.
pub const TELEMT_API_HOST: &str = "127.0.0.1";
pub const TELEMT_API_PORT: u16 = 9091;

/// 4 MiB ceiling on a single response body. The biggest response we
/// ever hit is `/v1/users` (potentially hundreds of users with their
/// link arrays); 4 MiB is hundreds of users worth of JSON. Anything
/// larger means something is wrong on the server side and we should
/// fail rather than OOM.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Total request budget. Localhost RTT is microseconds; 5 s is enough
/// headroom that even a stop-the-world gc on the server side wouldn't
/// trip it, but short enough that an admin UI request doesn't hang
/// forever if telemt crashed mid-call.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Subset of the JSON each `[GET|POST|PATCH] /v1/users[/name]` returns
/// that we actually consume. Telemt's response carries more fields
/// (stats, last-seen, per-user gates); we leave them as JSON Value at
/// the API edge so the admin UI can render them without us re-modeling
/// every telemt struct.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserPayload {
    pub username: String,
    /// 32-hex secret. Always present in GET / POST responses; not sent
    /// back as a separate field on PATCH responses if the secret didn't
    /// change.
    #[serde(default)]
    pub secret: Option<String>,
    /// Per-user ad_tag override. Telemt names this field `user_ad_tag`
    /// on the wire — in responses *and* in POST/PATCH request bodies.
    /// It ignores unknown keys silently (a body with `ad_tag` returns
    /// 2xx with `user_ad_tag: null`), so the rename is load-bearing:
    /// verified against telemt 3.4.24 and 3.5.5.
    #[serde(default, rename = "user_ad_tag")]
    pub ad_tag: Option<String>,
    /// `tg://proxy?...` links pre-rendered by telemt. We pass them
    /// through to the admin UI as-is.
    #[serde(default)]
    pub links: Option<Value>,
}

/// Request body for `POST /v1/users`.
#[derive(Debug, Clone, Serialize)]
pub struct CreateUser<'a> {
    pub username: &'a str,
    pub secret: &'a str,
    /// Serialized as `user_ad_tag` — see [`UserPayload::ad_tag`].
    #[serde(rename = "user_ad_tag", skip_serializing_if = "Option::is_none")]
    pub ad_tag: Option<&'a str>,
}

/// Request body for `PATCH /v1/users/{name}`. All fields optional;
/// fields not in the body are left as-is on telemt's side.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PatchUser<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<&'a str>,
    /// Serialized as `user_ad_tag` — see [`UserPayload::ad_tag`].
    #[serde(rename = "user_ad_tag", skip_serializing_if = "Option::is_none")]
    pub ad_tag: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// `is_alive` returns true when telemt's HTTP API is responding (its
/// listener is bound and `/v1/health` returns 200). We deliberately
/// do NOT use `/v1/health/ready` here: that endpoint also checks
/// Telegram middle-end pool reachability, which can take 20–30 s on
/// first boot and never resolves in degraded networks. The user CRUD
/// API works as soon as `/v1/health` is up — confirmed via smoke
/// test against telemt 3.4.11.
pub async fn is_alive() -> Result<bool> {
    match request("GET", "/v1/health", None).await {
        Ok((200..=299, _)) => Ok(true),
        Ok((status, _)) => {
            tracing::debug!(status, "telemt /v1/health not 2xx yet");
            Ok(false)
        }
        Err(e) => {
            tracing::trace!(error = ?e, "telemt /v1/health connect/IO error (not alive yet)");
            Ok(false)
        }
    }
}

/// Block until `is_alive()` returns true or `deadline` elapses. Polls
/// every 200 ms — quick enough to make the supervisor responsive,
/// slow enough that a busy-loop on a not-yet-listening port doesn't
/// pin a CPU.
pub async fn wait_until_alive(deadline: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        if is_alive().await.unwrap_or(false) {
            return Ok(());
        }
        if start.elapsed() >= deadline {
            return Err(anyhow!(
                "telemt /v1/health did not return 2xx within {deadline:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

pub async fn list_users() -> Result<Value> {
    let (status, body) = request("GET", "/v1/users", None).await?;
    expect_2xx(status, &body, "GET /v1/users")?;
    Ok(unwrap_envelope(parse_json(&body)?))
}

pub async fn get_user(username: &str) -> Result<Option<Value>> {
    let path = format!("/v1/users/{}", url_path_encode(username));
    let (status, body) = request("GET", &path, None).await?;
    if status == 404 {
        return Ok(None);
    }
    expect_2xx(status, &body, &format!("GET {path}"))?;
    Ok(Some(unwrap_envelope(parse_json(&body)?)))
}

pub async fn create_user(req: &CreateUser<'_>) -> Result<Value> {
    let body_bytes = serde_json::to_vec(req).context("encode CreateUser")?;
    let (status, body) = request("POST", "/v1/users", Some(&body_bytes)).await?;
    // 200/201 on create. 409 means a user with this name already
    // exists — caller's responsibility to decide whether to upsert.
    expect_2xx(status, &body, "POST /v1/users")?;
    Ok(unwrap_envelope(parse_json(&body)?))
}

pub async fn patch_user(username: &str, patch: &PatchUser<'_>) -> Result<Value> {
    let path = format!("/v1/users/{}", url_path_encode(username));
    let body_bytes = serde_json::to_vec(patch).context("encode PatchUser")?;
    let (status, body) = request("PATCH", &path, Some(&body_bytes)).await?;
    expect_2xx(status, &body, &format!("PATCH {path}"))?;
    Ok(unwrap_envelope(parse_json(&body)?))
}

pub async fn delete_user(username: &str) -> Result<()> {
    let path = format!("/v1/users/{}", url_path_encode(username));
    let (status, body) = request("DELETE", &path, None).await?;
    if status == 404 {
        // Already gone — idempotent delete.
        return Ok(());
    }
    expect_2xx(status, &body, &format!("DELETE {path}"))?;
    Ok(())
}

pub async fn rotate_secret(username: &str) -> Result<Value> {
    let path = format!("/v1/users/{}/rotate-secret", url_path_encode(username));
    let (status, body) = request("POST", &path, None).await?;
    expect_2xx(status, &body, &format!("POST {path}"))?;
    Ok(unwrap_envelope(parse_json(&body)?))
}

pub async fn reset_quota(username: &str) -> Result<()> {
    let path = format!("/v1/users/{}/reset-quota", url_path_encode(username));
    let (status, body) = request("POST", &path, None).await?;
    expect_2xx(status, &body, &format!("POST {path}"))?;
    Ok(())
}

pub async fn stats_summary() -> Result<Value> {
    let (status, body) = request("GET", "/v1/stats/summary", None).await?;
    expect_2xx(status, &body, "GET /v1/stats/summary")?;
    Ok(unwrap_envelope(parse_json(&body)?))
}

pub async fn stats_users() -> Result<Value> {
    let (status, body) = request("GET", "/v1/stats/users", None).await?;
    expect_2xx(status, &body, "GET /v1/stats/users")?;
    Ok(unwrap_envelope(parse_json(&body)?))
}

pub async fn system_info() -> Result<Value> {
    let (status, body) = request("GET", "/v1/system/info", None).await?;
    expect_2xx(status, &body, "GET /v1/system/info")?;
    Ok(unwrap_envelope(parse_json(&body)?))
}

/// Telemt v3.4.11 wraps every JSON response in `{"ok": <bool>, "data":
/// <payload>, "revision": "<sha>"}`. Callers want the inner `data`,
/// not the envelope. Older releases (pre-3.4) returned the payload
/// bare; we tolerate that by passing through anything without an `ok`
/// field. If `ok` is `false` we still return `data` — callers either
/// got a 2xx (in which case ok is true; trust the payload) or already
/// turned a non-2xx into an Err via `expect_2xx`.
fn unwrap_envelope(v: Value) -> Value {
    if let Value::Object(ref obj) = v {
        if obj.contains_key("ok") && obj.contains_key("data") {
            return obj.get("data").cloned().unwrap_or(Value::Null);
        }
    }
    v
}

// ---------------------------------------------------------------------------
// Lower-level HTTP/1.1 helpers
// ---------------------------------------------------------------------------

/// Issue one request and read the entire response. Returns
/// `(status_code, body_bytes)`. Body is the raw bytes after the
/// `\r\n\r\n` separator — JSON-decoding is the caller's problem.
async fn request(
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>)> {
    let fut = async move {
        let addr = format!("{TELEMT_API_HOST}:{TELEMT_API_PORT}");
        let mut stream = TcpStream::connect(&addr)
            .await
            .with_context(|| format!("connect to telemt API at {addr}"))?;

        let mut head = String::new();
        head.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
        head.push_str(&format!("Host: {TELEMT_API_HOST}:{TELEMT_API_PORT}\r\n"));
        head.push_str("User-Agent: awg-easy-rs\r\n");
        head.push_str("Accept: application/json\r\n");
        // `Connection: close` — server flushes + closes after the
        // response; we read until EOF. No keep-alive, no chunked
        // bookkeeping. Keep the client trivial.
        head.push_str("Connection: close\r\n");
        if let Some(b) = body {
            head.push_str("Content-Type: application/json\r\n");
            head.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).await.context("write request head")?;
        if let Some(b) = body {
            stream.write_all(b).await.context("write request body")?;
        }
        stream.flush().await.context("flush request")?;

        // Read everything. Cap at MAX_RESPONSE_BYTES to keep a misbehaving
        // server from OOMing us.
        let mut buf = Vec::with_capacity(8 * 1024);
        let mut tmp = [0u8; 16 * 1024];
        loop {
            let n = stream.read(&mut tmp).await.context("read response")?;
            if n == 0 {
                break;
            }
            if buf.len() + n > MAX_RESPONSE_BYTES {
                return Err(anyhow!(
                    "telemt response exceeded {} bytes — refusing to allocate further",
                    MAX_RESPONSE_BYTES
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        parse_response(&buf)
    };
    timeout(REQUEST_TIMEOUT, fut)
        .await
        .map_err(|_| anyhow!("telemt {method} {path} timed out after {REQUEST_TIMEOUT:?}"))?
}

/// Parse a complete HTTP/1.1 response into `(status, body)`. Handles:
///
/// - Status line: `HTTP/1.x <CODE> <REASON>\r\n`
/// - Header section terminated by `\r\n\r\n`
/// - Body: everything after, byte-exact
///
/// We don't honour `Content-Length` here — `Connection: close` means
/// the server closes after the body, so the EOF we already read in
/// `request()` is the body terminator. Chunked transfer encoding is
/// not handled; if telemt ever starts using it for a hit endpoint we'd
/// see truncated JSON and `parse_json` would fail loudly.
fn parse_response(buf: &[u8]) -> Result<(u16, Vec<u8>)> {
    // Find the end-of-headers sentinel. `\r\n\r\n` is mandatory in a
    // well-formed HTTP/1.1 response.
    let sep = b"\r\n\r\n";
    let split = buf
        .windows(sep.len())
        .position(|w| w == sep)
        .ok_or_else(|| anyhow!("malformed HTTP response: no \\r\\n\\r\\n header terminator"))?;
    let (head, rest) = buf.split_at(split);
    let body = rest[sep.len()..].to_vec();

    let head_str = std::str::from_utf8(head)
        .context("response headers are not valid UTF-8")?;
    let status_line = head_str
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty HTTP response (no status line)"))?;

    // "HTTP/1.1 200 OK" → split on whitespace, take field 1.
    let mut parts = status_line.split_whitespace();
    let _version = parts.next().ok_or_else(|| anyhow!("status line missing version"))?;
    let code_str = parts.next().ok_or_else(|| anyhow!("status line missing code"))?;
    let code: u16 = code_str
        .parse()
        .with_context(|| format!("status code {code_str:?} is not a u16"))?;
    Ok((code, body))
}

fn parse_json(body: &[u8]) -> Result<Value> {
    if body.is_empty() {
        // Some endpoints (DELETE, reset-quota) return 204 No Content
        // with an empty body. Treat that as JSON null so callers can
        // uniformly use Value.
        return Ok(Value::Null);
    }
    serde_json::from_slice(body).with_context(|| {
        // Scrub before the body reaches an error string. A create/rotate
        // response carries the user's 32-hex secret, and this context is
        // logged by the reconciler — so an otherwise harmless decode failure
        // (this client does not parse chunked encoding) wrote a live
        // credential to the journal. `logscrub` masks hex runs of 16+.
        let preview = std::str::from_utf8(body)
            .unwrap_or("<non-utf8>")
            .chars()
            .take(200)
            .collect::<String>();
        format!("decode telemt JSON response: {:?}", redact_hex_runs(&preview))
    })
}

/// Mask runs of 16+ hex characters.
///
/// A telemt create/rotate response carries the user's 32-hex secret, and the
/// decode-failure context above is logged by the reconciler — so a response
/// this client cannot parse (it does not handle chunked encoding, as the
/// module notes) wrote a live credential into the journal. MTProxy secrets are
/// exactly this shape, and nothing else in a telemt response body legitimately
/// is, so the rule is precise rather than a blanket redaction.
fn redact_hex_runs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= 16 {
            out.push_str("<redacted>");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod redaction_tests {
    use super::redact_hex_runs;

    #[test]
    fn masks_a_telemt_secret_but_keeps_the_surrounding_json() {
        let body = r#"{"username":"alice","secret":"0123456789abcdef0123456789abcdef"}"#;
        let out = redact_hex_runs(body);
        assert!(!out.contains("0123456789abcdef"), "secret survived: {out}");
        assert!(out.contains("username"), "structure lost: {out}");
        assert!(out.contains("<redacted>"), "no marker: {out}");
    }

    #[test]
    fn leaves_short_hex_and_ordinary_words_alone() {
        // "alice" and "decade" are hex-ish but far under the run length.
        let out = redact_hex_runs(r#"{"port":443,"name":"decade","id":"abc123"}"#);
        assert!(out.contains("decade") && out.contains("abc123") && out.contains("443"));
        assert!(!out.contains("<redacted>"));
    }
}

fn expect_2xx(status: u16, body: &[u8], context: &str) -> Result<()> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    // Surface telemt's error JSON if there is one — operators want to
    // see "username already exists" not "telemt returned 409".
    let preview = std::str::from_utf8(body)
        .unwrap_or("<non-utf8>")
        .chars()
        .take(400)
        .collect::<String>();
    Err(anyhow!(
        "{context} returned HTTP {status}: {preview}"
    ))
}

/// Percent-encode characters that are unsafe in a URL path segment.
/// Telemt validates usernames at create time but we still need to
/// safely substitute whatever the operator passed; without escaping a
/// value like `..` could traverse paths and `?` would be interpreted
/// as a query string. Stays conservative — encodes everything outside
/// `unreserved` (RFC 3986).
fn url_path_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        let safe = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~');
        if safe {
            out.push(*b as char);
        } else {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_path_encode_handles_separators() {
        assert_eq!(url_path_encode("alice"), "alice");
        assert_eq!(url_path_encode("../etc/passwd"), "..%2Fetc%2Fpasswd");
        assert_eq!(url_path_encode("alice bob"), "alice%20bob");
        assert_eq!(url_path_encode("user?id=1"), "user%3Fid%3D1");
    }

    #[test]
    fn parse_response_extracts_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"ok\":true}\r\n";
        let (code, body) = parse_response(raw).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, b"{\"ok\":true}\r\n".to_vec());
    }

    #[test]
    fn parse_response_handles_404() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let (code, body) = parse_response(raw).unwrap();
        assert_eq!(code, 404);
        assert_eq!(body, Vec::<u8>::new());
    }

    #[test]
    fn parse_response_rejects_no_separator() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n";
        assert!(parse_response(raw).is_err());
    }

    #[test]
    fn parse_json_treats_empty_body_as_null() {
        assert_eq!(parse_json(&[]).unwrap(), Value::Null);
    }

    #[test]
    fn create_user_serializes_minimal() {
        let body = serde_json::to_string(&CreateUser {
            username: "alice",
            secret: "0123456789abcdef0123456789abcdef",
            ad_tag: None,
        })
        .unwrap();
        // ad_tag should be elided by skip_serializing_if.
        assert!(!body.contains("ad_tag"));
        assert!(body.contains("\"username\":\"alice\""));
        assert!(body.contains("\"secret\":\""));
    }

    #[test]
    fn create_user_serializes_with_ad_tag() {
        let body = serde_json::to_string(&CreateUser {
            username: "bob",
            secret: "0123456789abcdef0123456789abcdef",
            ad_tag: Some("aaaabbbbccccddddeeeeffff00001111"),
        })
        .unwrap();
        // `user_ad_tag`, not `ad_tag` — telemt drops the latter silently.
        assert!(body.contains("\"user_ad_tag\":\"aaaabbbbccccddddeeeeffff00001111\""));
    }

    #[test]
    fn patch_user_default_serializes_to_empty_object() {
        let body = serde_json::to_string(&PatchUser::default()).unwrap();
        assert_eq!(body, "{}", "every field is None — JSON should be empty");
    }

    #[test]
    fn unwrap_envelope_strips_ok_data_revision() {
        // The shape v3.4.11 actually returns. Confirmed via curl against
        // the live binary in /tmp/telemt-smoke.
        let v = serde_json::json!({
            "ok": true,
            "data": { "username": "alice" },
            "revision": "deadbeef",
        });
        let inner = unwrap_envelope(v);
        assert_eq!(
            inner,
            serde_json::json!({ "username": "alice" }),
            "envelope should be peeled away"
        );
    }

    #[test]
    fn unwrap_envelope_passes_through_when_no_envelope() {
        // Bare arrays / objects without an `ok` key go through unchanged
        // — protects us if a future telemt drops the envelope.
        let v = serde_json::json!([{"username": "alice"}]);
        assert_eq!(unwrap_envelope(v.clone()), v);
        let v2 = serde_json::json!({"username": "bob"});
        assert_eq!(unwrap_envelope(v2.clone()), v2);
    }

    // Telemt calls the per-user ad-tag override `user_ad_tag` on the wire,
    // in both directions, and silently ignores request keys it doesn't
    // know — so a body keyed `ad_tag` is answered 2xx with the tag
    // unset. These pin the name that was measured against telemt 3.4.24
    // and 3.5.5; a rename regression would otherwise be invisible (the
    // reconciler would just re-PATCH forever).
    #[test]
    fn create_user_serializes_ad_tag_as_user_ad_tag() {
        let req = CreateUser {
            username: "alice",
            secret: "0123456789abcdef0123456789abcdef",
            ad_tag: Some("ffffffffffffffffffffffffffffffff"),
        };
        let v: Value = serde_json::to_value(&req).unwrap();
        assert_eq!(
            v.get("user_ad_tag").and_then(|t| t.as_str()),
            Some("ffffffffffffffffffffffffffffffff")
        );
        assert!(v.get("ad_tag").is_none(), "telemt would drop `ad_tag`");

        // Omitted tag stays omitted (telemt treats absent as "unchanged").
        let bare = CreateUser {
            username: "bob",
            secret: "0123456789abcdef0123456789abcdef",
            ad_tag: None,
        };
        let v: Value = serde_json::to_value(&bare).unwrap();
        assert!(v.get("user_ad_tag").is_none());
    }

    #[test]
    fn patch_user_serializes_ad_tag_as_user_ad_tag() {
        let patch = PatchUser {
            secret: None,
            ad_tag: Some(""),
            enabled: Some(false),
        };
        let v: Value = serde_json::to_value(&patch).unwrap();
        assert_eq!(v.get("user_ad_tag").and_then(|t| t.as_str()), Some(""));
        assert!(v.get("ad_tag").is_none());
        assert_eq!(v.get("enabled").and_then(|e| e.as_bool()), Some(false));
        assert!(v.get("secret").is_none());
    }

    #[test]
    fn user_payload_reads_user_ad_tag() {
        // Shape taken verbatim from a live telemt 3.5.5 GET /v1/users row.
        let raw = serde_json::json!({
            "username": "alice",
            "enabled": true,
            "user_ad_tag": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "total_octets": 0,
            "links": {"classic": [], "secure": [], "tls": []},
        });
        let u: UserPayload = serde_json::from_value(raw).unwrap();
        assert_eq!(u.username, "alice");
        assert_eq!(u.ad_tag.as_deref(), Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(u.secret.is_none());
        assert!(u.links.is_some());
    }

    #[test]
    fn unwrap_envelope_unwraps_array_data() {
        let v = serde_json::json!({
            "ok": true,
            "data": [{"username": "a"}, {"username": "b"}],
            "revision": "x",
        });
        let inner = unwrap_envelope(v);
        assert!(inner.is_array());
        assert_eq!(inner.as_array().unwrap().len(), 2);
    }
}
