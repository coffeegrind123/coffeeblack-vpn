//! A deliberately small HTTP/1.1 server.
//!
//! This replaces hyper. The admin panel's needs are narrow — plaintext HTTP/1.1
//! behind a reverse proxy, request bodies of a few kilobytes, responses fully
//! buffered in memory — and hyper's generality (HTTP/2, streaming bodies,
//! upgrades, a client, connection pooling) came with `tower`, `futures-util`
//! and two dozen other crates.
//!
//! Because a hand-written parser on an internet-facing admin port is exactly
//! where request smuggling lives, the parsing is strict rather than lenient.
//! Specifically:
//!
//! * The request line must be `METHOD SP request-target SP HTTP/1.x CRLF`,
//!   with a target that starts with `/`. No absolute-form, no CONNECT.
//! * Header folding (obs-fold) is rejected outright — it is the classic
//!   smuggling primitive and has been deprecated since RFC 7230.
//! * A request carrying **both** `Content-Length` and `Transfer-Encoding` is
//!   rejected, as is one with two `Content-Length` headers that disagree, or
//!   any `Transfer-Encoding` other than `chunked`. These are the disagreements
//!   a front end and a back end can resolve differently.
//! * Every limit is explicit: request line, header count, header size, body
//!   size, and the number of requests served on one connection.
//! * Timeouts bound the header read, the body read, and idle keep-alive, so a
//!   slowloris client cannot hold a connection open indefinitely.
//!
//! What is deliberately absent: HTTP/2 (the reverse proxy terminates it),
//! streaming request bodies, chunked *responses* (every response body is
//! already in memory, so `Content-Length` is always known), and pipelining
//! (requests are answered one at a time per connection).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ::http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use super::body::Body;
use super::extract::ConnectInfo;
use super::router::Router;

/// Longest request line accepted (method, target and version).
const MAX_REQUEST_LINE: usize = 8 * 1024;
/// Largest header block accepted.
const MAX_HEADER_BYTES: usize = 32 * 1024;
/// Most headers accepted in one request.
const MAX_HEADERS: usize = 100;
/// Largest request body accepted. The biggest legitimate payload is an admin
/// form of a few kilobytes.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// How long a client may take to send its request line and headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a client may take to send the body it announced.
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// How long an idle keep-alive connection is held open.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Requests served on a single connection before it is closed.
const MAX_REQUESTS_PER_CONNECTION: usize = 512;

/// Why a request could not be parsed. Each maps to the status the client gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseError {
    /// The connection closed cleanly before a request arrived.
    Closed,
    /// Syntax the parser refuses.
    BadRequest(&'static str),
    /// The request line or header block is too large.
    HeadersTooLarge,
    /// The body exceeds [`MAX_BODY_BYTES`].
    BodyTooLarge,
    /// The client stopped sending mid-request.
    Timeout,
}

impl ParseError {
    fn status(self) -> StatusCode {
        match self {
            ParseError::Closed => StatusCode::BAD_REQUEST,
            ParseError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ParseError::HeadersTooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            ParseError::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ParseError::Timeout => StatusCode::REQUEST_TIMEOUT,
        }
    }
}

/// Buffered reader over a connection, with the limits applied.
struct ConnReader<R> {
    inner: R,
    buf: Vec<u8>,
    /// How much of `buf` has been consumed.
    pos: usize,
}

impl<R: AsyncRead + Unpin> ConnReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(8 * 1024),
            pos: 0,
        }
    }

    /// Drop consumed bytes so the buffer does not grow without bound.
    fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    /// Whether any unconsumed bytes remain in the buffer.
    fn has_buffered(&self) -> bool {
        self.pos < self.buf.len()
    }

    /// Read more bytes from the socket. `Ok(false)` means EOF.
    async fn fill(&mut self) -> io::Result<bool> {
        let mut chunk = [0u8; 8 * 1024];
        let n = self.inner.read(&mut chunk).await?;
        if n == 0 {
            return Ok(false);
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(true)
    }

    /// Read up to and including the next CRLF, returning the line without it.
    ///
    /// A bare LF is accepted as a line ending (every real client sends CRLF,
    /// but tolerating LF costs nothing and no smuggling follows from it as
    /// long as the *framing* headers are validated, which they are).
    async fn read_line(&mut self, limit: usize) -> Result<Vec<u8>, ParseError> {
        loop {
            if let Some(idx) = self.buf[self.pos..].iter().position(|&b| b == b'\n') {
                let end = self.pos + idx;
                let mut line = self.buf[self.pos..end].to_vec();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                self.pos = end + 1;
                return Ok(line);
            }
            if self.buf.len() - self.pos > limit {
                return Err(ParseError::HeadersTooLarge);
            }
            match self.fill().await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(if self.has_buffered() {
                        ParseError::BadRequest("connection closed mid-request")
                    } else {
                        ParseError::Closed
                    })
                }
                Err(_) => return Err(ParseError::Closed),
            }
        }
    }

    /// Read exactly `n` bytes of body.
    async fn read_exact(&mut self, n: usize) -> Result<Vec<u8>, ParseError> {
        while self.buf.len() - self.pos < n {
            match self.fill().await {
                Ok(true) => {}
                Ok(false) => return Err(ParseError::BadRequest("body shorter than Content-Length")),
                Err(_) => return Err(ParseError::Closed),
            }
        }
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }
}

/// Parse the request line and headers.
async fn read_head<R: AsyncRead + Unpin>(
    reader: &mut ConnReader<R>,
) -> Result<Request<()>, ParseError> {
    let line = reader.read_line(MAX_REQUEST_LINE).await?;
    if line.is_empty() {
        // A stray CRLF before a request is tolerated by RFC 9112 §2.2.
        return Err(ParseError::BadRequest("empty request line"));
    }
    if line.len() > MAX_REQUEST_LINE {
        return Err(ParseError::HeadersTooLarge);
    }

    let text = std::str::from_utf8(&line)
        .map_err(|_| ParseError::BadRequest("request line is not valid UTF-8"))?;
    let mut fields = text.split(' ');
    let (Some(method), Some(target), Some(version), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(ParseError::BadRequest("malformed request line"));
    };

    let method =
        Method::from_bytes(method.as_bytes()).map_err(|_| ParseError::BadRequest("bad method"))?;
    if method == Method::CONNECT {
        return Err(ParseError::BadRequest("CONNECT is not supported"));
    }
    // Origin-form only: the panel is not a forward proxy, so an absolute-form
    // target (`http://host/path`) or an authority-form one has no meaning here
    // and is a routing-confusion risk.
    if !target.starts_with('/') {
        return Err(ParseError::BadRequest("request target must be origin-form"));
    }
    let uri: Uri = target
        .parse()
        .map_err(|_| ParseError::BadRequest("malformed request target"))?;
    let version = match version {
        "HTTP/1.1" => Version::HTTP_11,
        "HTTP/1.0" => Version::HTTP_10,
        _ => return Err(ParseError::BadRequest("unsupported HTTP version")),
    };

    let mut builder = Request::builder().method(method).uri(uri).version(version);
    let mut header_bytes = 0usize;
    let mut header_count = 0usize;
    loop {
        let line = reader.read_line(MAX_HEADER_BYTES).await?;
        if line.is_empty() {
            break;
        }
        header_bytes += line.len();
        header_count += 1;
        if header_bytes > MAX_HEADER_BYTES || header_count > MAX_HEADERS {
            return Err(ParseError::HeadersTooLarge);
        }
        // obs-fold: a header line starting with whitespace continues the
        // previous one. Deprecated, and the classic smuggling primitive.
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(ParseError::BadRequest("obsolete line folding"));
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(ParseError::BadRequest("header without a colon"));
        };
        let name = &line[..colon];
        // No whitespace is allowed between the field name and the colon
        // (RFC 9112 §5.1) — a front end that ignores this and a back end that
        // does not is another smuggling pair.
        if name.last().is_some_and(|b| b.is_ascii_whitespace()) {
            return Err(ParseError::BadRequest("whitespace before header colon"));
        }
        let value = &line[colon + 1..];
        let value = trim_ascii(value);
        let name = HeaderName::from_bytes(name)
            .map_err(|_| ParseError::BadRequest("invalid header name"))?;
        let value =
            HeaderValue::from_bytes(value).map_err(|_| ParseError::BadRequest("invalid header value"))?;
        builder = builder.header(name, value);
    }

    builder
        .body(())
        .map_err(|_| ParseError::BadRequest("malformed request"))
}

fn trim_ascii(mut v: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = v {
        if first.is_ascii_whitespace() {
            v = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = v {
        if last.is_ascii_whitespace() {
            v = rest;
        } else {
            break;
        }
    }
    v
}

/// How the body of a request is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// No body.
    None,
    /// Exactly this many bytes.
    Length(usize),
    /// Chunked transfer coding.
    Chunked,
}

/// Decide the body framing, rejecting every ambiguous combination.
fn framing(headers: &::http::HeaderMap) -> Result<Framing, ParseError> {
    let has_te = headers.contains_key(::http::header::TRANSFER_ENCODING);
    let content_lengths: Vec<&HeaderValue> = headers
        .get_all(::http::header::CONTENT_LENGTH)
        .iter()
        .collect();

    if has_te {
        if !content_lengths.is_empty() {
            // RFC 9112 §6.1 allows dropping Content-Length here; refusing is
            // strictly safer, since the disagreement is the whole attack.
            return Err(ParseError::BadRequest(
                "both Content-Length and Transfer-Encoding",
            ));
        }
        let mut codings = headers.get_all(::http::header::TRANSFER_ENCODING).iter();
        let (Some(value), None) = (codings.next(), codings.next()) else {
            return Err(ParseError::BadRequest("multiple Transfer-Encoding headers"));
        };
        let value = value
            .to_str()
            .map_err(|_| ParseError::BadRequest("invalid Transfer-Encoding"))?
            .trim()
            .to_ascii_lowercase();
        if value != "chunked" {
            return Err(ParseError::BadRequest("unsupported Transfer-Encoding"));
        }
        return Ok(Framing::Chunked);
    }

    match content_lengths.len() {
        0 => Ok(Framing::None),
        1 => {
            let text = content_lengths[0]
                .to_str()
                .map_err(|_| ParseError::BadRequest("invalid Content-Length"))?
                .trim();
            // A single header may still carry a comma-separated list; every
            // value must agree.
            let mut parsed: Option<usize> = None;
            for part in text.split(',') {
                let part = part.trim();
                if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ParseError::BadRequest("invalid Content-Length"));
                }
                let value: usize = part
                    .parse()
                    .map_err(|_| ParseError::BadRequest("invalid Content-Length"))?;
                match parsed {
                    Some(seen) if seen != value => {
                        return Err(ParseError::BadRequest("conflicting Content-Length values"))
                    }
                    _ => parsed = Some(value),
                }
            }
            let length = parsed.ok_or(ParseError::BadRequest("invalid Content-Length"))?;
            if length > MAX_BODY_BYTES {
                return Err(ParseError::BodyTooLarge);
            }
            Ok(Framing::Length(length))
        }
        _ => {
            // Several Content-Length headers: only legal if they all agree,
            // and refusing is safer than picking one.
            Err(ParseError::BadRequest("multiple Content-Length headers"))
        }
    }
}

/// Read a chunked body.
async fn read_chunked<R: AsyncRead + Unpin>(
    reader: &mut ConnReader<R>,
) -> Result<Vec<u8>, ParseError> {
    let mut body = Vec::new();
    loop {
        let line = reader.read_line(1024).await?;
        let text = std::str::from_utf8(&line)
            .map_err(|_| ParseError::BadRequest("invalid chunk size"))?;
        // A chunk size may carry extensions after a `;`.
        let size_text = text.split(';').next().unwrap_or("").trim();
        if size_text.is_empty() || !size_text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ParseError::BadRequest("invalid chunk size"));
        }
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| ParseError::BadRequest("invalid chunk size"))?;
        if size == 0 {
            // Trailers, then the terminating empty line.
            loop {
                let trailer = reader.read_line(MAX_HEADER_BYTES).await?;
                if trailer.is_empty() {
                    break;
                }
            }
            return Ok(body);
        }
        if body.len() + size > MAX_BODY_BYTES {
            return Err(ParseError::BodyTooLarge);
        }
        let chunk = reader.read_exact(size).await?;
        body.extend_from_slice(&chunk);
        // Each chunk is followed by CRLF.
        let sep = reader.read_line(8).await?;
        if !sep.is_empty() {
            return Err(ParseError::BadRequest("malformed chunk terminator"));
        }
    }
}

/// Serialise a response onto the wire.
async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: Response<Body>,
    include_body: bool,
    keep_alive: bool,
) -> io::Result<()> {
    let (parts, body) = response.into_parts();
    let mut head = Vec::with_capacity(256);
    head.extend_from_slice(b"HTTP/1.1 ");
    head.extend_from_slice(parts.status.as_str().as_bytes());
    head.push(b' ');
    head.extend_from_slice(parts.status.canonical_reason().unwrap_or("").as_bytes());
    head.extend_from_slice(b"\r\n");

    for (name, value) in parts.headers.iter() {
        // The framing headers are emitted below from the actual body and
        // connection state, so a handler cannot desynchronise the response
        // from what is really on the wire.
        if name == ::http::header::CONTENT_LENGTH
            || name == ::http::header::CONNECTION
            || name == ::http::header::TRANSFER_ENCODING
        {
            continue;
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }

    // Every body is buffered, so the length is always known and responses are
    // never chunked. 204 and 304 are defined to carry no body, and a
    // Content-Length on them confuses caches, so it is omitted there.
    let bodyless_status =
        parts.status == StatusCode::NO_CONTENT || parts.status == StatusCode::NOT_MODIFIED;
    if !bodyless_status {
        head.extend_from_slice(b"content-length: ");
        head.extend_from_slice(body.len().to_string().as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(if keep_alive {
        b"connection: keep-alive\r\n"
    } else {
        b"connection: close\r\n"
    });
    head.extend_from_slice(b"\r\n");

    writer.write_all(&head).await?;
    if include_body && !bodyless_status && !body.is_empty() {
        writer.write_all(body.as_bytes()).await?;
    }
    writer.flush().await
}

/// Build a bare error response.
fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let mut res = Response::new(Body::from(format!(
        "{{\"error\":\"{}\"}}",
        message.replace('"', "'")
    )));
    *res.status_mut() = status;
    res.headers_mut().insert(
        ::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    res
}

/// Whether the connection should stay open after this request.
fn wants_keep_alive(req: &Request<()>) -> bool {
    let connection = req
        .headers()
        .get(::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if connection.split(',').any(|t| t.trim() == "close") {
        return false;
    }
    match req.version() {
        Version::HTTP_10 => connection.split(',').any(|t| t.trim() == "keep-alive"),
        _ => true,
    }
}

/// Serve one connection until it closes.
async fn serve_connection<S>(stream: S, peer: SocketAddr, router: Arc<Router<()>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = ConnReader::new(read_half);

    for request_number in 1..=MAX_REQUESTS_PER_CONNECTION {
        reader.compact();
        // A connection waiting for its first byte gets the idle timeout; one
        // that has started sending gets the (shorter) header timeout.
        let timeout = if reader.has_buffered() {
            HEADER_TIMEOUT
        } else {
            IDLE_TIMEOUT
        };
        let head = match tokio::time::timeout(timeout, read_head(&mut reader)).await {
            Ok(Ok(head)) => head,
            Ok(Err(ParseError::Closed)) => return,
            Ok(Err(e)) => {
                let message = match e {
                    ParseError::BadRequest(m) => m,
                    ParseError::HeadersTooLarge => "request headers too large",
                    ParseError::BodyTooLarge => "request body too large",
                    ParseError::Timeout => "request timed out",
                    ParseError::Closed => unreachable!("handled above"),
                };
                let _ = write_response(
                    &mut write_half,
                    error_response(e.status(), message),
                    true,
                    false,
                )
                .await;
                return;
            }
            Err(_) => return, // timed out waiting for a request
        };

        // The connection is closed after the last request it may serve, and
        // that response has to say so or the client will try to reuse it.
        let keep_alive =
            wants_keep_alive(&head) && request_number < MAX_REQUESTS_PER_CONNECTION;
        let is_head_request = head.method() == Method::HEAD;

        let framing = match framing(head.headers()) {
            Ok(f) => f,
            Err(e) => {
                let message = match e {
                    ParseError::BadRequest(m) => m,
                    ParseError::BodyTooLarge => "request body too large",
                    _ => "bad request",
                };
                let _ = write_response(
                    &mut write_half,
                    error_response(e.status(), message),
                    true,
                    false,
                )
                .await;
                return;
            }
        };

        // Honour `Expect: 100-continue` before reading the body, or a client
        // that waits for it stalls until its own timeout.
        let expects_continue = head
            .headers()
            .get(::http::header::EXPECT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));
        if expects_continue
            && write_half
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .is_err()
        {
            return;
        }

        let body = match tokio::time::timeout(BODY_TIMEOUT, async {
            match framing {
                Framing::None => Ok(Vec::new()),
                Framing::Length(0) => Ok(Vec::new()),
                Framing::Length(n) => reader.read_exact(n).await,
                Framing::Chunked => read_chunked(&mut reader).await,
            }
        })
        .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(e)) => {
                let _ = write_response(
                    &mut write_half,
                    error_response(e.status(), "malformed request body"),
                    true,
                    false,
                )
                .await;
                return;
            }
            Err(_) => {
                let _ = write_response(
                    &mut write_half,
                    error_response(ParseError::Timeout.status(), "request body timed out"),
                    true,
                    false,
                )
                .await;
                return;
            }
        };

        let (mut parts, ()) = head.into_parts();
        parts.extensions.insert(ConnectInfo(peer));
        let request = Request::from_parts(parts, Body::from(body));

        let response = router.dispatch(request).await;
        if write_response(&mut write_half, response, !is_head_request, keep_alive)
            .await
            .is_err()
        {
            return;
        }
        if !keep_alive {
            return;
        }
    }
}

/// Accept connections on `listener` until `shutdown` resolves.
///
/// In-flight requests are allowed to finish: the accept loop stops first, and
/// the connection tasks are given a grace period to drain.
pub async fn serve<F>(listener: TcpListener, router: Router<()>, shutdown: F) -> io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let router = Arc::new(router);
    let tracker = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        // A per-connection accept error (fd exhaustion, a peer
                        // that vanished) must not kill the server.
                        crate::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&tracker).try_acquire_owned() else {
                    crate::warn!(%peer, "connection limit reached; dropping");
                    continue;
                };
                if let Err(e) = stream.set_nodelay(true) {
                    crate::debug!(error = %e, "failed to set TCP_NODELAY");
                }
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    serve_connection(stream, peer, router).await;
                    drop(permit);
                });
            }
        }
    }

    // Graceful drain: wait for in-flight connections, but not forever.
    let deadline = tokio::time::Instant::now() + GRACEFUL_SHUTDOWN_TIMEOUT;
    while tracker.available_permits() < MAX_CONNECTIONS {
        if tokio::time::Instant::now() >= deadline {
            crate::warn!("graceful shutdown timed out with connections still open");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

/// Most connections served at once.
const MAX_CONNECTIONS: usize = 1024;
/// How long in-flight connections are given to finish after shutdown starts.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
