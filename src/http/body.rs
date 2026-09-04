//! Request and response bodies.
//!
//! Every body this server handles is small and fully buffered — JSON API
//! payloads in, JSON/SVG/ZIP/config text out — so a body is just [`Bytes`]
//! rather than a stream. That removes the whole `http-body` / `futures`
//! plumbing axum and hyper needed to be generic over streaming bodies.

use bytes::Bytes;

/// A complete, in-memory HTTP body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Body(Bytes);

impl Body {
    /// An empty body.
    pub fn empty() -> Self {
        Self(Bytes::new())
    }

    /// The body's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the body, yielding its bytes.
    pub fn into_bytes(self) -> Bytes {
        self.0
    }

    /// Number of bytes in the body.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the body carries no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Bytes> for Body {
    fn from(b: Bytes) -> Self {
        Self(b)
    }
}

impl From<Vec<u8>> for Body {
    fn from(b: Vec<u8>) -> Self {
        Self(Bytes::from(b))
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Self(Bytes::from(s))
    }
}

impl From<&'static str> for Body {
    fn from(s: &'static str) -> Self {
        Self(Bytes::from_static(s.as_bytes()))
    }
}

impl From<&'static [u8]> for Body {
    fn from(b: &'static [u8]) -> Self {
        Self(Bytes::from_static(b))
    }
}

/// Read a body into bytes, refusing anything larger than `limit`.
///
/// Mirrors `axum::body::to_bytes`. Bodies are already buffered, so the limit
/// is a check rather than a streaming cutoff; it is still enforced so a caller
/// that passes a small limit gets an error rather than an oversized buffer.
pub fn to_bytes(body: Body, limit: usize) -> Result<Bytes, LengthLimitError> {
    if body.len() > limit {
        return Err(LengthLimitError { limit, actual: body.len() });
    }
    Ok(body.into_bytes())
}

/// Returned by [`to_bytes`] when a body exceeds the caller's limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LengthLimitError {
    /// The limit that was exceeded.
    pub limit: usize,
    /// The body's actual length.
    pub actual: usize,
}

impl std::fmt::Display for LengthLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "body of {} bytes exceeds the {}-byte limit",
            self.actual, self.limit
        )
    }
}

impl std::error::Error for LengthLimitError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_preserve_the_bytes() {
        assert!(Body::empty().is_empty());
        assert_eq!(Body::from("hello").as_bytes(), b"hello");
        assert_eq!(Body::from(String::from("hi")).as_bytes(), b"hi");
        assert_eq!(Body::from(vec![1u8, 2, 3]).as_bytes(), &[1, 2, 3]);
        assert_eq!(Body::from(&b"raw"[..]).len(), 3);
    }

    #[test]
    fn to_bytes_enforces_the_limit() {
        let body = Body::from("0123456789");
        assert_eq!(to_bytes(body.clone(), 10).unwrap().len(), 10);
        let err = to_bytes(body, 9).unwrap_err();
        assert_eq!(err.actual, 10);
        assert!(err.to_string().contains("exceeds"));
    }
}
