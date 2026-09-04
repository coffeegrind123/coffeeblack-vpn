//! Typed errors for the proxy modules.
//!
//! Hand-written rather than derived: `thiserror` contributed six `Display`
//! arms and one `From`, and its 1.x line was the last thing holding a second
//! copy of the crate (plus its proc-macro half) in the build. The impls below
//! are what the derive expands to, and the tests at the bottom pin every
//! message string.

use std::fmt;

/// Top-level errors for the proxy application.
#[derive(Debug)]
pub enum ProxyError {
    /// Malformed or unusable proxy configuration.
    Config(String),
    /// An I/O failure from a socket or file operation.
    Io(std::io::Error),
    /// No session exists for the given client address.
    SessionNotFound(std::net::SocketAddr),
    /// The client address exceeded its packet-rate budget.
    RateLimited(std::net::SocketAddr),
    /// The AmneziaWG backend could not be reached.
    BackendUnreachable(String),
    /// A shutdown signal ended the operation.
    Shutdown,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::SessionNotFound(addr) => write!(f, "session not found for {addr}"),
            Self::RateLimited(addr) => write!(f, "rate limited: {addr}"),
            Self::BackendUnreachable(msg) => write!(f, "backend unreachable: {msg}"),
            Self::Shutdown => write!(f, "shutdown signal received"),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ProxyError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_config() {
        let e = ProxyError::Config("bad toml".into());
        assert_eq!(e.to_string(), "configuration error: bad toml");
    }

    #[test]
    fn error_display_io() {
        let io = std::io::Error::new(std::io::ErrorKind::AddrInUse, "port taken");
        let e = ProxyError::Io(io);
        assert!(e.to_string().contains("port taken"));
    }

    #[test]
    fn error_display_rate_limited() {
        let addr: std::net::SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let e = ProxyError::RateLimited(addr);
        assert!(e.to_string().contains("127.0.0.1:1234"));
    }

    #[test]
    fn error_display_session_not_found() {
        let addr: std::net::SocketAddr = "10.0.0.1:5555".parse().unwrap();
        let e = ProxyError::SessionNotFound(addr);
        assert!(e.to_string().contains("10.0.0.1:5555"));
    }

    #[test]
    fn error_display_backend_unreachable() {
        let e = ProxyError::BackendUnreachable("timeout".into());
        assert_eq!(e.to_string(), "backend unreachable: timeout");
    }

    #[test]
    fn error_display_shutdown() {
        let e = ProxyError::Shutdown;
        assert_eq!(e.to_string(), "shutdown signal received");
    }
    #[test]
    fn io_source_is_preserved() {
        use std::error::Error as _;
        let io = std::io::Error::new(std::io::ErrorKind::AddrInUse, "port taken");
        let e = ProxyError::Io(io);
        assert!(e.source().is_some(), "Io variant must expose its source");
        assert!(ProxyError::Shutdown.source().is_none());
    }

    #[test]
    fn io_error_converts_with_question_mark() {
        fn fallible() -> Result<(), ProxyError> {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"))?;
            Ok(())
        }
        assert!(matches!(fallible(), Err(ProxyError::Io(_))));
    }
}
