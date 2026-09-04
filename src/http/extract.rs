//! Extractors: how a handler's arguments are produced from a request.
//!
//! Two traits, both synchronous because bodies are already buffered by the
//! time a handler runs:
//!
//! * [`FromRequestParts`] — anything derived from the method, URI, headers or
//!   the router's captured path parameters. Any number of these may appear in
//!   a handler's argument list.
//! * [`FromRequest`] — consumes the body, so at most one may appear, and it
//!   must be last. [`Json`] is the only such extractor here.
//!
//! A rejection is just a [`Response`], which is what lets the handler
//! machinery return it directly.

// The "error" type throughout this module is a complete HTTP response — that
// is the whole point of a rejection: it *is* what gets sent. Boxing it to
// shrink the `Result` would add an allocation on the rejection path and a
// deref at every construction site, for a type that is already only moved
// once, so the lint is answered here rather than obeyed.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Deref;

use ::http::request::Parts;
use ::http::StatusCode;
use serde::de::DeserializeOwned;

use super::body::Body;
use super::cookie::CookieJar;
use super::response::{IntoResponse, Json, Response};

/// Path parameters captured by the router, attached to the request so
/// extractors can read them.
#[derive(Debug, Clone, Default)]
pub(super) struct PathParams(pub HashMap<String, String>);

/// The peer address of the connection, attached by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectInfo<T>(pub T);

/// Extract from the request's metadata.
pub trait FromRequestParts<S>: Sized {
    /// Produce the value, or a response to send instead.
    fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response>;
}

/// Extract from the whole request, consuming the body.
pub trait FromRequest<S>: Sized {
    /// Produce the value, or a response to send instead.
    fn from_request(req: ::http::Request<Body>, state: &S) -> Result<Self, Response>;
}

/// Every parts-extractor is also a whole-request extractor, so it may appear
/// in the last argument position too.
///
/// This is spelled out per type rather than as a blanket
/// `impl<T: FromRequestParts<S>> FromRequest<S> for T`, which would overlap
/// with the body extractors below. (axum resolves the same conflict with a
/// pair of private marker types threaded through its `Handler` trait; naming
/// the eight types is simpler and just as complete here.)
macro_rules! from_request_via_parts {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<S> FromRequest<S> for $ty {
                fn from_request(req: ::http::Request<Body>, state: &S) -> Result<Self, Response> {
                    let (mut parts, _body) = req.into_parts();
                    <$ty as FromRequestParts<S>>::from_request_parts(&mut parts, state)
                }
            }
        )*
    };
}

from_request_via_parts!(
    ::http::HeaderMap,
    ::http::Method,
    ::http::Uri,
    CookieJar,
    ConnectInfo<SocketAddr>,
);

impl<S: Clone> FromRequest<S> for State<S> {
    fn from_request(req: ::http::Request<Body>, state: &S) -> Result<Self, Response> {
        let (mut parts, _body) = req.into_parts();
        Self::from_request_parts(&mut parts, state)
    }
}

impl<S, T: std::str::FromStr> FromRequest<S> for Path<T> {
    fn from_request(req: ::http::Request<Body>, state: &S) -> Result<Self, Response> {
        let (mut parts, _body) = req.into_parts();
        Self::from_request_parts(&mut parts, state)
    }
}

impl<S, T: DeserializeOwned> FromRequest<S> for Query<T> {
    fn from_request(req: ::http::Request<Body>, state: &S) -> Result<Self, Response> {
        let (mut parts, _body) = req.into_parts();
        Self::from_request_parts(&mut parts, state)
    }
}

/// Shared application state, cloned into the handler.
#[derive(Debug, Clone, Copy, Default)]
pub struct State<S>(pub S);

impl<S: Clone> FromRequestParts<S> for State<S> {
    fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Response> {
        Ok(State(state.clone()))
    }
}

impl<S> FromRequestParts<S> for ::http::HeaderMap {
    fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Response> {
        Ok(parts.headers.clone())
    }
}

impl<S> FromRequestParts<S> for ::http::Method {
    fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Response> {
        Ok(parts.method.clone())
    }
}

impl<S> FromRequestParts<S> for ::http::Uri {
    fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Response> {
        Ok(parts.uri.clone())
    }
}

impl<S> FromRequestParts<S> for CookieJar {
    fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Response> {
        Ok(CookieJar::from_headers(&parts.headers))
    }
}

impl<S> FromRequestParts<S> for ConnectInfo<SocketAddr> {
    fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Response> {
        parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .copied()
            .ok_or_else(|| {
                // Only reachable if a request is dispatched without the server
                // attaching peer information — in tests, for instance.
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "peer address unavailable"})),
                )
                    .into_response()
            })
    }
}

/// An optional extractor: `None` when the inner one would have rejected.
///
/// Used where an extractor must never fail the request — an absent JSON body
/// for an endpoint whose fields are all optional, or the peer address, which
/// the server always attaches but a `oneshot` unit test does not.
impl<S, T> FromRequest<S> for Option<T>
where
    T: FromRequest<S>,
{
    fn from_request(req: ::http::Request<Body>, state: &S) -> Result<Self, Response> {
        Ok(T::from_request(req, state).ok())
    }
}

impl<S, T> FromRequestParts<S> for Option<T>
where
    T: FromRequestParts<S>,
{
    fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        Ok(T::from_request_parts(parts, state).ok())
    }
}

/// A path parameter captured from the route pattern, parsed into `T`.
///
/// Single-parameter routes only — every route in this project captures exactly
/// one value (`/api/client/:id`, `/cnf/:oneTimeLink`). A route with two
/// captures is rejected at request time with a clear error rather than
/// silently parsing whichever the map iterated first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Path<T>(pub T);

impl<S, T> FromRequestParts<S> for Path<T>
where
    T: std::str::FromStr,
{
    fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Response> {
        let params = parts
            .extensions
            .get::<PathParams>()
            .cloned()
            .unwrap_or_default();
        let mut values = params.0.values();
        let raw = match (values.next(), values.next()) {
            (Some(raw), None) => raw.clone(),
            (None, _) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "missing path parameter"})),
                )
                    .into_response())
            }
            (Some(_), Some(_)) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "route captures more than one path parameter"
                    })),
                )
                    .into_response())
            }
        };
        raw.parse::<T>().map(Path).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid path parameter"})),
            )
                .into_response()
        })
    }
}

/// The request's query string, deserialised into `T`.
///
/// An absent query string deserialises the empty string, so a struct of
/// `Option` and `#[serde(default)]` fields comes back with its defaults.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Query<T>(pub T);

impl<S, T> FromRequestParts<S> for Query<T>
where
    T: DeserializeOwned,
{
    fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Response> {
        let query = parts.uri.query().unwrap_or("");
        super::query::from_str(query).map(Query).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("invalid query string: {e}")})),
            )
                .into_response()
        })
    }
}

impl<T> Deref for Query<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// Whether a `Content-Type` names JSON: `application/json`, or any
/// `…/…+json` structured suffix, with parameters ignored.
fn is_json_content_type(headers: &::http::HeaderMap) -> bool {
    let Some(value) = headers
        .get(::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let essence = value.split(';').next().unwrap_or("").trim();
    essence.eq_ignore_ascii_case("application/json")
        || essence
            .rsplit_once('+')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
}

/// A JSON request body, deserialised into `T`.
///
/// The `Content-Type` must name JSON, as it did under axum. That is not
/// pedantry: a cross-origin HTML form can only send `text/plain`,
/// `application/x-www-form-urlencoded` or `multipart/form-data`, so requiring
/// the JSON type keeps a form post from reaching a JSON endpoint at all —
/// defence in depth behind the `SameSite=Strict` session cookie.
///
/// A request with no JSON content type (a bodyless `POST /client/:id/enable`,
/// say) is rejected here, and the handlers that expect one take
/// `Option<Json<T>>` so the rejection becomes `None` instead of an error.
impl<S, T> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
{
    fn from_request(req: ::http::Request<Body>, _state: &S) -> Result<Self, Response> {
        if !is_json_content_type(req.headers()) {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(serde_json::json!({
                    "error": "expected a request with `Content-Type: application/json`"
                })),
            )
                .into_response());
        }
        let body = req.into_body();
        let bytes = body.as_bytes();
        let value: T = if bytes.is_empty() {
            serde_json::from_str("null")
        } else {
            serde_json::from_slice(bytes)
        }
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("invalid JSON body: {e}")})),
            )
                .into_response()
        })?;
        Ok(Json(value))
    }
}

/// The raw body, for handlers that want the bytes.
impl<S> FromRequest<S> for Body {
    fn from_request(req: ::http::Request<Body>, _state: &S) -> Result<Self, Response> {
        Ok(req.into_body())
    }
}

/// The whole request.
impl<S> FromRequest<S> for ::http::Request<Body> {
    fn from_request(req: ::http::Request<Body>, _state: &S) -> Result<Self, Response> {
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn parts(uri: &str) -> Parts {
        ::http::Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Days {
        days: Option<i64>,
    }

    #[test]
    fn query_extractor_reads_the_uri() {
        let mut p = parts("/api/activity/heatmap?days=60");
        let Query(days) = Query::<Days>::from_request_parts(&mut p, &()).unwrap();
        assert_eq!(days.days, Some(60));
    }

    #[test]
    fn query_extractor_defaults_without_a_query_string() {
        let mut p = parts("/api/activity/heatmap");
        let Query(days) = Query::<Days>::from_request_parts(&mut p, &()).unwrap();
        assert_eq!(days.days, None);
    }

    #[test]
    fn query_extractor_rejects_a_bad_value() {
        let mut p = parts("/x?days=soon");
        let rejection = Query::<Days>::from_request_parts(&mut p, &()).unwrap_err();
        assert_eq!(rejection.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn path_extractor_parses_the_captured_value() {
        let mut p = parts("/api/client/42");
        let mut params = HashMap::new();
        params.insert("id".to_string(), "42".to_string());
        p.extensions.insert(PathParams(params));
        let Path(id) = Path::<i64>::from_request_parts(&mut p, &()).unwrap();
        assert_eq!(id, 42);
    }

    #[test]
    fn path_extractor_refuses_a_multi_capture_route() {
        let mut p = parts("/a/1/2");
        let mut params = HashMap::new();
        params.insert("a".to_string(), "1".to_string());
        params.insert("b".to_string(), "2".to_string());
        p.extensions.insert(PathParams(params));
        let rejection = Path::<String>::from_request_parts(&mut p, &()).unwrap_err();
        assert_eq!(rejection.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn path_extractor_rejects_an_unparsable_value() {
        let mut p = parts("/api/client/abc");
        let mut params = HashMap::new();
        params.insert("id".to_string(), "abc".to_string());
        p.extensions.insert(PathParams(params));
        let rejection = Path::<i64>::from_request_parts(&mut p, &()).unwrap_err();
        assert_eq!(rejection.status(), StatusCode::BAD_REQUEST);
        // The same value is fine as a String.
        let mut p = parts("/api/client/abc");
        let mut params = HashMap::new();
        params.insert("id".to_string(), "abc".to_string());
        p.extensions.insert(PathParams(params));
        let Path(id) = Path::<String>::from_request_parts(&mut p, &()).unwrap();
        assert_eq!(id, "abc");
    }

    #[test]
    fn json_extractor_reads_a_body() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct In {
            name: String,
        }
        let req = ::http::Request::builder()
            .header(::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"name":"peer"}"#))
            .unwrap();
        let Json(v) = Json::<In>::from_request(req, &()).unwrap();
        assert_eq!(v.name, "peer");
    }

    #[test]
    fn json_extractor_requires_a_json_content_type() {
        for (content_type, accepted) in [
            (Some("application/json"), true),
            (Some("application/json; charset=utf-8"), true),
            (Some("application/merge-patch+json"), true),
            (Some("APPLICATION/JSON"), true),
            (Some("text/plain"), false),
            (Some("application/x-www-form-urlencoded"), false),
            (Some("multipart/form-data; boundary=x"), false),
            (None, false),
        ] {
            let mut builder = ::http::Request::builder();
            if let Some(ct) = content_type {
                builder = builder.header(::http::header::CONTENT_TYPE, ct);
            }
            let req = builder.body(Body::from(r#"{"a":1}"#)).unwrap();
            let result = Json::<serde_json::Value>::from_request(req, &());
            assert_eq!(
                result.is_ok(),
                accepted,
                "content type {content_type:?} should {} be accepted",
                if accepted { "" } else { "not" }
            );
            if let Err(rejection) = result {
                assert_eq!(rejection.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
        }
    }

    #[test]
    fn an_optional_json_body_absorbs_the_rejection() {
        // How the bodyless POST endpoints work: no content type, so the inner
        // extractor rejects, and `Option` turns that into `None`.
        let req = ::http::Request::builder().body(Body::empty()).unwrap();
        let value = Option::<Json<serde_json::Value>>::from_request(req, &()).unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn json_extractor_treats_an_empty_body_as_null() {
        #[derive(Debug, Deserialize, PartialEq, Default)]
        #[serde(default)]
        struct In {
            name: Option<String>,
        }
        let req = ::http::Request::builder()
            .header(::http::header::CONTENT_TYPE, "application/json")
            .body(Body::empty())
            .unwrap();
        let Json(v) = Json::<Option<In>>::from_request(req, &()).unwrap();
        assert_eq!(v, None);
    }

    #[test]
    fn json_extractor_rejects_malformed_json() {
        let req = ::http::Request::builder()
            .header(::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from("{not json"))
            .unwrap();
        let rejection = Json::<serde_json::Value>::from_request(req, &()).unwrap_err();
        assert_eq!(rejection.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn cookie_jar_extractor_reads_the_request_header() {
        let req = ::http::Request::builder()
            .header(::http::header::COOKIE, "awg_session=tok")
            .body(Body::empty())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let jar = CookieJar::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(jar.get("awg_session").unwrap().value(), "tok");
    }

    #[test]
    fn connect_info_requires_the_server_to_have_attached_it() {
        let mut p = parts("/x");
        assert!(ConnectInfo::<SocketAddr>::from_request_parts(&mut p, &()).is_err());
        let addr: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        p.extensions.insert(ConnectInfo(addr));
        let ConnectInfo(got) = ConnectInfo::<SocketAddr>::from_request_parts(&mut p, &()).unwrap();
        assert_eq!(got, addr);
    }
}
