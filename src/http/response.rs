//! Turning handler return values into HTTP responses.
//!
//! The [`IntoResponse`] trait and its implementations mirror the subset of
//! axum's the handlers in `src/api/` actually return: JSON, JSON with a status
//! code, a body with explicit headers, a cookie jar alongside a JSON body, and
//! `Result` combinations of those.

use ::http::header::{self, HeaderMap, HeaderValue};
use ::http::StatusCode;

use super::body::Body;
use super::cookie::CookieJar;

/// The response type handlers produce.
pub type Response = ::http::Response<Body>;

/// Conversion into an HTTP response.
pub trait IntoResponse {
    /// Consume `self` and produce the response.
    fn into_response(self) -> Response;
}

impl IntoResponse for Response {
    fn into_response(self) -> Response {
        self
    }
}

impl IntoResponse for StatusCode {
    fn into_response(self) -> Response {
        let mut res = Response::new(Body::empty());
        *res.status_mut() = self;
        res
    }
}

impl IntoResponse for () {
    fn into_response(self) -> Response {
        Response::new(Body::empty())
    }
}

/// Plain-text body with `text/plain; charset=utf-8`.
impl IntoResponse for String {
    fn into_response(self) -> Response {
        text_response(Body::from(self))
    }
}

impl IntoResponse for &'static str {
    fn into_response(self) -> Response {
        text_response(Body::from(self))
    }
}

impl IntoResponse for Vec<u8> {
    fn into_response(self) -> Response {
        let mut res = Response::new(Body::from(self));
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        res
    }
}

fn text_response(body: Body) -> Response {
    let mut res = Response::new(body);
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    res
}

/// A JSON body. Serialisation failure becomes a 500 rather than a panic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Json<T>(pub T);

impl<T: serde::Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        match serde_json::to_vec(&self.0) {
            Ok(bytes) => {
                let mut res = Response::new(Body::from(bytes));
                res.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                res
            }
            Err(e) => {
                crate::error!(error = %e, "failed to serialise a JSON response");
                let mut res = Response::new(Body::from(
                    r#"{"error":"internal serialisation failure"}"#,
                ));
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                res.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                res
            }
        }
    }
}

impl<T, E> IntoResponse for Result<T, E>
where
    T: IntoResponse,
    E: IntoResponse,
{
    fn into_response(self) -> Response {
        match self {
            Ok(v) => v.into_response(),
            Err(e) => e.into_response(),
        }
    }
}

impl<T: IntoResponse> IntoResponse for (StatusCode, T) {
    fn into_response(self) -> Response {
        let (status, body) = self;
        let mut res = body.into_response();
        *res.status_mut() = status;
        res
    }
}

impl<T: IntoResponse> IntoResponse for (StatusCode, HeaderMap, T) {
    fn into_response(self) -> Response {
        let (status, headers, body) = self;
        let mut res = body.into_response();
        *res.status_mut() = status;
        // Explicit headers win over whatever the body's own conversion set.
        for (name, value) in headers.iter() {
            res.headers_mut().insert(name.clone(), value.clone());
        }
        res
    }
}

/// A body with an inline list of headers, the shape
/// `(StatusCode, [(HeaderName, &str); N], body)` handlers use for one-off
/// content types.
impl<T: IntoResponse, K, V, const N: usize> IntoResponse for (StatusCode, [(K, V); N], T)
where
    K: TryInto<::http::HeaderName>,
    V: TryInto<HeaderValue>,
{
    fn into_response(self) -> Response {
        let (status, headers, body) = self;
        let mut res = body.into_response();
        *res.status_mut() = status;
        for (name, value) in headers {
            // A header that cannot be encoded is dropped rather than
            // corrupting the response; the conversions here are from
            // constants in practice, so this is unreachable in the codebase.
            if let (Ok(name), Ok(value)) = (name.try_into(), value.try_into()) {
                res.headers_mut().insert(name, value);
            }
        }
        res
    }
}

impl<T: IntoResponse> IntoResponse for (HeaderMap, T) {
    fn into_response(self) -> Response {
        let (headers, body) = self;
        let mut res = body.into_response();
        for (name, value) in headers.iter() {
            res.headers_mut().insert(name.clone(), value.clone());
        }
        res
    }
}

/// A cookie jar carried alongside a body: every cookie added to the jar is
/// emitted as a `Set-Cookie` header.
impl<T: IntoResponse> IntoResponse for (CookieJar, T) {
    fn into_response(self) -> Response {
        let (jar, body) = self;
        let mut res = body.into_response();
        jar.write_headers(res.headers_mut());
        res
    }
}

impl IntoResponse for CookieJar {
    fn into_response(self) -> Response {
        let mut res = Response::new(Body::empty());
        self.write_headers(res.headers_mut());
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn status_only_response_has_no_body() {
        let res = StatusCode::NO_CONTENT.into_response();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(res.body().is_empty());
    }

    #[test]
    fn json_sets_the_content_type() {
        let res = Json(json!({"a": 1})).into_response();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(res.body().as_bytes(), br#"{"a":1}"#);
    }

    #[test]
    fn status_and_json_tuple_keeps_both() {
        let res = (StatusCode::NOT_FOUND, Json(json!({"error": "nope"}))).into_response();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn explicit_headers_override_the_body_default() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/svg+xml"));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        let res = (StatusCode::OK, headers, String::from("<svg/>")).into_response();
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/svg+xml"
        );
        assert_eq!(res.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(res.body().as_bytes(), b"<svg/>");
    }

    #[test]
    fn results_map_both_arms() {
        let ok: Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> =
            Ok(Json(json!({"ok": true})));
        assert_eq!(ok.into_response().status(), StatusCode::OK);
        let err: Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> =
            Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "no"}))));
        assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn text_bodies_declare_utf8() {
        let res = "hello".into_response();
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
    }
}
