//! Path routing.
//!
//! Patterns are the `/api/client/:id` shape axum 0.7 uses: literal segments
//! plus `:name` captures. Matching walks the registered routes and prefers the
//! most specific one (fewest captures), so a static route always wins over a
//! parameterised route of the same shape — the property `matchit`'s radix tree
//! provided.

use std::collections::HashMap;
use std::sync::Arc;

use ::http::{Method, StatusCode};

use super::body::Body;
use super::extract::PathParams;
use super::handler::{BoxFuture, Handler};
use super::query::percent_decode;
use super::response::{IntoResponse, Response};

/// A handler erased to a callable taking the request and the router state.
type Erased<S> = Arc<dyn Fn(::http::Request<Body>, S) -> BoxFuture + Send + Sync>;

fn erase<H, T, S>(handler: H) -> Erased<S>
where
    H: Handler<T, S> + Clone + Send + Sync + 'static,
    T: 'static,
    S: 'static,
{
    Arc::new(move |req, state| handler.clone().call(req, state))
}

/// One segment of a route pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// Must match exactly.
    Literal(String),
    /// Matches any one segment, captured under this name.
    Param(String),
}

/// A parsed route pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    segments: Vec<Segment>,
    params: usize,
}

impl Pattern {
    fn parse(path: &str) -> Self {
        let segments: Vec<Segment> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| match s.strip_prefix(':') {
                Some(name) => Segment::Param(name.to_string()),
                None => Segment::Literal(s.to_string()),
            })
            .collect();
        let params = segments
            .iter()
            .filter(|s| matches!(s, Segment::Param(_)))
            .count();
        Self { segments, params }
    }

    /// Match a request path, returning the captured parameters.
    fn matches(&self, path: &str) -> Option<HashMap<String, String>> {
        let mut actual = path.split('/').filter(|s| !s.is_empty());
        let mut captured = HashMap::new();
        for segment in &self.segments {
            let part = actual.next()?;
            match segment {
                Segment::Literal(literal) => {
                    if literal != part {
                        return None;
                    }
                }
                Segment::Param(name) => {
                    captured.insert(name.clone(), percent_decode(part).into_owned());
                }
            }
        }
        // Every segment of the request must have been consumed.
        actual.next().is_none().then_some(captured)
    }

    /// Prefix this pattern with another path (used by `nest`).
    fn prefixed(&self, prefix: &str) -> Self {
        let mut segments = Pattern::parse(prefix).segments;
        segments.extend(self.segments.iter().cloned());
        let params = segments
            .iter()
            .filter(|s| matches!(s, Segment::Param(_)))
            .count();
        Pattern { segments, params }
    }
}

/// The handlers registered for one path, keyed by method.
pub struct MethodRouter<S = ()> {
    entries: Vec<(Method, Erased<S>)>,
}

impl<S> Clone for MethodRouter<S> {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }
}

impl<S: Clone + Send + Sync + 'static> MethodRouter<S> {
    fn with(method: Method, handler: Erased<S>) -> Self {
        Self {
            entries: vec![(method, handler)],
        }
    }

    fn add<H, T>(mut self, method: Method, handler: H) -> Self
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
    {
        self.entries.retain(|(m, _)| *m != method);
        self.entries.push((method, erase(handler)));
        self
    }

    /// Also handle `GET` with `handler`.
    pub fn get<H, T>(self, handler: H) -> Self
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
    {
        self.add(Method::GET, handler)
    }

    /// Also handle `POST` with `handler`.
    pub fn post<H, T>(self, handler: H) -> Self
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
    {
        self.add(Method::POST, handler)
    }

    /// Also handle `PUT` with `handler`.
    pub fn put<H, T>(self, handler: H) -> Self
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
    {
        self.add(Method::PUT, handler)
    }

    /// Also handle `PATCH` with `handler`.
    pub fn patch<H, T>(self, handler: H) -> Self
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
    {
        self.add(Method::PATCH, handler)
    }

    /// Also handle `DELETE` with `handler`.
    pub fn delete<H, T>(self, handler: H) -> Self
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
    {
        self.add(Method::DELETE, handler)
    }

    /// The methods this route answers, for the `Allow` header of a 405.
    fn allowed(&self) -> String {
        let mut methods: Vec<&str> = self.entries.iter().map(|(m, _)| m.as_str()).collect();
        // HEAD is served by the GET handler (the server drops the body).
        if methods.contains(&"GET") {
            methods.push("HEAD");
        }
        methods.join(", ")
    }
}

/// Route builders, mirroring `axum::routing`.
pub mod routing {
    use super::*;

    /// Handle `GET` (and `HEAD`) with `handler`.
    pub fn get<H, T, S>(handler: H) -> MethodRouter<S>
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
        S: Clone + Send + Sync + 'static,
    {
        MethodRouter::with(Method::GET, erase(handler))
    }

    /// Handle `POST` with `handler`.
    pub fn post<H, T, S>(handler: H) -> MethodRouter<S>
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
        S: Clone + Send + Sync + 'static,
    {
        MethodRouter::with(Method::POST, erase(handler))
    }

    /// Handle `PUT` with `handler`.
    pub fn put<H, T, S>(handler: H) -> MethodRouter<S>
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
        S: Clone + Send + Sync + 'static,
    {
        MethodRouter::with(Method::PUT, erase(handler))
    }

    /// Handle `PATCH` with `handler`.
    pub fn patch<H, T, S>(handler: H) -> MethodRouter<S>
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
        S: Clone + Send + Sync + 'static,
    {
        MethodRouter::with(Method::PATCH, erase(handler))
    }

    /// Handle `DELETE` with `handler`.
    pub fn delete<H, T, S>(handler: H) -> MethodRouter<S>
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
        S: Clone + Send + Sync + 'static,
    {
        MethodRouter::with(Method::DELETE, erase(handler))
    }
}

/// A set of routes, optionally carrying application state.
pub struct Router<S = ()> {
    routes: Vec<(Pattern, MethodRouter<S>)>,
    fallback: Option<Erased<S>>,
}

impl<S> Clone for Router<S> {
    fn clone(&self) -> Self {
        Self {
            routes: self.routes.clone(),
            fallback: self.fallback.clone(),
        }
    }
}

impl<S: Clone + Send + Sync + 'static> Default for Router<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Clone + Send + Sync + 'static> Router<S> {
    /// An empty router.
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            fallback: None,
        }
    }

    /// Register `method_router` at `path`.
    ///
    /// Registering the same path twice replaces the earlier entry, which is
    /// what axum does (it panics on overlapping routes; replacing keeps the
    /// last definition authoritative and is never exercised here — every path
    /// in this project is registered once).
    pub fn route(mut self, path: &str, method_router: MethodRouter<S>) -> Self {
        let pattern = Pattern::parse(path);
        self.routes.retain(|(p, _)| *p != pattern);
        self.routes.push((pattern, method_router));
        self
    }

    /// Fold another router's routes into this one.
    pub fn merge(mut self, other: Router<S>) -> Self {
        self.routes.extend(other.routes);
        if self.fallback.is_none() {
            self.fallback = other.fallback;
        }
        self
    }

    /// Mount another router under `prefix`.
    pub fn nest(mut self, prefix: &str, other: Router<S>) -> Self {
        for (pattern, methods) in other.routes {
            self.routes.push((pattern.prefixed(prefix), methods));
        }
        self
    }

    /// Handle any request no route matched.
    pub fn fallback<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
    {
        self.fallback = Some(erase(handler));
        self
    }

    /// Bind the application state, producing a router that can serve requests.
    pub fn with_state(self, state: S) -> Router<()> {
        let routes = self
            .routes
            .into_iter()
            .map(|(pattern, methods)| {
                let entries = methods
                    .entries
                    .into_iter()
                    .map(|(method, handler)| {
                        let state = state.clone();
                        let mapped: Erased<()> = Arc::new(move |req, _| handler(req, state.clone()));
                        (method, mapped)
                    })
                    .collect();
                (pattern, MethodRouter { entries })
            })
            .collect();
        let fallback = self.fallback.map(|handler| {
            let state = state.clone();
            let mapped: Erased<()> = Arc::new(move |req, _| handler(req, state.clone()));
            mapped
        });
        Router { routes, fallback }
    }
}

impl Router<()> {
    /// Dispatch one request, consuming the router.
    ///
    /// The `Result` is `Infallible` — dispatch never fails, it produces a
    /// response — and exists so the shape matches the `tower::ServiceExt`
    /// method the test suite used to call.
    pub async fn oneshot(
        self,
        req: ::http::Request<Body>,
    ) -> Result<Response, std::convert::Infallible> {
        Ok(self.dispatch(req).await)
    }

    /// Dispatch one request, returning the response.
    ///
    /// This is the whole request path: match, capture parameters, hand the
    /// request to the handler.
    pub async fn dispatch(&self, mut req: ::http::Request<Body>) -> Response {
        let path = req.uri().path().to_string();

        // Prefer the most specific match: fewest captures wins, so a literal
        // route beats a parameterised one of the same shape.
        let mut best: Option<(&MethodRouter<()>, HashMap<String, String>, usize)> = None;
        for (pattern, methods) in &self.routes {
            if let Some(params) = pattern.matches(&path) {
                let better = best.as_ref().is_none_or(|(_, _, best_params)| {
                    pattern.params < *best_params
                });
                if better {
                    best = Some((methods, params, pattern.params));
                }
            }
        }

        let Some((methods, params, _)) = best else {
            return match &self.fallback {
                Some(handler) => handler(req, ()).await,
                None => not_found(),
            };
        };

        // HEAD is answered by the GET handler; the server strips the body.
        let method = if req.method() == Method::HEAD {
            Method::GET
        } else {
            req.method().clone()
        };

        let Some((_, handler)) = methods.entries.iter().find(|(m, _)| *m == method) else {
            return method_not_allowed(&methods.allowed());
        };

        req.extensions_mut().insert(PathParams(params));
        handler(req, ()).await
    }
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        super::response::Json(serde_json::json!({"error": "Not found"})),
    )
        .into_response()
}

fn method_not_allowed(allow: &str) -> Response {
    let mut res = (
        StatusCode::METHOD_NOT_ALLOWED,
        super::response::Json(serde_json::json!({"error": "Method not allowed"})),
    )
        .into_response();
    if let Ok(value) = ::http::HeaderValue::from_str(allow) {
        res.headers_mut().insert(::http::header::ALLOW, value);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body::Body;
    use crate::http::extract::{Path, State};
    use crate::http::response::Json;

    fn request(method: Method, uri: &str) -> ::http::Request<Body> {
        ::http::Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    async fn body_of(res: Response) -> String {
        String::from_utf8(res.into_body().as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn patterns_match_literal_and_parameter_segments() {
        let p = Pattern::parse("/api/client/:id/configuration");
        assert_eq!(p.params, 1);
        let captured = p.matches("/api/client/42/configuration").unwrap();
        assert_eq!(captured.get("id").unwrap(), "42");
        assert!(p.matches("/api/client/42").is_none(), "too few segments");
        assert!(
            p.matches("/api/client/42/configuration/extra").is_none(),
            "too many segments"
        );
        assert!(p.matches("/api/other/42/configuration").is_none());
    }

    #[test]
    fn patterns_ignore_leading_and_trailing_slashes() {
        let p = Pattern::parse("/health");
        assert!(p.matches("/health").is_some());
        assert!(p.matches("health").is_some());
        assert!(p.matches("/health/").is_some());
    }

    #[test]
    fn captured_parameters_are_percent_decoded() {
        let p = Pattern::parse("/cnf/:token");
        let captured = p.matches("/cnf/a%20b").unwrap();
        assert_eq!(captured.get("token").unwrap(), "a b");
    }

    #[tokio::test]
    async fn dispatch_routes_by_path_and_method() {
        let app: Router<()> = Router::new()
            .route(
                "/thing",
                routing::get(|| async { "got" }).post(|| async { "posted" }),
            )
            .route("/thing/:id", routing::get(|Path(id): Path<i64>| async move {
                format!("id={id}")
            }));

        let res = app.dispatch(request(Method::GET, "/thing")).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_of(res).await, "got");

        let res = app.dispatch(request(Method::POST, "/thing")).await;
        assert_eq!(body_of(res).await, "posted");

        let res = app.dispatch(request(Method::GET, "/thing/7")).await;
        assert_eq!(body_of(res).await, "id=7");
    }

    #[tokio::test]
    async fn head_is_served_by_the_get_handler() {
        let app: Router<()> = Router::new().route("/thing", routing::get(|| async { "got" }));
        let res = app.dispatch(request(Method::HEAD, "/thing")).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unmatched_method_is_405_with_an_allow_header() {
        let app: Router<()> = Router::new().route(
            "/thing",
            routing::get(|| async { "got" }).delete(|| async { "gone" }),
        );
        let res = app.dispatch(request(Method::POST, "/thing")).await;
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        let allow = res.headers().get(::http::header::ALLOW).unwrap().to_str().unwrap();
        assert!(allow.contains("GET"), "{allow}");
        assert!(allow.contains("DELETE"), "{allow}");
        assert!(allow.contains("HEAD"), "{allow}");
        assert!(!allow.contains("POST"), "{allow}");
    }

    #[tokio::test]
    async fn unmatched_path_is_404_or_the_fallback() {
        let app: Router<()> = Router::new().route("/thing", routing::get(|| async { "got" }));
        let res = app.dispatch(request(Method::GET, "/nope")).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let app = app.fallback(|| async { "fell back" });
        let res = app.dispatch(request(Method::GET, "/nope")).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_of(res).await, "fell back");
    }

    #[tokio::test]
    async fn the_most_specific_route_wins() {
        // Registration order must not decide which of these answers.
        let app: Router<()> = Router::new()
            .route("/api/client/:id", routing::get(|| async { "dynamic" }))
            .route("/api/client/list", routing::get(|| async { "static" }));
        assert_eq!(
            body_of(app.dispatch(request(Method::GET, "/api/client/list")).await).await,
            "static"
        );
        assert_eq!(
            body_of(app.dispatch(request(Method::GET, "/api/client/9")).await).await,
            "dynamic"
        );
    }

    #[tokio::test]
    async fn nest_prefixes_every_route() {
        let inner: Router<()> = Router::new()
            .route("/session", routing::get(|| async { "session" }))
            .route("/client/:id", routing::get(|| async { "client" }));
        let app: Router<()> = Router::new()
            .route("/health", routing::get(|| async { "ok" }))
            .nest("/api", inner);

        assert_eq!(
            app.dispatch(request(Method::GET, "/api/session")).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            body_of(app.dispatch(request(Method::GET, "/api/client/3")).await).await,
            "client"
        );
        assert_eq!(
            app.dispatch(request(Method::GET, "/session")).await.status(),
            StatusCode::NOT_FOUND,
            "the un-prefixed path must not answer"
        );
        assert_eq!(
            body_of(app.dispatch(request(Method::GET, "/health")).await).await,
            "ok"
        );
    }

    #[tokio::test]
    async fn merge_combines_routes() {
        let a: Router<()> = Router::new().route("/a", routing::get(|| async { "a" }));
        let b: Router<()> = Router::new().route("/b", routing::get(|| async { "b" }));
        let app = a.merge(b);
        assert_eq!(body_of(app.dispatch(request(Method::GET, "/a")).await).await, "a");
        assert_eq!(body_of(app.dispatch(request(Method::GET, "/b")).await).await, "b");
    }

    #[tokio::test]
    async fn state_reaches_the_handler() {
        #[derive(Clone)]
        struct Config {
            greeting: &'static str,
        }
        let app = Router::new()
            .route(
                "/hello",
                routing::get(|State(cfg): State<Config>| async move { cfg.greeting.to_string() }),
            )
            .with_state(Config {
                greeting: "hello from state",
            });
        assert_eq!(
            body_of(app.dispatch(request(Method::GET, "/hello")).await).await,
            "hello from state"
        );
    }

    #[tokio::test]
    async fn oneshot_matches_the_tower_shape() {
        let app: Router<()> = Router::new().route(
            "/j",
            routing::get(|| async { Json(serde_json::json!({"ok": true})) }),
        );
        let res = app.oneshot(request(Method::GET, "/j")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_of(res).await, r#"{"ok":true}"#);
    }

    #[tokio::test]
    async fn a_query_string_does_not_affect_matching() {
        let app: Router<()> = Router::new().route("/thing", routing::get(|| async { "got" }));
        let res = app.dispatch(request(Method::GET, "/thing?a=1&b=2")).await;
        assert_eq!(res.status(), StatusCode::OK);
    }
}
