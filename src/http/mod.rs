//! The HTTP layer: server, router, extractors and responses.
//!
//! This replaces axum, hyper, tower and their supporting cast — some thirty
//! crates — with the subset this project uses. The public shapes deliberately
//! mirror axum's, so handlers read the same:
//!
//! ```ignore
//! pub async fn get_client(
//!     State(state): State<AppState>,
//!     jar: CookieJar,
//!     Path(id): Path<i64>,
//! ) -> Result<Json<Value>, (StatusCode, Json<Value>)> { … }
//! ```
//!
//! The pieces:
//!
//! * [`server`] — a strict HTTP/1.1 server (see its module docs for the
//!   parsing rules and limits).
//! * [`router`] — `/api/client/:id` patterns, method dispatch, state binding.
//! * [`handler`] — the trait that lets an `async fn` be a handler.
//! * [`extract`] — `State`, `Path`, `Query`, `Json`, `CookieJar`,
//!   `ConnectInfo`, `HeaderMap`.
//! * [`response`] — `IntoResponse` for what handlers return.
//! * [`cookie`] — cookie parsing and `Set-Cookie` rendering.
//! * [`query`] — a serde `Deserializer` for query strings.
//!
//! The `http` crate is kept: it is the ecosystem's shared definition of
//! `Request`, `Response`, `HeaderMap`, `StatusCode`, `Method` and `Uri`, and
//! its only dependencies (`bytes`, `itoa`) are already in the graph for the
//! proxy and `serde_json`. Rewriting a header map would trade a
//! widely-audited type layer for a bespoke one and remove exactly one crate.

pub mod body;
pub mod cookie;
pub mod extract;
pub mod handler;
pub mod query;
pub mod response;
pub mod router;
pub mod server;

pub use body::{to_bytes, Body};
pub use cookie::{Cookie, CookieJar, SameSite};
pub use extract::{ConnectInfo, FromRequest, FromRequestParts, Path, Query, State};
pub use handler::Handler;
pub use ::http::response::Builder as ResponseBuilder;
pub use ::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
pub use response::{IntoResponse, Json, Response};
pub use router::{routing, MethodRouter, Router};
pub use server::serve;
