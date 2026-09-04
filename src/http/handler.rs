//! The [`Handler`] trait: how an `async fn` with extractor arguments becomes
//! something the router can call.
//!
//! The shape follows axum's: every argument but the last must implement
//! [`FromRequestParts`], the last may additionally implement [`FromRequest`]
//! and consume the body. The `T` type parameter is the tuple of argument
//! types — it exists only so the compiler can pick the right implementation,
//! and is never named at a call site.

use std::future::Future;
use std::pin::Pin;

use super::body::Body;
use super::extract::{FromRequest, FromRequestParts};
use super::response::{IntoResponse, Response};

/// A boxed, `Send` future returning a response.
pub type BoxFuture = Pin<Box<dyn Future<Output = Response> + Send>>;

/// Something the router can invoke for a matched request.
pub trait Handler<T, S>: Clone + Send + Sized + 'static {
    /// Run the handler.
    fn call(self, req: ::http::Request<Body>, state: S) -> BoxFuture;
}

impl<F, Fut, R, S> Handler<(), S> for F
where
    F: FnOnce() -> Fut + Clone + Send + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoResponse,
{
    fn call(self, _req: ::http::Request<Body>, _state: S) -> BoxFuture {
        Box::pin(async move { self().await.into_response() })
    }
}

/// Implement `Handler` for a function of N arguments: N-1 taken from the
/// request's parts, and the last from the request as a whole.
macro_rules! impl_handler {
    ([$($parts:ident),*], $last:ident) => {
        #[allow(non_snake_case, unused_mut, unused_variables)]
        impl<F, Fut, R, S, $($parts,)* $last> Handler<($($parts,)* $last,), S> for F
        where
            F: FnOnce($($parts,)* $last) -> Fut + Clone + Send + 'static,
            Fut: Future<Output = R> + Send + 'static,
            R: IntoResponse,
            S: Send + Sync + 'static,
            $($parts: FromRequestParts<S> + Send,)*
            $last: FromRequest<S> + Send,
        {
            fn call(self, req: ::http::Request<Body>, state: S) -> BoxFuture {
                Box::pin(async move {
                    let (mut parts, body) = req.into_parts();
                    $(
                        let $parts = match $parts::from_request_parts(&mut parts, &state) {
                            Ok(value) => value,
                            Err(rejection) => return rejection,
                        };
                    )*
                    let req = ::http::Request::from_parts(parts, body);
                    let $last = match $last::from_request(req, &state) {
                        Ok(value) => value,
                        Err(rejection) => return rejection,
                    };
                    self($($parts,)* $last).await.into_response()
                })
            }
        }
    };
}

impl_handler!([], T1);
impl_handler!([T1], T2);
impl_handler!([T1, T2], T3);
impl_handler!([T1, T2, T3], T4);
impl_handler!([T1, T2, T3, T4], T5);
impl_handler!([T1, T2, T3, T4, T5], T6);
impl_handler!([T1, T2, T3, T4, T5, T6], T7);
