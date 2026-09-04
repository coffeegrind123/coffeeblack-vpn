//! Cookies: a builder, and the jar that reads `Cookie:` and writes
//! `Set-Cookie:`.
//!
//! Replaces `axum-extra`'s cookie extractor and the `cookie` crate under it.
//! This project keeps exactly one cookie — the session token — so what was
//! needed is parsing a request header, and emitting a correctly attributed
//! `Set-Cookie` (path, `HttpOnly`, `Secure`, `SameSite=Strict`, and an optional
//! `Max-Age`) plus the removal form. The rest of the `cookie` crate (signed and
//! private jars, percent-encoded values, a `time`-based expiry model) was never
//! used, and `axum-extra`'s default features additionally dragged in `multer`
//! and `encoding_rs` for a multipart extractor this project has no route for.

use ::http::header::{HeaderMap, HeaderValue, COOKIE, SET_COOKIE};

/// `SameSite` attribute values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// Never sent on cross-site requests.
    Strict,
    /// Sent on top-level cross-site navigations.
    Lax,
    /// Always sent; requires `Secure`.
    None,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

/// A cookie: a name/value pair plus the attributes that go with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    name: String,
    value: String,
    path: Option<String>,
    http_only: bool,
    secure: bool,
    same_site: Option<SameSite>,
    max_age: Option<i64>,
    /// Set by [`CookieJar::remove`]: emit the expiry form rather than a value.
    removal: bool,
}

impl Cookie {
    /// Start building a cookie from a `(name, value)` pair.
    pub fn build(pair: impl Into<Cookie>) -> CookieBuilder {
        CookieBuilder(pair.into())
    }

    /// The cookie's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The cookie's value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Render the `Set-Cookie` header value.
    ///
    /// Attribute order matches what browsers and proxies expect to see, and
    /// the removal form pins `Max-Age=0` together with a zero `Expires` so
    /// that both modern and legacy clients drop the cookie.
    fn to_set_cookie(&self) -> String {
        let mut out = String::with_capacity(96);
        out.push_str(&self.name);
        out.push('=');
        if !self.removal {
            out.push_str(&self.value);
        }
        if let Some(path) = &self.path {
            out.push_str("; Path=");
            out.push_str(path);
        }
        if self.removal {
            out.push_str("; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
        } else if let Some(max_age) = self.max_age {
            out.push_str("; Max-Age=");
            out.push_str(&max_age.to_string());
        }
        if self.http_only {
            out.push_str("; HttpOnly");
        }
        if self.secure {
            out.push_str("; Secure");
        }
        if let Some(same_site) = self.same_site {
            out.push_str("; SameSite=");
            out.push_str(same_site.as_str());
        }
        out
    }
}

impl From<(&str, String)> for Cookie {
    fn from((name, value): (&str, String)) -> Self {
        Self::new(name, &value)
    }
}

impl From<(&str, &str)> for Cookie {
    fn from((name, value): (&str, &str)) -> Self {
        Self::new(name, value)
    }
}

impl From<&str> for Cookie {
    /// A bare name, used by the removal form.
    fn from(name: &str) -> Self {
        Self::new(name, "")
    }
}

impl Cookie {
    fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
            path: None,
            http_only: false,
            secure: false,
            same_site: None,
            max_age: None,
            removal: false,
        }
    }
}

/// Fluent builder returned by [`Cookie::build`].
#[derive(Debug, Clone)]
pub struct CookieBuilder(Cookie);

impl CookieBuilder {
    /// Set the `Path` attribute.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.0.path = Some(path.into());
        self
    }

    /// Set the `HttpOnly` attribute.
    pub fn http_only(mut self, yes: bool) -> Self {
        self.0.http_only = yes;
        self
    }

    /// Set the `Secure` attribute.
    pub fn secure(mut self, yes: bool) -> Self {
        self.0.secure = yes;
        self
    }

    /// Set the `SameSite` attribute.
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.0.same_site = Some(same_site);
        self
    }

    /// Set `Max-Age`, in seconds.
    pub fn max_age(mut self, duration: time::Duration) -> Self {
        self.0.max_age = Some(duration.whole_seconds());
        self
    }

    /// Finish the cookie.
    pub fn build(self) -> Cookie {
        self.0
    }
}

/// The cookies of one request, plus any changes a handler makes.
///
/// Extracted from the request (see `super::extract`) and, when returned from a
/// handler, written back out as `Set-Cookie` headers. Only cookies added or
/// removed during the request are emitted — the ones that merely arrived are
/// not echoed back.
#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    /// Cookies parsed from the request, with no attributes attached.
    incoming: Vec<Cookie>,
    /// Cookies to emit as `Set-Cookie`.
    outgoing: Vec<Cookie>,
}

impl CookieJar {
    /// Parse the jar from a request's headers.
    ///
    /// A malformed pair is skipped rather than failing the request: browsers
    /// and intermediaries do send oddities, and the only cookie that matters
    /// here is looked up by name.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut incoming = Vec::new();
        for value in headers.get_all(COOKIE).iter() {
            let Ok(text) = value.to_str() else {
                continue;
            };
            for pair in text.split(';') {
                let pair = pair.trim();
                if pair.is_empty() {
                    continue;
                }
                let Some((name, value)) = pair.split_once('=') else {
                    continue;
                };
                let name = name.trim();
                if name.is_empty() {
                    continue;
                }
                // Values may be double-quoted (RFC 6265 §4.1.1).
                let value = value.trim().trim_matches('"');
                incoming.push(Cookie::new(name, value));
            }
        }
        Self {
            incoming,
            outgoing: Vec::new(),
        }
    }

    /// Look up a cookie by name. A cookie added during this request wins over
    /// one that arrived with it, and one removed during this request is gone.
    pub fn get(&self, name: &str) -> Option<&Cookie> {
        if let Some(pending) = self.outgoing.iter().find(|c| c.name == name) {
            return (!pending.removal).then_some(pending);
        }
        self.incoming.iter().find(|c| c.name == name)
    }

    /// Add a cookie, to be emitted as `Set-Cookie`.
    ///
    /// Named `add`, like the jar it replaces, so the call sites read the same.
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, cookie: Cookie) -> Self {
        self.outgoing.retain(|c| c.name != cookie.name);
        self.outgoing.push(cookie);
        self
    }

    /// Remove a cookie from the client by emitting an expired `Set-Cookie`.
    ///
    /// The removal carries a `Path` — defaulting to `/`, the path the session
    /// cookie is set with. A `Set-Cookie` whose path does not match the
    /// original leaves the original in place, which for a logout would mean
    /// the session cookie survives the request meant to clear it.
    pub fn remove(mut self, cookie: Cookie) -> Self {
        let mut removal = cookie;
        removal.removal = true;
        removal.value.clear();
        if removal.path.is_none() {
            removal.path = Some("/".to_string());
        }
        self.outgoing.retain(|c| c.name != removal.name);
        self.outgoing.push(removal);
        self
    }

    /// Write every pending change as a `Set-Cookie` header.
    pub(super) fn write_headers(&self, headers: &mut HeaderMap) {
        for cookie in &self.outgoing {
            match HeaderValue::from_str(&cookie.to_set_cookie()) {
                Ok(value) => {
                    headers.append(SET_COOKIE, value);
                }
                Err(e) => {
                    // A name or value with a control character cannot go on
                    // the wire; dropping it is better than corrupting the
                    // header block.
                    crate::error!(error = %e, cookie = %cookie.name, "invalid Set-Cookie value");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jar_with(header: &str) -> CookieJar {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_str(header).unwrap());
        CookieJar::from_headers(&headers)
    }

    fn set_cookie_values(jar: &CookieJar) -> Vec<String> {
        let mut headers = HeaderMap::new();
        jar.write_headers(&mut headers);
        headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn parses_a_single_pair() {
        let jar = jar_with("coffeeblack_session=abc123");
        assert_eq!(jar.get("coffeeblack_session").unwrap().value(), "abc123");
        assert!(jar.get("other").is_none());
    }

    #[test]
    fn parses_multiple_pairs_and_trims_whitespace() {
        let jar = jar_with("a=1; coffeeblack_session=tok ;b=2");
        assert_eq!(jar.get("a").unwrap().value(), "1");
        assert_eq!(jar.get("coffeeblack_session").unwrap().value(), "tok");
        assert_eq!(jar.get("b").unwrap().value(), "2");
    }

    #[test]
    fn tolerates_malformed_pairs() {
        let jar = jar_with("novalue; =empty; ok=1;;");
        assert_eq!(jar.get("ok").unwrap().value(), "1");
        assert!(jar.get("novalue").is_none());
        assert!(jar.get("").is_none());
    }

    #[test]
    fn unquotes_values() {
        let jar = jar_with("coffeeblack_session=\"quoted\"");
        assert_eq!(jar.get("coffeeblack_session").unwrap().value(), "quoted");
    }

    #[test]
    fn reads_several_cookie_headers() {
        let mut headers = HeaderMap::new();
        headers.append(COOKIE, HeaderValue::from_static("a=1"));
        headers.append(COOKIE, HeaderValue::from_static("b=2"));
        let jar = CookieJar::from_headers(&headers);
        assert_eq!(jar.get("a").unwrap().value(), "1");
        assert_eq!(jar.get("b").unwrap().value(), "2");
    }

    #[test]
    fn added_cookie_renders_every_attribute() {
        let jar = CookieJar::default().add(
            Cookie::build(("coffeeblack_session", "tok"))
                .path("/")
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Strict)
                .max_age(time::Duration::days(30))
                .build(),
        );
        let values = set_cookie_values(&jar);
        assert_eq!(values.len(), 1);
        let v = &values[0];
        assert!(v.starts_with("coffeeblack_session=tok"), "{v}");
        assert!(v.contains("; Path=/"), "{v}");
        assert!(v.contains("; Max-Age=2592000"), "{v}");
        assert!(v.contains("; HttpOnly"), "{v}");
        assert!(v.contains("; Secure"), "{v}");
        assert!(v.contains("; SameSite=Strict"), "{v}");
    }

    #[test]
    fn a_session_cookie_omits_max_age() {
        let jar = CookieJar::default().add(
            Cookie::build(("coffeeblack_session", "tok"))
                .path("/")
                .http_only(true)
                .secure(false)
                .same_site(SameSite::Strict)
                .build(),
        );
        let v = &set_cookie_values(&jar)[0];
        assert!(!v.contains("Max-Age"), "{v}");
        assert!(!v.contains("Secure"), "{v}");
    }

    #[test]
    fn removal_expires_the_cookie_on_the_right_path() {
        let jar = jar_with("coffeeblack_session=tok").remove(Cookie::from("coffeeblack_session"));
        let v = &set_cookie_values(&jar)[0];
        assert!(v.starts_with("coffeeblack_session=;"), "{v}");
        assert!(v.contains("Path=/"), "{v}");
        assert!(v.contains("Max-Age=0"), "{v}");
        assert!(v.contains("Expires=Thu, 01 Jan 1970"), "{v}");
        // And the jar itself no longer reports the cookie.
        assert!(jar.get("coffeeblack_session").is_none());
    }

    #[test]
    fn adding_twice_emits_one_header() {
        let jar = CookieJar::default()
            .add(Cookie::build(("k", "first")).build())
            .add(Cookie::build(("k", "second")).build());
        let values = set_cookie_values(&jar);
        assert_eq!(values.len(), 1);
        assert!(values[0].starts_with("k=second"));
    }

    #[test]
    fn incoming_cookies_are_not_echoed_back() {
        let jar = jar_with("coffeeblack_session=tok; other=1");
        assert!(set_cookie_values(&jar).is_empty());
    }
}
