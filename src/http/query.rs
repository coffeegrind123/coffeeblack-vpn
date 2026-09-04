//! `application/x-www-form-urlencoded` query-string deserialisation.
//!
//! Replaces `serde_urlencoded` (and the `form_urlencoded` /
//! `percent-encoding` crates beneath it). A serde `Deserializer` is the right
//! shape here rather than "parse into a map of strings and hope": query values
//! are always text on the wire, but the target fields are `Option<i64>`,
//! `bool`, `Option<String>` and friends, so the conversion has to be driven by
//! the type serde asks for — exactly what `serde_urlencoded` did.

use std::borrow::Cow;

use serde::de::{
    self, DeserializeSeed, Deserializer, Error as DeError, IntoDeserializer, MapAccess, Visitor,
};

/// Failure to decode a query string into the target type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryError(String);

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for QueryError {}

impl DeError for QueryError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}

/// Percent-decode a query component, treating `+` as a space.
///
/// Invalid escapes are left as-is rather than rejected: a query string is
/// attacker-controlled, and a strict parser here would turn a typo into a 400
/// where the field would simply not match anything.
pub fn percent_decode(input: &str) -> Cow<'_, str> {
    if !input.contains('%') && !input.contains('+') {
        return Cow::Borrowed(input);
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| -> Option<u8> {
                    match b {
                        b'0'..=b'9' => Some(b - b'0'),
                        b'a'..=b'f' => Some(b - b'a' + 10),
                        b'A'..=b'F' => Some(b - b'A' + 10),
                        _ => None,
                    }
                };
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi << 4) | lo);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    // Invalid UTF-8 becomes replacement characters rather than an error, for
    // the same reason invalid escapes are tolerated.
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

/// Split a query string into decoded key/value pairs.
pub fn parse_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (
                percent_decode(k).into_owned(),
                percent_decode(v).into_owned(),
            ),
            // A bare key is a present flag with an empty value, which is what
            // `serde_urlencoded` produces too.
            None => (percent_decode(pair).into_owned(), String::new()),
        })
        .collect()
}

/// Deserialize a query string into `T`.
pub fn from_str<T: serde::de::DeserializeOwned>(query: &str) -> Result<T, QueryError> {
    let pairs = parse_pairs(query);
    T::deserialize(QueryDeserializer { pairs, index: 0 })
}

struct QueryDeserializer {
    pairs: Vec<(String, String)>,
    index: usize,
}

impl<'de> Deserializer<'de> for QueryDeserializer {
    type Error = QueryError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_map(self)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_map(self)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_map(self)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct enum identifier ignored_any
    }
}

impl<'de> MapAccess<'de> for QueryDeserializer {
    type Error = QueryError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        match self.pairs.get(self.index) {
            Some((key, _)) => seed
                .deserialize(key.clone().into_deserializer())
                .map(Some),
            None => Ok(None),
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        let (_, value) = self.pairs[self.index].clone();
        self.index += 1;
        seed.deserialize(ValueDeserializer(value))
    }
}

/// Deserializer for one query value: a string on the wire, converted to
/// whatever the target field asks for.
struct ValueDeserializer(String);

macro_rules! parse_into {
    ($method:ident, $visit:ident, $ty:ty) => {
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            let parsed: $ty = self.0.parse().map_err(|_| {
                QueryError(format!(
                    "`{}` is not a valid {}",
                    self.0,
                    std::stringify!($ty)
                ))
            })?;
            visitor.$visit(parsed)
        }
    };
}

impl<'de> Deserializer<'de> for ValueDeserializer {
    type Error = QueryError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_string(self.0)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_string(self.0)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_string(self.0)
    }

    /// An empty value means "absent" — `?flag=` deserialises to `None`, which
    /// is what a form submission with an untouched field produces.
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        if self.0.is_empty() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    /// HTML forms send `true`/`false`, but also `on` for a checked box and
    /// `1`/`0` from hand-written clients; all three are accepted.
    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let value = match self.0.as_str() {
            "true" | "1" | "on" | "yes" => true,
            "false" | "0" | "off" | "no" | "" => false,
            other => {
                return Err(QueryError(format!("`{other}` is not a boolean")));
            }
        };
        visitor.visit_bool(value)
    }

    parse_into!(deserialize_i8, visit_i8, i8);
    parse_into!(deserialize_i16, visit_i16, i16);
    parse_into!(deserialize_i32, visit_i32, i32);
    parse_into!(deserialize_i64, visit_i64, i64);
    parse_into!(deserialize_u8, visit_u8, u8);
    parse_into!(deserialize_u16, visit_u16, u16);
    parse_into!(deserialize_u32, visit_u32, u32);
    parse_into!(deserialize_u64, visit_u64, u64);
    parse_into!(deserialize_f32, visit_f32, f32);
    parse_into!(deserialize_f64, visit_f64, f64);

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let mut chars = self.0.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => visitor.visit_char(c),
            _ => Err(QueryError(format!("`{}` is not a single character", self.0))),
        }
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_enum(self.0.into_deserializer())
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    serde::forward_to_deserialize_any! {
        i128 u128 bytes byte_buf unit unit_struct seq tuple tuple_struct map
        struct identifier ignored_any
    }
}

impl de::IntoDeserializer<'_, QueryError> for ValueDeserializer {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, Default, PartialEq)]
    struct Filter {
        filter: Option<String>,
    }

    #[derive(Debug, Deserialize, Default, PartialEq)]
    struct Heatmap {
        days: Option<i64>,
    }

    #[derive(Debug, Deserialize, Default, PartialEq)]
    struct Delete {
        #[serde(default, rename = "rotateKey")]
        rotate_key: bool,
    }

    #[test]
    fn decodes_percent_escapes_and_plus() {
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%2Ffoo"), "/foo");
        assert_eq!(percent_decode("%2f%2F"), "//");
        assert_eq!(percent_decode("caf%C3%A9"), "café");
        // Malformed escapes survive rather than failing the request.
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn splits_pairs() {
        assert_eq!(
            parse_pairs("a=1&b=two"),
            vec![("a".into(), "1".into()), ("b".into(), "two".into())]
        );
        assert_eq!(parse_pairs(""), Vec::<(String, String)>::new());
        assert_eq!(parse_pairs("flag"), vec![("flag".into(), String::new())]);
        assert_eq!(parse_pairs("a=1&&b=2").len(), 2);
    }

    #[test]
    fn strings_stay_strings_even_when_numeric() {
        // The bug a "coerce to JSON" shortcut would introduce: a search term
        // that happens to be digits must not become a number.
        let f: Filter = from_str("filter=12345").unwrap();
        assert_eq!(f.filter.as_deref(), Some("12345"));
        let f: Filter = from_str("filter=abc").unwrap();
        assert_eq!(f.filter.as_deref(), Some("abc"));
    }

    #[test]
    fn integers_parse_from_their_text_form() {
        let h: Heatmap = from_str("days=30").unwrap();
        assert_eq!(h.days, Some(30));
        let h: Heatmap = from_str("days=-1").unwrap();
        assert_eq!(h.days, Some(-1));
        assert!(from_str::<Heatmap>("days=abc").is_err());
    }

    #[test]
    fn booleans_accept_the_usual_spellings() {
        assert!(from_str::<Delete>("rotateKey=true").unwrap().rotate_key);
        assert!(from_str::<Delete>("rotateKey=1").unwrap().rotate_key);
        assert!(from_str::<Delete>("rotateKey=on").unwrap().rotate_key);
        assert!(!from_str::<Delete>("rotateKey=false").unwrap().rotate_key);
        assert!(!from_str::<Delete>("rotateKey=0").unwrap().rotate_key);
        assert!(from_str::<Delete>("rotateKey=maybe").is_err());
    }

    #[test]
    fn missing_and_empty_fields_fall_back_to_defaults() {
        assert_eq!(from_str::<Filter>("").unwrap(), Filter { filter: None });
        assert_eq!(
            from_str::<Filter>("filter=").unwrap(),
            Filter { filter: None },
            "an empty value is an absent option"
        );
        assert!(!from_str::<Delete>("").unwrap().rotate_key);
        assert_eq!(from_str::<Heatmap>("other=1").unwrap().days, None);
    }

    #[test]
    fn percent_encoded_values_reach_the_field() {
        let f: Filter = from_str("filter=hello%20world").unwrap();
        assert_eq!(f.filter.as_deref(), Some("hello world"));
        let f: Filter = from_str("filter=a%26b").unwrap();
        assert_eq!(f.filter.as_deref(), Some("a&b"));
    }

    #[test]
    fn a_repeated_key_is_rejected() {
        // serde's derived struct visitor refuses a duplicate field, which is
        // what `serde_urlencoded` produced here too: `?filter=one&filter=two`
        // is an error, not a last-one-wins.
        let err = from_str::<Filter>("filter=one&filter=two").unwrap_err();
        assert!(err.to_string().contains("duplicate field"), "{err}");
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let f: Filter = from_str("unrelated=1&filter=x&other=2").unwrap();
        assert_eq!(f.filter.as_deref(), Some("x"));
    }
}
