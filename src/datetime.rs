//! Small date/time helpers over the `time` crate.
//!
//! `time` is already a mandatory dependency (axum-extra's cookie jar takes a
//! `time::Duration` for `max_age`, and it's pulled transitively regardless), so
//! routing our own date handling through it — instead of `chrono` — drops the
//! entire chrono subtree (`chrono`, `iana-time-zone`, `num-traits`) for zero
//! new cost. These wrappers keep the call sites terse and the `time` API
//! (fallible `format`/`parse`) from leaking everywhere.

use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

/// Current UTC instant.
pub fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Format an instant as an RFC 3339 string (the on-disk representation for
/// expiry timestamps and one-time-link deadlines).
///
/// `OffsetDateTime` can always be represented in RFC 3339, so the only way
/// `format` can fail is an out-of-range component that this type cannot hold;
/// `unwrap_or_default` keeps the signature infallible for callers that just
/// want a string to store.
pub fn to_rfc3339(dt: OffsetDateTime) -> String {
    dt.format(&Rfc3339).unwrap_or_default()
}

/// `now_utc()` formatted as RFC 3339 — the common "stamp it now" case.
pub fn now_rfc3339() -> String {
    to_rfc3339(now_utc())
}

/// Parse an RFC 3339 timestamp, returning `None` on any malformed input.
pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

/// True if `s` is an acceptable client-expiry timestamp: full RFC 3339, or
/// either HTML `datetime-local` shape the UI can emit — `YYYY-MM-DDTHH:MM`
/// (no seconds) and `YYYY-MM-DDTHH:MM:SS`. Mirrors the previous chrono check
/// (`DateTime::parse_from_rfc3339` OR `NaiveDateTime::parse_from_str` with
/// `%Y-%m-%dT%H:%M` / `%Y-%m-%dT%H:%M:%S`).
pub fn is_valid_expiry(s: &str) -> bool {
    if OffsetDateTime::parse(s, &Rfc3339).is_ok() {
        return true;
    }
    let hm = format_description!("[year]-[month]-[day]T[hour]:[minute]");
    let hms = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    PrimitiveDateTime::parse(s, hm).is_ok() || PrimitiveDateTime::parse(s, hms).is_ok()
}

/// Parse a stored client-expiry timestamp, accepting exactly the shapes
/// [`is_valid_expiry`] admits.
///
/// Validation and enforcement have to agree. They did not: `is_valid_expiry`
/// accepted the two HTML `datetime-local` shapes the UI emits, while every
/// enforcement site parsed with `parse_rfc3339`, which rejects them — so an
/// expiry entered as `YYYY-MM-DDTHH:MM` was stored happily and then silently
/// never fired, leaving the client enabled forever. The naive shapes carry no
/// offset and are interpreted as UTC, matching how they are rendered.
pub fn parse_expiry(s: &str) -> Option<OffsetDateTime> {
    if let Ok(dt) = OffsetDateTime::parse(s, &Rfc3339) {
        return Some(dt);
    }
    let hms = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    let hm = format_description!("[year]-[month]-[day]T[hour]:[minute]");
    PrimitiveDateTime::parse(s, hms)
        .or_else(|_| PrimitiveDateTime::parse(s, hm))
        .ok()
        .map(|naive| naive.assume_utc())
}

/// Convert a Unix timestamp (seconds) to an instant, `None` if out of range.
/// Used to render `awg show … dump`'s latest-handshake epoch column.
pub fn from_unix(ts: i64) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(ts).ok()
}

// ---------------------------------------------------------------------------
// UTC day strings — the activity history's bucket key
// ---------------------------------------------------------------------------

/// `YYYY-MM-DD`. Fixed-width by construction (`[year]` pads to 4, `[month]`
/// and `[day]` to 2), which is what lets the activity table's `day` column be
/// range-compared and sorted as plain text.
const DAY_FMT: &[time::format_description::FormatItem<'_>] =
    format_description!("[year]-[month]-[day]");

/// Format a date as `YYYY-MM-DD`.
///
/// `format` can only fail here if the format description references a
/// component the type doesn't carry, which this one does not — so the error
/// arm is unreachable, and `unwrap_or_default` keeps callers infallible.
pub fn format_day(d: time::Date) -> String {
    d.format(&DAY_FMT).unwrap_or_default()
}

/// Today's UTC date as `YYYY-MM-DD`. Everything about the activity history is
/// keyed on UTC rather than local time so a server that changes timezone (or
/// crosses a DST boundary) doesn't split or merge a day's bucket.
pub fn today_utc() -> String {
    format_day(now_utc().date())
}

/// The UTC day `n` days before today, as `YYYY-MM-DD`. Used for the retention
/// cutoff and the start of the heatmap window.
///
/// Saturating rather than wrapping: `n` is operator-supplied, and clamping to
/// the minimum representable date makes an absurd value degrade to "keep
/// everything" instead of panicking or silently selecting a future cutoff
/// that would delete the whole table.
pub fn day_utc_ago(n: i64) -> String {
    let date = now_utc()
        .date()
        .saturating_sub(time::Duration::days(n.max(0)));
    format_day(date)
}

/// The `n` UTC days ending today, ascending — the heatmap's x-axis.
///
/// Built by walking the calendar rather than emitting a range the caller
/// re-derives, so month lengths and leap days are the `time` crate's problem
/// and not the frontend's. `n <= 0` yields an empty axis.
pub fn last_n_days(n: i64) -> Vec<String> {
    if n <= 0 {
        return Vec::new();
    }
    let today = now_utc().date();
    let mut days = Vec::with_capacity(n as usize);
    let mut d = today.saturating_sub(time::Duration::days(n - 1));
    while d <= today {
        days.push(format_day(d));
        match d.next_day() {
            Some(next) => d = next,
            // Only reachable at the maximum representable date.
            None => break,
        }
    }
    days
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_round_trip() {
        let s = "2024-06-15T12:34:56Z";
        let dt = parse_rfc3339(s).unwrap();
        // time renders UTC with a `Z` designator, same instant.
        assert_eq!(to_rfc3339(dt), s);
    }

    #[test]
    fn accepts_rfc3339_offset_form() {
        // chrono's to_rfc3339 emitted `+00:00`; ensure we still accept it.
        assert!(parse_rfc3339("2024-06-15T12:34:56+00:00").is_some());
    }

    #[test]
    fn valid_expiry_shapes() {
        assert!(is_valid_expiry("2024-06-15T12:34:56Z")); // RFC3339
        assert!(is_valid_expiry("2024-06-15T12:34")); // datetime-local, no secs
        assert!(is_valid_expiry("2024-06-15T12:34:56")); // datetime-local, secs
        assert!(!is_valid_expiry("15/06/2024")); // wrong shape
        assert!(!is_valid_expiry("not a date"));
        assert!(!is_valid_expiry("2024-13-40T99:99")); // out of range
    }

    #[test]
    fn from_unix_matches_expected() {
        let dt = from_unix(1_718_454_896).unwrap();
        assert_eq!(dt.unix_timestamp(), 1_718_454_896);
    }
}

#[cfg(test)]
mod expiry_parse_tests {
    use super::{is_valid_expiry, parse_expiry};

    /// Validation and enforcement must accept exactly the same set. When they
    /// disagreed, an expiry the API accepted was one the enforcement path
    /// could not read, so the client silently never expired.
    #[test]
    fn every_accepted_expiry_shape_also_parses() {
        for s in [
            "2027-01-02T03:04:05Z",
            "2027-01-02T03:04:05+00:00",
            "2027-01-02T03:04:05",
            "2027-01-02T03:04",
        ] {
            assert!(is_valid_expiry(s), "is_valid_expiry rejected {s:?}");
            assert!(
                parse_expiry(s).is_some(),
                "parse_expiry could not read the accepted value {s:?}"
            );
        }
    }

    #[test]
    fn rejects_what_validation_rejects() {
        for s in ["", "not-a-date", "2027-13-02T03:04", "03:04"] {
            assert!(!is_valid_expiry(s), "is_valid_expiry accepted {s:?}");
            assert!(parse_expiry(s).is_none(), "parse_expiry accepted {s:?}");
        }
    }

    #[test]
    fn naive_shapes_are_interpreted_as_utc() {
        let naive = parse_expiry("2027-01-02T03:04:05").unwrap();
        let explicit = parse_expiry("2027-01-02T03:04:05Z").unwrap();
        assert_eq!(naive, explicit);
    }
}
