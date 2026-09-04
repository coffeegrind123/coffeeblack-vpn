//! Secret scrubbing for the MasterDnsVPN child-process log stream.
//!
//! ## Why this exists
//!
//! The pinned upstream server prints the **raw shared encryption key** at
//! INFO on every start (`cmd/server/main.go`):
//!
//! ```text
//! 🔑 Active Encryption Key: deadbeefcafebabe1234567890abcdef
//! ```
//!
//! `supervisor::spawn_log_pump` forwards the child's stdout/stderr verbatim
//! into `tracing`. Without scrubbing, the tunnel's shared secret therefore
//! lands in journald, `docker logs`, and any log shipper attached to
//! coffeeblack-vpn — a direct key-disclosure path for a tool whose entire threat
//! model is a hostile network operator. There is no per-peer secret in
//! MasterDnsVPN: whoever holds this one key can impersonate every peer and
//! decrypt every tunnel, so it is the most sensitive value in the deployment.
//!
//! Upstream's own fork (CottenDNS) fixed this by logging a SHA-256 prefix
//! instead of the key. We cannot patch the vendored ELF, so we scrub at the
//! boundary where its output enters our log stream.
//!
//! ## Two independent axes, because either alone has a gap
//!
//! 1. **By value** — replace the live key wherever it appears, in any ASCII
//!    case. This catches leak paths we have not read: a `%+v` config dump, a
//!    future log line, an error message quoting `encrypt_key.txt`.
//! 2. **By label** — on any line that mentions an encryption key, redact long
//!    hex runs *even when they do not match the key we know about*. This
//!    covers the window where the child is still running with a key that has
//!    already been rotated in the DB, and any key the child reformats or
//!    derives.
//!
//! Neither axis can be dropped: (1) misses stale keys, (2) misses lines that
//! leak the key without naming it.

use std::borrow::Cow;

/// Shortest hex run the label-based pass will redact. Matches
/// `keys::MIN_KEY_HEX_LEN` — anything shorter cannot be a key we would have
/// accepted, and staying at 16 keeps our own 8-char fingerprints readable.
const MIN_HEX_RUN: usize = 16;

/// Substrings that mark a line as "this is about key material". Compared
/// case-insensitively against the whole line.
const KEY_LABELS: &[&str] = &["encryption key", "encrypt_key", "encryption_key"];

/// Scrubs secrets out of one child-process log line.
///
/// Construct one per spawned process — the supervisor re-renders config and
/// re-spawns on every inbound change, so the key a scrubber holds is always
/// the key the child was started with.
#[derive(Debug, Clone)]
pub struct LogScrubber {
    /// The live shared secret, or `None` when the inbound has no key set
    /// (then only the label pass applies).
    key: Option<String>,
    /// What we substitute in. Carries the fingerprint so an operator can
    /// still correlate log lines with a key without seeing the key.
    replacement: String,
}

impl LogScrubber {
    /// Build a scrubber for `key`. A blank/whitespace key yields a scrubber
    /// that still runs the label pass — a key can appear in the child's log
    /// before our DB row has one (e.g. the child read a key file we did not
    /// write), and that is exactly the case worth catching.
    pub fn new(key: &str) -> Self {
        let trimmed = key.trim();
        if trimmed.is_empty() {
            return Self {
                key: None,
                replacement: "<redacted>".to_string(),
            };
        }
        Self {
            key: Some(trimmed.to_string()),
            replacement: format!("<redacted:{}>", super::keys::key_fingerprint(trimmed)),
        }
    }

    /// Scrub one line. Returns `Cow::Borrowed` unchanged when the line holds
    /// no secret, so the common case allocates nothing.
    pub fn scrub<'a>(&self, line: &'a str) -> Cow<'a, str> {
        let mut current: Cow<'a, str> = Cow::Borrowed(line);

        // Axis 1 — by value.
        if let Some(key) = self.key.as_deref() {
            if let Some(replaced) =
                replace_ignore_ascii_case(current.as_ref(), key, &self.replacement)
            {
                current = Cow::Owned(replaced);
            }
        }

        // Axis 2 — by label. Only on lines that advertise key material, so a
        // legitimate long hex value elsewhere (a SHA pin, a peer public key)
        // is left alone.
        if mentions_key_material(current.as_ref()) {
            if let Some(replaced) =
                redact_hex_runs(current.as_ref(), MIN_HEX_RUN, &self.replacement)
            {
                current = Cow::Owned(replaced);
            }
        }

        current
    }
}

/// Case-insensitive check for any of `KEY_LABELS`.
fn mentions_key_material(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    KEY_LABELS.iter().any(|label| lower.contains(label))
}

/// Replace every ASCII-case-insensitive occurrence of `needle` in `haystack`.
/// Returns `None` when there was nothing to replace (so callers can avoid an
/// allocation).
///
/// `needle` is a hex key, i.e. pure ASCII — but `haystack` is arbitrary UTF-8
/// (upstream's log lines are emoji-prefixed), so every candidate offset is
/// char-boundary checked before slicing. Without that guard this panics the
/// log pump on the very lines we care about.
fn replace_ignore_ascii_case(haystack: &str, needle: &str, with: &str) -> Option<String> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let hay = haystack.as_bytes();
    let ned = needle.as_bytes();

    let mut out: Option<String> = None;
    let mut cursor = 0usize;
    let mut copied_to = 0usize;

    while cursor + ned.len() <= hay.len() {
        if !haystack.is_char_boundary(cursor) {
            cursor += 1;
            continue;
        }
        if hay[cursor..cursor + ned.len()].eq_ignore_ascii_case(ned) {
            let buf = out.get_or_insert_with(String::new);
            buf.push_str(&haystack[copied_to..cursor]);
            buf.push_str(with);
            cursor += ned.len();
            copied_to = cursor;
        } else {
            cursor += 1;
        }
    }

    if let Some(buf) = out.as_mut() {
        buf.push_str(&haystack[copied_to..]);
    }
    out
}

/// Replace every maximal run of >= `min_len` ASCII hex digits. Returns `None`
/// when there was no such run.
fn redact_hex_runs(line: &str, min_len: usize, with: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let mut out: Option<String> = None;
    let mut copied_to = 0usize;
    let mut idx = 0usize;

    while idx < bytes.len() {
        if !bytes[idx].is_ascii_hexdigit() {
            idx += 1;
            continue;
        }
        let start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_hexdigit() {
            idx += 1;
        }
        if idx - start >= min_len {
            let buf = out.get_or_insert_with(String::new);
            buf.push_str(&line[copied_to..start]);
            buf.push_str(with);
            copied_to = idx;
        }
    }

    if let Some(buf) = out.as_mut() {
        buf.push_str(&line[copied_to..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "deadbeefcafebabe1234567890abcdef";

    /// The exact line the pinned upstream binary emits. This is the
    /// regression that motivated the module — if it ever passes through
    /// intact, the shared secret is in the operator's log stream again.
    #[test]
    fn redacts_the_real_upstream_startup_line() {
        let s = LogScrubber::new(KEY);
        let line = format!("\u{1F511} Active Encryption Key: {KEY}");
        let got = s.scrub(&line);
        assert!(!got.contains(KEY), "key survived scrubbing: {got}");
        assert!(got.contains("Active Encryption Key"), "label was destroyed: {got}");
        assert!(got.contains("<redacted:"), "no redaction marker: {got}");
        // The emoji prefix must survive — proves we didn't slice mid-char.
        assert!(got.starts_with('\u{1F511}'));
    }

    /// The two key-related lines captured from the *actual* pinned
    /// `vendor/mdnsvpn-linux-amd64.gz` (run with a known key and its stdout
    /// grepped), not reconstructed from source. Line 1 must be neutralised;
    /// line 2 must survive intact, because destroying the key-file path would
    /// cost operators a real diagnostic for no security gain.
    #[test]
    fn handles_the_observed_binary_output_verbatim() {
        let key = "cafebabe0123456789abcdefdeadbeef";
        let s = LogScrubber::new(key);

        let leak = format!(
            "2026/08/07 04:23:08 [MasterDnsVPN Server] [INFO] \u{1F511} Active Encryption Key: {key}"
        );
        let got = s.scrub(&leak);
        assert!(!got.contains(key), "raw key survived: {got}");
        assert!(got.contains("[MasterDnsVPN Server] [INFO]"), "{got}");

        let path_line = "2026/08/07 04:23:08 [MasterDnsVPN Server] [INFO] \u{1F5C2} \
                         Encryption Key Loaded, Path: /etc/coffeeblack/mdnsvpn/encrypt_key.txt";
        assert_eq!(s.scrub(path_line), path_line);
    }

    #[test]
    fn redacts_key_on_a_line_with_no_label_at_all() {
        // Axis 1 alone: an unlabelled leak (config dump, error text).
        let s = LogScrubber::new(KEY);
        let line = format!("cfg dump: {{EncryptionKey:{KEY} UDPPort:53}}");
        let got = s.scrub(&line);
        assert!(!got.contains(KEY));
        assert!(got.contains("UDPPort:53"));
    }

    #[test]
    fn redacts_uppercase_and_mixed_case_spellings() {
        let s = LogScrubber::new(KEY);
        for variant in [KEY.to_ascii_uppercase(), mixed_case(KEY)] {
            let line = format!("key={variant}");
            let got = s.scrub(&line);
            assert!(
                !got.to_ascii_lowercase().contains(KEY),
                "case variant survived: {got}"
            );
        }
    }

    #[test]
    fn redacts_every_occurrence_not_just_the_first() {
        let s = LogScrubber::new(KEY);
        let line = format!("{KEY} middle {KEY} tail {KEY}");
        let got = s.scrub(&line);
        assert!(!got.contains(KEY));
        assert_eq!(got.matches("<redacted:").count(), 3);
        assert!(got.contains("middle") && got.contains("tail"));
    }

    #[test]
    fn label_pass_catches_a_stale_key_we_no_longer_hold() {
        // The DB was rotated to a new key; the still-running child logs the
        // OLD one. Axis 1 cannot match it — axis 2 must.
        let s = LogScrubber::new("00000000000000000000000000000000");
        let stale = "aaaaaaaabbbbbbbbccccccccdddddddd";
        let line = format!("Active Encryption Key: {stale}");
        let got = s.scrub(&line);
        assert!(!got.contains(stale), "stale key survived: {got}");
    }

    #[test]
    fn label_pass_applies_with_no_key_configured() {
        let s = LogScrubber::new("   ");
        let leaked = "0123456789abcdef0123456789abcdef";
        let line = format!("encryption_key loaded: {leaked}");
        let got = s.scrub(&line);
        assert!(!got.contains(leaked));
        assert!(got.contains("<redacted>"));
    }

    #[test]
    fn leaves_ordinary_lines_untouched_and_unallocated() {
        let s = LogScrubber::new(KEY);
        for line in [
            "\u{1F680} Server started on 0.0.0.0:53",
            "session 42 closed after 12.5s",
            "\u{26A0} upstream 1.1.1.1:53 timed out",
        ] {
            let got = s.scrub(line);
            assert!(matches!(got, Cow::Borrowed(_)), "needless allocation: {line}");
            assert_eq!(got, line);
        }
    }

    #[test]
    fn long_hex_outside_a_key_context_is_preserved() {
        // A SHA pin or peer key in an unrelated line must not be mangled —
        // axis 2 is deliberately gated on the label.
        let s = LogScrubber::new(KEY);
        let sha = "aebb7eb879c742135327b147f66e267e";
        let line = format!("verified bundled ELF sha256={sha}");
        assert_eq!(s.scrub(&line), line);
    }

    #[test]
    fn our_own_fingerprint_survives_the_label_pass() {
        // The fingerprint we log is 8 hex chars — below MIN_HEX_RUN — so the
        // label pass must not eat the very affordance it exists to enable.
        let s = LogScrubber::new(KEY);
        let fp = super::super::keys::key_fingerprint(KEY);
        let line = format!("Active Encryption Key Fingerprint: {fp}");
        assert_eq!(s.scrub(&line), line);
    }

    #[test]
    fn key_file_path_line_is_not_mangled() {
        let s = LogScrubber::new(KEY);
        let line = "ENCRYPTION_KEY_FILE = /etc/coffeeblack/mdnsvpn/encrypt_key.txt";
        assert_eq!(s.scrub(line), line);
    }

    #[test]
    fn multibyte_content_around_a_match_is_preserved() {
        let s = LogScrubber::new(KEY);
        let line = format!("\u{1F511}\u{2192}\u{feff} key {KEY} \u{2190}\u{1F510}");
        let got = s.scrub(&line);
        assert!(!got.contains(KEY));
        assert!(got.contains('\u{2192}') && got.contains('\u{1F510}'));
    }

    #[test]
    fn empty_line_is_safe() {
        let s = LogScrubber::new(KEY);
        assert_eq!(s.scrub(""), "");
    }

    #[test]
    fn short_key_shorter_than_min_hex_run_still_redacted_by_value() {
        // Axis 1 is not bounded by MIN_HEX_RUN.
        let s = LogScrubber::new("abcdef0123");
        let got = s.scrub("Active Encryption Key: abcdef0123");
        assert!(!got.contains("abcdef0123"));
    }

    fn mixed_case(s: &str) -> String {
        s.chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect()
    }
}
