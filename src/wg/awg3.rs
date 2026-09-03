//! AmneziaWG 3 device knobs: value grammar, capability probing, and the
//! interlock with the DPI-imitation proxy.
//!
//! AWG 3 adds nine `[Interface]` keys on top of the 2.x junk/magic-header
//! set — header protection, content padding, five timer overrides, random
//! trailers and a cookie switch. Everything here is **additive and inert
//! when unset**: no key is emitted unless the operator sets it, and the
//! AWG 3 binaries treat an absent key as "off", so an upgraded deployment's
//! wire format is unchanged until someone opts in.
//!
//! ## Where the rules come from
//!
//! Not from the upstream README — from the parsers, because the README is
//! looser than the code in two places that matter:
//!
//! - **Ranges** (`ContentPaddingAddition`, the timers) are parsed by
//!   `u16_range_from_string` in `amneziawg-tools/src/type.c` as `lo` or
//!   `lo-hi`, decimal, `hi >= lo`. It accepts values up to `UINT32_MAX`
//!   and then *silently truncates* them into a `uint16_t` — `70000`
//!   becomes `4464` with no diagnostic. So the 0–65535 bound is enforced
//!   here rather than left to the tools.
//! - **Header protection** requires **all four** of S1–S4 to be at least
//!   12: the padding doubles as the cipher nonce, and
//!   `amneziawg-go/device/uapi.go` rejects the device with `S%d must be
//!   more then 12 to use headerProtection` otherwise. Enforcing it at the
//!   API means the operator gets a 400 instead of an interface that
//!   refuses to come up.
//!
//! Booleans are `on`/`off` (also `0`/`1`, per `parse_bool` in `config.c`);
//! we always render `on`/`off`.
//!
//! ## Interlock with the DPI-imitation proxy
//!
//! Two of the nine change the *shape* of the datagrams the proxy in
//! `src/proxy/` parses, and cannot be used together with it — see
//! [`proxy_conflict`] for the mechanism in each case.

use anyhow::{anyhow, Result};
use base64::Engine;

/// Every AWG 3 range-valued key, as `(db column, config key)`. The order is
/// the order they are rendered in.
pub const RANGE_FIELDS: &[(&str, &str)] = &[
    ("content_padding_addition", "ContentPaddingAddition"),
    ("rekey_after_time", "RekeyAfterTime"),
    ("rekey_timeout", "RekeyTimeout"),
    ("reject_after_time", "RejectAfterTime"),
    ("keepalive_timeout", "KeepaliveTimeout"),
    ("max_handshake_attempts", "MaxHandshakeAttempts"),
];

/// Nonce size of the header-protection cipher, and therefore the minimum
/// every S1–S4 padding must reach before header protection can be enabled
/// (`amneziawg-go/device/noise-types.go: HeaderCipherNonceSize`).
pub const HEADER_PROTECTION_MIN_S: i64 = 12;

/// Validate one range-valued AWG 3 field: `n` or `lo-hi`, decimal, each
/// side within `u16`, `hi >= lo`. Empty is valid and means "unset".
///
/// `name` is the config key, used only in the error text.
pub fn validate_range(name: &str, value: &str) -> Result<()> {
    let v = value.trim();
    if v.is_empty() {
        return Ok(());
    }
    let bad = || {
        anyhow!(
            "{name} must be a number or a `lo-hi` range, each side 0-65535 \
             with hi >= lo (got {v:?})"
        )
    };
    let (lo_s, hi_s) = match v.split_once('-') {
        Some((lo, hi)) => (lo, hi),
        None => (v, v),
    };
    // Reject anything strtoul would have skipped or ignored: leading signs,
    // whitespace, or trailing text. The tools stop at the first non-digit
    // and use whatever prefix they parsed, so `12abc` would otherwise
    // become 12 on one side of the wire and an error on the other.
    if lo_s.is_empty()
        || hi_s.is_empty()
        || !lo_s.bytes().all(|b| b.is_ascii_digit())
        || !hi_s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(bad());
    }
    let lo: u32 = lo_s.parse().map_err(|_| bad())?;
    let hi: u32 = hi_s.parse().map_err(|_| bad())?;
    if lo > u16::MAX as u32 || hi > u16::MAX as u32 || hi < lo {
        return Err(bad());
    }
    Ok(())
}

/// Validate a header-protection key: standard base64 of exactly 32 bytes,
/// the same shape as every other AmneziaWG key (`parse_key` in
/// `amneziawg-tools/src/config.c`). Empty is valid and means "disabled".
pub fn validate_header_protection_key(value: &str) -> Result<()> {
    let v = value.trim();
    if v.is_empty() {
        return Ok(());
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(v)
        .map_err(|_| anyhow!("headerProtectionKey must be base64 (44 chars, like `awg genkey`)"))?;
    if raw.len() != 32 {
        return Err(anyhow!(
            "headerProtectionKey must decode to 32 bytes, got {}",
            raw.len()
        ));
    }
    Ok(())
}

/// Generate a fresh header-protection key.
///
/// 32 bytes from the same CSPRNG the rest of the project draws keys from,
/// base64-encoded. Deliberately not shelled out to `awg genkey`: that
/// clamps the value into an X25519 scalar, which is right for a
/// Diffie-Hellman private key and meaningless for a symmetric cipher key —
/// it would just throw away a few bits of entropy.
pub fn generate_header_protection_key() -> String {
    let mut raw = [0u8; 32];
    crate::rng::fill(&mut raw);
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// Check the S1–S4 precondition for header protection.
///
/// All four paddings must be >= [`HEADER_PROTECTION_MIN_S`]. `s3`/`s4` are
/// `Option` in the DB and an unset one renders no line at all, which the
/// device reads as 0 — so "unset" fails this check just as a small value
/// would, and the error says so.
pub fn check_header_protection_paddings(
    s1: i64,
    s2: i64,
    s3: Option<i64>,
    s4: Option<i64>,
) -> Result<()> {
    let min = HEADER_PROTECTION_MIN_S;
    let mut too_small = Vec::new();
    for (name, val) in [
        ("S1", Some(s1)),
        ("S2", Some(s2)),
        ("S3", s3),
        ("S4", s4),
    ] {
        match val {
            Some(v) if v >= min => {}
            Some(v) => too_small.push(format!("{name}={v}")),
            None => too_small.push(format!("{name}=unset")),
        }
    }
    if too_small.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "header protection needs every S padding to be at least {min} \
         (it doubles as the cipher nonce); {} — raise them or leave header \
         protection off",
        too_small.join(", ")
    ))
}

/// Which AWG 3 knobs cannot be combined with the DPI-imitation proxy, and
/// why. Returns `None` when the interface's AWG 3 settings are compatible.
///
/// Both conflicts are structural, not policy:
///
/// - **`HeaderProtectionKey`** — the cipher's nonce is the first 12 bytes
///   of the S-padding, and the proxy *rewrites* that padding to imitate
///   QUIC/DNS/STUN/SIP. The far end would derive a different keystream and
///   drop every packet. The header the proxy classifies on is ciphertext
///   under this key as well, so it could not read it even if the nonce
///   survived.
/// - **`RandomTrailers`** — the proxy identifies handshake packets by an
///   exact total length (`S + 148` for an initiation, and so on, in
///   `proxy/responder.rs::classify_awg_packet`). A random trailer breaks
///   that equality, so handshakes stop being recognised as AmneziaWG and
///   get answered as if they were probes.
///
/// The rest are safe: content padding only grows data packets, which are
/// classified by a *minimum* size, and the timers and cookie switch don't
/// change packet shape at all.
pub fn proxy_conflict(header_protection_key: &str, random_trailers: bool) -> Option<&'static str> {
    if !header_protection_key.trim().is_empty() {
        return Some(
            "header protection cannot be combined with the DPI-imitation proxy: \
             the proxy rewrites the S1-S4 padding that the header cipher uses as \
             its nonce, so the peer would derive a different keystream and drop \
             every packet",
        );
    }
    if random_trailers {
        return Some(
            "random trailers cannot be combined with the DPI-imitation proxy: \
             the proxy recognises AmneziaWG handshakes by their exact length, \
             and a random trailer makes them look like unauthenticated probes",
        );
    }
    None
}

/// Whether the installed `awg` understands the AWG 3 keys.
///
/// Probed from `awg --version`, which prints e.g.
/// `amneziawg-tools v3.1.20260812 - https://amnezia.org`. Anything below
/// major 3 predates these keys and would abort with a parse error on the
/// first unknown one, taking the whole interface down — so the admin API
/// surfaces this and the UI gates the section on it.
///
/// `None` means "couldn't tell" (no `awg` on PATH, unparseable output):
/// the UI shows the section without a positive confirmation, and nothing
/// is blocked, because refusing to configure on a failed probe would be
/// worse than letting an operator who knows their deployment proceed.
pub fn tools_support_awg3() -> Option<bool> {
    let out = crate::wg::cli::run("awg", &["--version"]).ok()?;
    parse_major_version(&out).map(|major| major >= 3)
}

/// Pull the major version out of an `awg --version` line.
pub(crate) fn parse_major_version(line: &str) -> Option<u32> {
    // "amneziawg-tools v3.1.20260812 - https://amnezia.org"
    let token = line.split_whitespace().find(|t| {
        t.starts_with('v') && t.len() > 1 && t[1..].starts_with(|c: char| c.is_ascii_digit())
    })?;
    token[1..]
        .split('.')
        .next()?
        .parse::<u32>()
        .ok()
}

/// Render the AWG 3 `[Interface]` lines for a device, in a stable order.
///
/// Returns an empty vector when nothing is set, which is the normal case —
/// the caller appends these to the AWG 2 lines and emits nothing extra.
pub fn config_lines(
    header_protection_key: &str,
    ranges: &[(&str, &str)],
    random_trailers: bool,
    disable_cookies: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let hpk = header_protection_key.trim();
    if !hpk.is_empty() {
        out.push(format!("HeaderProtectionKey = {hpk}"));
    }
    for (key, value) in ranges {
        let v = value.trim();
        if !v.is_empty() {
            out.push(format!("{key} = {v}"));
        }
    }
    // Only rendered when true: `off` is the device default, and emitting it
    // would make an AWG 2 tool choke on a line that changes nothing.
    if random_trailers {
        out.push("RandomTrailers = on".to_string());
    }
    if disable_cookies {
        out.push("DisableCookies = on".to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_accept_single_values_and_ordered_pairs() {
        for ok in ["", "0", "22", "65535", "22-30", "5-5", "0-65535"] {
            validate_range("X", ok).unwrap_or_else(|e| panic!("{ok:?} should parse: {e}"));
        }
    }

    #[test]
    fn ranges_reject_what_the_tools_would_silently_mangle() {
        // Above u16 the tools truncate into uint16_t without a word:
        // 70000 would land as 4464 on the wire.
        assert!(validate_range("X", "70000").is_err());
        assert!(validate_range("X", "0-70000").is_err());
        // strtoul stops at the first non-digit, so a typo'd value would be
        // silently accepted as its numeric prefix.
        assert!(validate_range("X", "12abc").is_err());
        assert!(validate_range("X", "0x10").is_err());
        // Reversed and malformed ranges.
        assert!(validate_range("X", "30-22").is_err());
        assert!(validate_range("X", "-5").is_err());
        assert!(validate_range("X", "5-").is_err());
        assert!(validate_range("X", "1-2-3").is_err());
        assert!(validate_range("X", " 5").is_ok(), "outer trim is fine");
    }

    #[test]
    fn header_protection_key_must_be_32_bytes_of_base64() {
        let k = generate_header_protection_key();
        validate_header_protection_key(&k).unwrap();
        assert_eq!(k.len(), 44, "32 bytes base64 is 44 chars");
        validate_header_protection_key("").unwrap();
        assert!(validate_header_protection_key("not base64!").is_err());
        // 16 bytes, valid base64, wrong length.
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(validate_header_protection_key(&short).is_err());
    }

    #[test]
    fn generated_keys_are_not_constant() {
        let a = generate_header_protection_key();
        let b = generate_header_protection_key();
        assert_ne!(a, b);
    }

    #[test]
    fn header_protection_requires_all_four_paddings_at_twelve() {
        check_header_protection_paddings(12, 12, Some(12), Some(12)).unwrap();
        check_header_protection_paddings(128, 56, Some(1000), Some(32)).unwrap();

        // An unset S3/S4 renders no line, which the device reads as 0.
        let e = check_header_protection_paddings(128, 56, None, Some(32)).unwrap_err();
        assert!(e.to_string().contains("S3=unset"), "{e}");
        let e = check_header_protection_paddings(11, 56, Some(20), Some(20)).unwrap_err();
        assert!(e.to_string().contains("S1=11"), "{e}");
        // Every offender is named, not just the first.
        let e = check_header_protection_paddings(1, 2, Some(3), Some(4)).unwrap_err();
        for want in ["S1=1", "S2=2", "S3=3", "S4=4"] {
            assert!(e.to_string().contains(want), "{want} missing from {e}");
        }
    }

    #[test]
    fn proxy_conflicts_name_the_incompatible_knob() {
        assert!(proxy_conflict("", false).is_none());
        // Compatible knobs don't trip it.
        assert!(proxy_conflict("", false).is_none());
        let k = generate_header_protection_key();
        assert!(proxy_conflict(&k, false).unwrap().contains("header protection"));
        assert!(proxy_conflict("", true).unwrap().contains("random trailers"));
        // Whitespace-only key is "unset", not a conflict.
        assert!(proxy_conflict("   ", false).is_none());
    }

    #[test]
    fn version_probe_reads_the_upstream_banner() {
        assert_eq!(
            parse_major_version("amneziawg-tools v3.1.20260812 - https://amnezia.org"),
            Some(3)
        );
        assert_eq!(
            parse_major_version("amneziawg-tools v1.0.20260618-2 - https://amnezia.org"),
            Some(1)
        );
        assert_eq!(parse_major_version("wireguard-tools v1.0.20210914"), Some(1));
        assert_eq!(parse_major_version("something unparseable"), None);
        assert_eq!(parse_major_version(""), None);
    }

    #[test]
    fn config_lines_render_only_what_is_set() {
        assert!(config_lines("", &[], false, false).is_empty());

        let lines = config_lines(
            "KEY==",
            &[
                ("ContentPaddingAddition", "10-20"),
                ("RekeyAfterTime", ""),
                ("RekeyTimeout", "5"),
            ],
            true,
            true,
        );
        assert_eq!(
            lines,
            vec![
                "HeaderProtectionKey = KEY==",
                "ContentPaddingAddition = 10-20",
                "RekeyTimeout = 5",
                "RandomTrailers = on",
                "DisableCookies = on",
            ]
        );
        // `off` is the device default and is never emitted — an AWG 2 tool
        // would abort on the unknown key for no gain.
        let lines = config_lines("", &[], false, false);
        assert!(!lines.iter().any(|l| l.contains("off")));
    }
}
