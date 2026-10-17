//! Credential generation for TrustTunnel users.

use crate::trusttunnel::config::{USERNAME_MAX, validate_password};

/// Alphabet for generated passwords: alphanumerics only, so a password
/// survives the endpoint's credentials parser, URL query strings, QR codes
/// and copy-paste unchanged.
const PASSWORD_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// 32 characters of a 62-symbol alphabet ≈ 190 bits.
pub const PASSWORD_LEN: usize = 32;

/// Bytes in a generated client-random prefix. Upstream's
/// `--generate-client-random-prefix` defaults to 4.
pub const PREFIX_BYTES: usize = 4;

/// Share of prefix bits fixed by the mask. Upstream defaults to 70 %; the
/// unmasked bits stay random per connection, so the ClientHello random is
/// not a constant an observer could match across sessions.
const PREFIX_MASK_PERCENT: u32 = 70;

pub fn generate_password() -> String {
    // Rejection sampling: 248 is the largest multiple of 62 below 256, so
    // every symbol is equally likely.
    let mut out = String::with_capacity(PASSWORD_LEN);
    while out.len() < PASSWORD_LEN {
        let b = crate::rng::byte();
        if b < 248 {
            out.push(PASSWORD_ALPHABET[(b % 62) as usize] as char);
        }
    }
    debug_assert!(validate_password(&out).is_ok());
    out
}

/// Derive a username from a display name: lowercase ASCII alphanumerics,
/// other runs collapsed to `-`. Falls back to `user` when nothing survives.
/// The caller makes it unique.
pub fn username_from_name(name: &str) -> String {
    let mut out = String::new();
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let mut out = out.trim_end_matches('-').to_string();
    // Leave room for a `-NN` uniqueness suffix.
    out.truncate(USERNAME_MAX - 4);
    let out = out.trim_end_matches('-').to_string();
    if out.is_empty() {
        "user".to_string()
    } else {
        out
    }
}

/// A fresh `prefix/mask` pair in the `rules.toml` / deep-link syntax.
pub fn generate_client_random_prefix() -> String {
    let mut prefix = [0u8; PREFIX_BYTES];
    crate::rng::fill(&mut prefix);
    let mut mask = [0u8; PREFIX_BYTES];
    for byte in mask.iter_mut() {
        for bit in 0..8 {
            if (crate::rng::byte() as u32 * 100) / 256 < PREFIX_MASK_PERCENT {
                *byte |= 1 << bit;
            }
        }
    }
    // An all-zero mask matches every ClientHello and would make the rule
    // meaningless; pin the top bit.
    if mask.iter().all(|b| *b == 0) {
        mask[0] = 0x80;
    }
    for (p, m) in prefix.iter_mut().zip(mask.iter()) {
        *p &= *m;
    }
    format!(
        "{}/{}",
        crate::encoding::hex_encode(prefix),
        crate::encoding::hex_encode(mask)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusttunnel::config::{validate_client_random_prefix, validate_username};

    #[test]
    fn passwords_are_valid_and_distinct() {
        let a = generate_password();
        let b = generate_password();
        assert_eq!(a.len(), PASSWORD_LEN);
        assert!(validate_password(&a).is_ok());
        assert!(a.bytes().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b);
    }

    #[test]
    fn usernames_are_slugged() {
        assert_eq!(username_from_name("Alice's Phone"), "alice-s-phone");
        assert_eq!(username_from_name("  --  "), "user");
        assert_eq!(username_from_name("Ünïcode Ok"), "n-code-ok");
        let long = username_from_name(&"x".repeat(200));
        assert!(long.len() <= USERNAME_MAX - 4);
        for n in ["Alice's Phone", "", "a.b", "日本"] {
            assert!(validate_username(&username_from_name(n)).is_ok(), "{n}");
        }
    }

    #[test]
    fn prefixes_validate_and_respect_their_mask() {
        for _ in 0..64 {
            let p = generate_client_random_prefix();
            validate_client_random_prefix(&p).unwrap();
            let (prefix, mask) = p.split_once('/').unwrap();
            let prefix = crate::encoding::hex_decode(prefix).unwrap();
            let mask = crate::encoding::hex_decode(mask).unwrap();
            assert_eq!(prefix.len(), PREFIX_BYTES);
            assert!(mask.iter().any(|b| *b != 0));
            assert!(prefix.iter().zip(&mask).all(|(p, m)| p & !m == 0));
        }
    }
}
