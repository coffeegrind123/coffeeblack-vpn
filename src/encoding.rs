//! Hex and Base64 codecs.
//!
//! Both replace crates that earned their place only by doing a few dozen lines
//! of work each:
//!
//! * `hex` — every call site was `hex::encode` over a digest or a random token;
//!   the sole decoder lives in the QQ-DNS parity test. Encoding is a two-nibble
//!   table lookup, so the crate bought nothing a `const` table doesn't.
//! * `base64` — replaced by `base64ct`, which is already compiled into the
//!   binary (argon2 → password-hash uses it for PHC strings). Its `Encoding`
//!   trait is constant-time and rejects non-canonical trailing bits, which is
//!   the behaviour we want for WireGuard keys and stored ciphertext alike.
//!   The wrappers here keep the call sites free of the trait import.

use base64ct::{Base64, Encoding as _};

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex encoding of `bytes`.
pub fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_LOWER[(b >> 4) as usize] as char);
        out.push(HEX_LOWER[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a hex string. Accepts either case; rejects odd lengths and any
/// non-hex byte. Returns `None` rather than an error type — every caller
/// treats a malformed input as "not a hex string" and nothing more.
pub fn hex_decode(s: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let s = s.as_ref();
    if s.len() % 2 != 0 {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(s.len() / 2);
    for [hi, lo] in s.as_chunks::<2>().0 {
        out.push((nibble(*hi)? << 4) | nibble(*lo)?);
    }
    Some(out)
}

/// Standard (padded, `+/`) Base64 encoding — the alphabet WireGuard keys,
/// the Reality key material, and our AES-GCM blobs all use.
pub fn b64_encode(bytes: impl AsRef<[u8]>) -> String {
    Base64::encode_string(bytes.as_ref())
}

/// Decode standard padded Base64. `None` on any malformed input, including
/// non-canonical trailing bits — a stricter reading than the `base64` crate's
/// default engine, and the correct one for fixed-width key material.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    Base64::decode_vec(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let s = hex_encode(&bytes);
        assert_eq!(s.len(), 512);
        assert!(s.starts_with("000102"));
        assert!(s.ends_with("fdfeff"));
        assert_eq!(hex_decode(&s).unwrap(), bytes);
    }

    #[test]
    fn hex_encode_matches_known_vectors() {
        assert_eq!(hex_encode([]), "");
        assert_eq!(hex_encode([0x00]), "00");
        assert_eq!(hex_encode([0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(b"abc"), "616263");
    }

    #[test]
    fn hex_decode_rejects_malformed() {
        assert!(hex_decode("abc").is_none(), "odd length");
        assert!(hex_decode("zz").is_none(), "non-hex byte");
        assert!(hex_decode("de ad").is_none(), "embedded space");
        assert_eq!(hex_decode("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn b64_round_trip_and_vectors() {
        // RFC 4648 test vectors.
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        for v in ["", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"] {
            assert_eq!(b64_encode(b64_decode(v).unwrap()), v);
        }
    }

    #[test]
    fn b64_decode_rejects_malformed() {
        assert!(b64_decode("Zg=").is_none(), "bad padding");
        assert!(b64_decode("Zm9v!").is_none(), "invalid character");
        assert!(b64_decode("Zh==").is_none(), "non-canonical trailing bits");
    }

    #[test]
    fn b64_handles_a_wireguard_sized_key() {
        let key = [0x42u8; 32];
        let s = b64_encode(key);
        assert_eq!(s.len(), 44);
        assert!(s.ends_with('='));
        assert_eq!(b64_decode(&s).unwrap(), key);
    }
}
