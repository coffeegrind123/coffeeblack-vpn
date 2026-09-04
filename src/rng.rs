//! CSPRNG helpers over `getrandom`, replacing the `rand` crate.
//!
//! Every value here comes straight from the OS CSPRNG — the same source
//! `rand::rngs::OsRng` drew from — so there is no userspace PRNG state to seed
//! or reason about. `rand` only earned its place by offering a userspace
//! generator (`rand_chacha` + `ppv-lite86`, plus a second `getrandom`/
//! `rand_core` line) that none of our call sites needed: they were either
//! `OsRng.fill_bytes` (now [`fill`]) or bounded integer draws for AmneziaWG
//! obfuscation parameters (now the unbiased [`range_incl_i64`] /
//! [`range_excl_i64`]). We keep `getrandom` at 0.2 to unify with the version
//! argon2's `password-hash` already pulls, so this adds no new crate.

/// Fill `buf` with cryptographically secure random bytes from the OS.
///
/// Panics only if the OS entropy source is unavailable — the same failure mode
/// as `OsRng.fill_bytes`, and an unrecoverable condition for a VPN key manager
/// (there is no safe fallback: returning predictable bytes would be worse).
pub fn fill(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// A single random byte.
pub fn byte() -> u8 {
    let mut b = [0u8; 1];
    fill(&mut b);
    b[0]
}

/// A uniform `u64` straight from the OS CSPRNG.
fn next_u64() -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b)
}

/// Uniform integer in `[0, bound)` with **no modulo bias**. Rejection
/// sampling: discard the lowest `2^64 mod bound` outputs so the surviving
/// range is an exact multiple of `bound`, making `% bound` uniform. `bound`
/// must be non-zero.
fn u64_below(bound: u64) -> u64 {
    assert!(bound > 0, "u64_below bound must be non-zero");
    // `bound.wrapping_neg()` is `2^64 - bound`; `(2^64 - bound) % bound` equals
    // `2^64 % bound` — the exact size of the biased bottom zone to reject.
    let reject_below = bound.wrapping_neg() % bound;
    loop {
        let x = next_u64();
        if x >= reject_below {
            return x % bound;
        }
    }
}

/// Uniform `i64` in the inclusive range `[lo, hi]`. Requires `lo <= hi`.
/// Replaces `rand`'s `gen_range(lo..=hi)`.
pub fn range_incl_i64(lo: i64, hi: i64) -> i64 {
    assert!(lo <= hi, "range_incl_i64 requires lo <= hi");
    // span = hi - lo + 1, in i128 so the full i64 range can't overflow.
    let span = (i128::from(hi) - i128::from(lo) + 1) as u64;
    lo + u64_below(span) as i64
}

/// Uniform `i64` in the half-open range `[lo, hi)`. Requires `lo < hi`.
/// Replaces `rand`'s `gen_range(lo..hi)`.
pub fn range_excl_i64(lo: i64, hi: i64) -> i64 {
    assert!(lo < hi, "range_excl_i64 requires lo < hi");
    let span = (i128::from(hi) - i128::from(lo)) as u64;
    lo + u64_below(span) as i64
}

/// A random UUID v4, in the canonical hyphenated lowercase form.
///
/// Replaces the `uuid` crate, whose entire contribution here was 16 random
/// bytes, six fixed bits, and a hyphen layout — all of which are RFC 4122
/// §4.4 in full. The bytes come from the same OS CSPRNG as every other secret
/// in the project, so the version/variant nibbles are the only structure.
pub fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    fill(&mut b);
    // Version 4 in the high nibble of byte 6, RFC 4122 variant (0b10) in the
    // top two bits of byte 8.
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = crate::encoding::hex_encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_touches_every_byte_position() {
        // Two 64-byte draws should differ with overwhelming probability; a
        // no-op fill (all zeros) would make them equal.
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        fill(&mut a);
        fill(&mut b);
        assert_ne!(a, b, "two CSPRNG draws must not collide");
        assert!(a.iter().any(|&x| x != 0), "draw must not be all zeros");
    }

    #[test]
    fn range_incl_stays_in_bounds_and_hits_both_ends() {
        let (lo, hi) = (4i64, 12i64);
        let mut saw_lo = false;
        let mut saw_hi = false;
        for _ in 0..10_000 {
            let v = range_incl_i64(lo, hi);
            assert!((lo..=hi).contains(&v), "out of range: {v}");
            saw_lo |= v == lo;
            saw_hi |= v == hi;
        }
        assert!(saw_lo && saw_hi, "inclusive endpoints must both be reachable");
    }

    #[test]
    fn range_excl_never_returns_hi() {
        let (lo, hi) = (5i64, 8i64);
        for _ in 0..10_000 {
            let v = range_excl_i64(lo, hi);
            assert!(v >= lo && v < hi, "out of range: {v}");
        }
    }

    #[test]
    fn range_incl_singleton() {
        assert_eq!(range_incl_i64(7, 7), 7);
    }

    #[test]
    fn u64_below_is_roughly_uniform() {
        // Chi-square-free sanity: every bucket of a small modulus is hit over
        // enough draws, and none exceeds the bound.
        const B: u64 = 6;
        let mut counts = [0u32; B as usize];
        for _ in 0..60_000 {
            let x = u64_below(B);
            counts[x as usize] += 1;
        }
        for (i, &c) in counts.iter().enumerate() {
            // Expected ~10_000 each; a bucket never hit (or wildly off) would
            // signal a bias or a stuck bit.
            assert!(c > 8_000 && c < 12_000, "bucket {i} skewed: {c}");
        }
    }

    #[test]
    fn large_exclusive_range_matches_cb_h_window() {
        // The magic-header window uses 5..2_147_483_647; ensure the i128 span
        // math holds and outputs stay inside.
        const H_MIN: i64 = 5;
        const H_MAX: i64 = 2_147_483_647;
        for _ in 0..10_000 {
            let v = range_excl_i64(H_MIN, H_MAX);
            assert!((H_MIN..H_MAX).contains(&v));
        }
    }

    #[test]
    fn uuid_v4_has_the_rfc_4122_shape() {
        let u = uuid_v4();
        assert_eq!(u.len(), 36);
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(u.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        assert!(u.chars().all(|c| !c.is_ascii_uppercase()));
        // Version nibble and variant bits are the only non-random structure.
        assert_eq!(parts[2].as_bytes()[0], b'4', "version 4");
        assert!(
            matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'),
            "RFC 4122 variant, got {}",
            parts[3]
        );
    }

    #[test]
    fn uuid_v4_values_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            assert!(seen.insert(uuid_v4()), "UUID repeated");
        }
    }
}
