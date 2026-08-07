//! Byte-exact port of QQ-Tunnel's `utility/base32.py` + `data_cap.py`.
//!
//! This is the wire codec that turns a raw UDP datagram into a list of
//! DNS-label-encoded QNAMEs (one per fragment) and back again. Every
//! function here is a faithful reimplementation of the upstream Python so
//! that this Rust engine interoperates with the reference client/server on
//! the wire; the parity is pinned by `tests/qqdns_parity.rs`, which replays
//! `tests/qqdns_vectors.json` (produced directly from the Python).
//!
//! Layout of one fragment's data labels, before the send-domain suffix is
//! appended (all characters are lowercase base32, `a-z2-7`):
//!
//! ```text
//! [ data_offset : DATA_OFFSET_WIDTH chars ][ frag char : 1 ][ magic : 1 ][ chunk base32 data … ]
//! ```
//!
//! * `data_offset` — per-datagram id (round-robins mod `2^(5*WIDTH)`), the
//!   reassembly key.
//! * `frag char` — low 5 bits of the fragment index (`i & 31`).
//! * `magic` — encodes bit 5 of the fragment index and the last-fragment
//!   flag: `0`=more/lo, `1`=last/lo, `8`=more/hi, `9`=last/hi.
//! * `chunk` — a slice of the whole datagram's base32 encoding.
//!
//! The label string above is then split into ≤`max_sub_len` DNS labels and
//! the send-domain's wire-encoded QNAME is appended (see [`crate::qqdns::dns`]).

use crate::qqdns::dns::insert_dots;

/// Lowercase RFC 4648 base32 alphabet — matches Python `BASE32_LIST_LOWER`
/// and the lowercased output of `base64.b32encode`.
pub const B32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Width (in base32 chars) of the per-datagram offset field. Upstream
/// `DATA_OFFSET_WIDTH = 3`, giving a `2^15` offset space.
pub const DATA_OFFSET_WIDTH: usize = 3;

/// Total offset space (`1 << (5 * DATA_OFFSET_WIDTH)`), i.e. the modulus the
/// per-datagram offset counter wraps at and the size of the reassembly table.
pub const TOTAL_DATA_OFFSET: u32 = 1 << (5 * DATA_OFFSET_WIDTH as u32);

/// Reverse lookup for base32 decode; `-1` for non-alphabet bytes. Accepts
/// both cases (matches Python `casefold=True` / the mixed BASE32_LOOKUP).
fn b32_value(c: u8) -> i8 {
    match c {
        b'a'..=b'z' => (c - b'a') as i8,
        b'A'..=b'Z' => (c - b'A') as i8,
        b'2'..=b'7' => (c - b'2' + 26) as i8,
        _ => -1,
    }
}

/// Port of `b32encode_nopad_lower`: standard RFC 4648 base32, padding
/// stripped, lowercase.
pub fn b32_encode_nopad_lower(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(5) * 8);
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        bits = (bits << 8) | u64::from(b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(B32_ALPHABET[((bits >> nbits) & 0x1f) as usize]);
        }
    }
    if nbits > 0 {
        // Left-align the remaining bits into a final 5-bit group, matching
        // standard base32's treatment of the last partial group.
        out.push(B32_ALPHABET[((bits << (5 - nbits)) & 0x1f) as usize]);
    }
    out
}

/// Port of `b32decode_nopad`: decode a padding-free base32 string,
/// case-insensitively. Errors on any non-alphabet byte.
pub fn b32_decode_nopad(s: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8 + 1);
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;
    for &c in s {
        let v = b32_value(c);
        if v < 0 {
            return Err(CodecError::InvalidBase32(c));
        }
        bits = (bits << 5) | v as u64;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    // Leftover (<8) bits are zero-padding of a well-formed encoding; drop.
    Ok(out)
}

/// Port of `number_to_base32_lower`.
pub fn number_to_base32_lower(mut n: u32, width: usize) -> Vec<u8> {
    let mut result = vec![0u8; width];
    for i in (0..width).rev() {
        result[i] = B32_ALPHABET[(n & 31) as usize];
        n >>= 5;
    }
    result
}

/// Port of `base32_to_number`. Errors on any non-alphabet byte.
pub fn base32_to_number(s: &[u8]) -> Result<u32, CodecError> {
    let mut value: u32 = 0;
    for &c in s {
        let v = b32_value(c);
        if v < 0 {
            return Err(CodecError::InvalidBase32(c));
        }
        value = (value << 5) + v as u32;
    }
    Ok(value)
}

/// Port of `compute_max_m`: maximum `m` such that `m + ceil(m/s) <= max_allowed`.
/// Uses signed arithmetic to mirror the Python (inputs can go negative).
pub fn compute_max_m(s: i64, max_allowed: i64) -> i64 {
    if max_allowed <= 0 {
        return 0;
    }
    let q = max_allowed / (s + 1);
    let remaining = max_allowed - q * (s + 1);
    let r = (remaining - 1).max(0);
    q * s + r
}

/// Port of `get_chunk_len`: how many base32 data chars fit in one QNAME
/// alongside the send-domain suffix and the 5-char per-fragment header
/// (`DATA_OFFSET_WIDTH` offset chars + 1 frag char + 1 magic char).
pub fn get_chunk_len(
    max_encoded_domain_len: i64,
    qname_encoded_len: i64,
    max_sub_len: i64,
    data_offset_width: i64,
) -> Result<usize, CodecError> {
    let max_allowed = max_encoded_domain_len - qname_encoded_len;
    let m = compute_max_m(max_sub_len, max_allowed);
    let chunk_len = m - data_offset_width - 2; // fragment_part_width is 2
    if chunk_len <= 0 {
        return Err(CodecError::DomainTooSmall);
    }
    Ok(chunk_len as usize)
}

/// A send domain paired with the chunk length it can carry — the Rust
/// analogue of `send_doms_with_chunk_len_list` entries. `qname_encoded` is
/// the wire-encoded QNAME (length-prefixed labels ending in `\x00`).
#[derive(Clone, Debug)]
pub struct SendDomain {
    pub qname_encoded: Vec<u8>,
    pub chunk_len: usize,
}

/// Port of `get_base32_final_domains`.
///
/// Encodes `data` to base32, splits it across as many fragments as needed
/// (round-robining `send_domains`), prepends each fragment's 5-char header,
/// dot-segments it into DNS labels, and appends the send domain's QNAME.
/// Returns the wire-encoded QNAME bytes for each fragment.
///
/// Mirrors the upstream 64-fragment ceiling: a datagram whose base32 form
/// needs more than 64 fragments for the configured `max_domain_len` is
/// dropped (empty return), matching the reference client.
#[allow(clippy::too_many_arguments)]
pub fn get_base32_final_domains(
    data: &[u8],
    data_offset: u32,
    mut send_domain_idx: usize,
    send_domains: &[SendDomain],
    max_sub_len: usize,
    data_offset_width: usize,
    max_encoded_domain_len: usize,
) -> Vec<Vec<u8>> {
    let data = b32_encode_nopad_lower(data);
    let len_data = data.len();
    let data_offset_bytes = number_to_base32_lower(data_offset, data_offset_width);

    let mut final_domains: Vec<Vec<u8>> = Vec::new();
    let mut i: usize = 0;
    let mut s_index: usize = 0;
    let mut c_loop = true;

    while c_loop {
        if i == 64 {
            // max_domain_len too small for this datagram — drop it.
            return Vec::new();
        }
        let sd = &send_domains[send_domain_idx];
        send_domain_idx = (send_domain_idx + 1) % send_domains.len();

        let end = (s_index + sd.chunk_len).min(len_data);
        let chunk_slice = &data[s_index..end];
        s_index += sd.chunk_len;

        // Header: offset(width) + frag char + magic char.
        let frag_char = B32_ALPHABET[i & 31];
        let magic: u8 = if s_index < len_data {
            // more fragments follow
            if i & 32 != 0 {
                b'8'
            } else {
                b'0'
            }
        } else {
            c_loop = false;
            if i & 32 != 0 {
                b'9'
            } else {
                b'1'
            }
        };

        let mut labeled = Vec::with_capacity(data_offset_width + 2 + chunk_slice.len());
        labeled.extend_from_slice(&data_offset_bytes);
        labeled.push(frag_char);
        labeled.push(magic);
        labeled.extend_from_slice(chunk_slice);

        // Dot-segment into DNS labels, then append the send-domain QNAME.
        let mut final_domain = insert_dots(&labeled, max_sub_len);
        final_domain.extend_from_slice(&sd.qname_encoded);

        debug_assert!(
            final_domain.len() <= max_encoded_domain_len,
            "final domain exceeds max_encoded_domain_len"
        );
        let _ = max_encoded_domain_len;

        final_domains.push(final_domain);
        i += 1;
    }

    final_domains
}

/// One fragment's decoded header + payload, from [`get_chunk_data`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkData {
    pub data_offset: u32,
    pub fragment_part: usize,
    pub last_fragment: bool,
    /// The base32 payload of this fragment (still encoded — decoded only
    /// after the whole datagram is reassembled).
    pub chunk: Vec<u8>,
}

/// Port of `get_chunk_data`. `data` is the concatenation of the received
/// QNAME's labels (the send-domain suffix already stripped), i.e. the
/// dot-free `offset|frag|magic|chunk` byte string.
pub fn get_chunk_data(data: &[u8], data_offset_width: usize) -> Result<ChunkData, CodecError> {
    if data.len() < data_offset_width + 2 {
        return Err(CodecError::ShortHeader);
    }
    let data_offset = base32_to_number(&data[..data_offset_width])?;

    let frag_raw = b32_value(data[data_offset_width]);
    if frag_raw < 0 {
        return Err(CodecError::InvalidBase32(data[data_offset_width]));
    }
    let frag_raw = frag_raw as usize;

    let magic = data[data_offset_width + 1];
    let (fragment_part, last_fragment) = match magic {
        b'0' => (frag_raw, false),
        b'1' => (frag_raw, true),
        b'8' => (frag_raw | 32, false),
        b'9' => (frag_raw | 32, true),
        _ => return Err(CodecError::UnknownMagic(magic)),
    };

    let chunk = data[data_offset_width + 2..].to_vec();
    Ok(ChunkData {
        data_offset,
        fragment_part,
        last_fragment,
        chunk,
    })
}

/// Codec-level errors. All are "drop this datagram/fragment" conditions on
/// the receive path and configuration errors on the send path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    InvalidBase32(u8),
    UnknownMagic(u8),
    ShortHeader,
    DomainTooSmall,
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::InvalidBase32(c) => write!(f, "invalid base32 byte 0x{c:02x}"),
            CodecError::UnknownMagic(c) => write!(f, "unknown fragment magic byte 0x{c:02x}"),
            CodecError::ShortHeader => write!(f, "fragment shorter than header"),
            CodecError::DomainTooSmall => {
                write!(f, "max_domain_len too small to fit any data")
            }
        }
    }
}

impl std::error::Error for CodecError {}
