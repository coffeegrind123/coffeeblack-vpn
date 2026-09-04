//! Gzip (RFC 1952) and DEFLATE (RFC 1951) decompression.
//!
//! Replaces `flate2`, which cost five crates (`miniz_oxide`, `adler2`,
//! `crc32fast`, `simd-adler32`) to do exactly one thing here: expand the
//! vendored `vendor/*.gz` ELF blobs at startup. Nothing in the project ever
//! *compresses* outside of tests, and nothing reads a zlib or raw-deflate
//! stream — so a decoder for the one container format we ship is the whole
//! requirement.
//!
//! Shape of the implementation:
//!
//! * The compressed input is always a `&[u8]` (the blobs are `include_bytes!`
//!   constants), so the reader side needs no buffering machinery.
//! * The output side streams: decoded bytes are flushed to the writer as they
//!   are produced, retaining only the 32 KiB LZ77 back-reference window plus a
//!   small staging buffer. Expanding the ~35 MiB Xray ELF therefore costs
//!   about a megabyte of transient memory, not 35.
//! * Huffman decoding uses a single flat lookup table per code, sized to the
//!   longest code in that block, so each symbol costs one table index rather
//!   than a bit-at-a-time tree walk.
//! * Both integrity checks in the gzip trailer are enforced: the CRC-32 of the
//!   decompressed bytes and the ISIZE length. A corrupt blob fails here rather
//!   than at the SHA-256 check the callers do afterwards, which keeps the
//!   error message pointing at the real problem.

use std::io::Write;

use anyhow::{bail, Result};

/// Largest legal Huffman code length in DEFLATE.
const MAX_BITS: usize = 15;
/// LZ77 window: back-references may reach 32 KiB into the output.
const WINDOW: usize = 32 * 1024;
/// Staging buffer high-water mark before bytes are flushed to the writer.
const FLUSH_AT: usize = 1024 * 1024;

/// Base lengths for the 29 length codes (257..=285), RFC 1951 §3.2.5.
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
/// Extra bits read for each length code.
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// Base distances for the 30 distance codes.
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
/// Extra bits read for each distance code.
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Order in which code-length-code lengths appear in a dynamic block header.
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

// ---------------------------------------------------------------------------
// Bit reader
// ---------------------------------------------------------------------------

/// LSB-first bit reader over an in-memory DEFLATE stream.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Bits already loaded, least-significant end first.
    buf: u64,
    /// How many of `buf`'s low bits are valid.
    cnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            buf: 0,
            cnt: 0,
        }
    }

    /// Load bytes until at least 57 bits are buffered (or input runs out).
    #[inline]
    fn refill(&mut self) {
        while self.cnt <= 56 && self.pos < self.data.len() {
            self.buf |= (self.data[self.pos] as u64) << self.cnt;
            self.pos += 1;
            self.cnt += 8;
        }
    }

    /// Look at the next `n` bits without consuming them. Past the end of the
    /// stream the missing bits read as zero; [`consume`](Self::consume) is
    /// what turns an over-read into an error.
    #[inline]
    fn peek(&mut self, n: u32) -> u32 {
        if self.cnt < n {
            self.refill();
        }
        (self.buf & ((1u64 << n) - 1)) as u32
    }

    /// Drop `n` bits. Fails if the stream does not actually hold them.
    #[inline]
    fn consume(&mut self, n: u32) -> Result<()> {
        if self.cnt < n {
            self.refill();
            if self.cnt < n {
                bail!("truncated deflate stream");
            }
        }
        self.buf >>= n;
        self.cnt -= n;
        Ok(())
    }

    /// Read `n` bits as an integer.
    #[inline]
    fn bits(&mut self, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        let v = self.peek(n);
        self.consume(n)?;
        Ok(v)
    }

    /// Discard buffered bits back to a byte boundary (stored-block prologue).
    fn align(&mut self) {
        let drop = self.cnt % 8;
        self.buf >>= drop;
        self.cnt -= drop;
    }

    /// Take `n` whole bytes from the byte-aligned stream.
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        // Whatever is still buffered came from `data`; rewind `pos` by those
        // whole bytes so slicing lines up with the real stream position.
        let buffered = (self.cnt / 8) as usize;
        let start = self.pos - buffered;
        if start + n > self.data.len() {
            bail!("truncated stored block");
        }
        let out = &self.data[start..start + n];
        self.pos = start + n;
        self.buf = 0;
        self.cnt = 0;
        Ok(out)
    }

    /// Byte offset of the next unread byte, ignoring buffered bits.
    fn byte_pos(&self) -> usize {
        self.pos - (self.cnt / 8) as usize
    }
}

// ---------------------------------------------------------------------------
// Huffman decoding
// ---------------------------------------------------------------------------

/// A canonical Huffman code as one flat lookup table.
///
/// `table[i]` is indexed by the next `bits` bits of the stream (LSB-first, so
/// codes are stored bit-reversed) and packs the symbol in the high 16 bits and
/// the code length in the low 16. A length of 0 marks an invalid code.
struct Huffman {
    table: Vec<u32>,
    bits: u32,
}

impl Huffman {
    /// Build from per-symbol code lengths (0 = symbol unused).
    ///
    /// Rejects over-subscribed codes. Incomplete codes are accepted only in
    /// the single-symbol case DEFLATE explicitly permits (a block whose
    /// distance code has one symbol), which real encoders do emit.
    fn new(lengths: &[u8]) -> Result<Self> {
        let mut counts = [0u16; MAX_BITS + 1];
        for &l in lengths {
            if l as usize > MAX_BITS {
                bail!("huffman code length {l} exceeds 15");
            }
            counts[l as usize] += 1;
        }
        counts[0] = 0;

        let max = (1..=MAX_BITS).rev().find(|&l| counts[l] > 0).unwrap_or(0);
        if max == 0 {
            // No symbols at all: a table that always fails to decode. Legal
            // for an unused distance tree in a literals-only block.
            return Ok(Self {
                table: vec![0],
                bits: 0,
            });
        }

        // Kraft check: the code must not claim more space than exists.
        let mut left: i32 = 1;
        for &count in &counts[1..=max] {
            left <<= 1;
            left -= count as i32;
            if left < 0 {
                bail!("over-subscribed huffman code");
            }
        }
        let symbol_total: u16 = counts[1..=max].iter().sum();
        if left > 0 && symbol_total != 1 {
            bail!("incomplete huffman code");
        }

        // Canonical code assignment: first code of each length.
        let mut next_code = [0u32; MAX_BITS + 2];
        let mut code = 0u32;
        for l in 1..=max {
            code = (code + counts[l - 1] as u32) << 1;
            next_code[l] = code;
        }

        let size = 1usize << max;
        let mut table = vec![0u32; size];
        for (sym, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let len = len as usize;
            let code = next_code[len];
            next_code[len] += 1;
            // The stream delivers bits LSB-first while codes are defined
            // MSB-first, so index the table by the reversed code and replicate
            // the entry across every combination of the higher bits.
            let rev = reverse_bits(code, len as u32) as usize;
            let step = 1usize << len;
            let entry = ((sym as u32) << 16) | len as u32;
            let mut i = rev;
            while i < size {
                table[i] = entry;
                i += step;
            }
        }

        Ok(Self {
            table,
            bits: max as u32,
        })
    }

    /// Decode one symbol.
    #[inline]
    fn decode(&self, br: &mut BitReader<'_>) -> Result<u16> {
        if self.bits == 0 {
            bail!("huffman symbol from an empty code");
        }
        let idx = br.peek(self.bits) as usize;
        let entry = self.table[idx];
        let len = entry & 0xffff;
        if len == 0 {
            bail!("invalid huffman code");
        }
        br.consume(len)?;
        Ok((entry >> 16) as u16)
    }
}

/// Reverse the low `n` bits of `v`.
fn reverse_bits(v: u32, n: u32) -> u32 {
    let mut out = 0;
    for i in 0..n {
        out |= ((v >> i) & 1) << (n - 1 - i);
    }
    out
}

// ---------------------------------------------------------------------------
// Output sink: sliding window + streaming flush
// ---------------------------------------------------------------------------

/// Collects decoded bytes, serving LZ77 back-references from the retained
/// window and flushing everything older than the window to the writer.
struct Sink<'w, W: Write> {
    out: &'w mut W,
    buf: Vec<u8>,
    /// Bytes already handed to the writer.
    flushed: u64,
    crc: u32,
}

impl<'w, W: Write> Sink<'w, W> {
    fn new(out: &'w mut W) -> Self {
        Self {
            out,
            buf: Vec::with_capacity(FLUSH_AT + WINDOW),
            flushed: 0,
            crc: 0xffff_ffff,
        }
    }

    #[inline]
    fn push(&mut self, b: u8) -> Result<()> {
        self.buf.push(b);
        if self.buf.len() >= FLUSH_AT + WINDOW {
            self.flush_old()?;
        }
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() >= FLUSH_AT + WINDOW {
            self.flush_old()?;
        }
        Ok(())
    }

    /// Copy `len` bytes from `dist` back in the output — the LZ77 match. The
    /// ranges may overlap (a run-length fill), so this copies byte by byte.
    fn copy_back(&mut self, dist: usize, len: usize) -> Result<()> {
        let have = self.buf.len();
        // `flush_old` always retains WINDOW bytes, and DEFLATE distances never
        // exceed WINDOW, so a distance larger than what is retained can only
        // mean the stream is corrupt (or references data before its start).
        if dist == 0 || dist > have {
            bail!("back-reference distance {dist} exceeds the {have} bytes available");
        }
        for src in (have - dist)..(have - dist + len) {
            let b = self.buf[src];
            self.buf.push(b);
        }
        if self.buf.len() >= FLUSH_AT + WINDOW {
            self.flush_old()?;
        }
        Ok(())
    }

    /// Write out everything except the trailing window.
    fn flush_old(&mut self) -> Result<()> {
        let keep = WINDOW.min(self.buf.len());
        let upto = self.buf.len() - keep;
        if upto == 0 {
            return Ok(());
        }
        self.crc = crc32_update(self.crc, &self.buf[..upto]);
        self.out.write_all(&self.buf[..upto])?;
        self.flushed += upto as u64;
        self.buf.drain(..upto);
        Ok(())
    }

    /// Write the remaining window and return `(total bytes, CRC-32)`.
    fn finish(mut self) -> Result<(u64, u32)> {
        self.crc = crc32_update(self.crc, &self.buf);
        self.out.write_all(&self.buf)?;
        let total = self.flushed + self.buf.len() as u64;
        Ok((total, self.crc ^ 0xffff_ffff))
    }
}

// ---------------------------------------------------------------------------
// CRC-32 (RFC 1952 / IEEE 802.3)
// ---------------------------------------------------------------------------

/// Standard reflected CRC-32 table, built once on first use.
fn crc_table() -> &'static [u32; 256] {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *slot = c;
        }
        t
    })
}

fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    let t = crc_table();
    for &b in data {
        crc = t[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

/// CRC-32 of a buffer, in the gzip convention.
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0xffff_ffff, data) ^ 0xffff_ffff
}

// ---------------------------------------------------------------------------
// DEFLATE
// ---------------------------------------------------------------------------

/// Fixed literal/length code lengths for a type-01 block (RFC 1951 §3.2.6).
fn fixed_literal_lengths() -> [u8; 288] {
    let mut l = [0u8; 288];
    l[0..=143].fill(8);
    l[144..=255].fill(9);
    l[256..=279].fill(7);
    l[280..=287].fill(8);
    l
}

/// Inflate a raw DEFLATE stream into `sink`, returning the reader positioned
/// after the final block.
fn inflate_blocks<W: Write>(br: &mut BitReader<'_>, sink: &mut Sink<'_, W>) -> Result<()> {
    loop {
        let last = br.bits(1)? == 1;
        let btype = br.bits(2)?;
        match btype {
            0 => {
                br.align();
                let header = br.bytes(4)?;
                let len = u16::from_le_bytes([header[0], header[1]]) as usize;
                let nlen = u16::from_le_bytes([header[2], header[3]]);
                if nlen != !(len as u16) {
                    bail!("stored block length check failed");
                }
                let data = br.bytes(len)?;
                sink.extend(data)?;
            }
            1 => {
                let lit = Huffman::new(&fixed_literal_lengths())?;
                // 32 five-bit codes, not 30: the fixed distance code is a
                // complete 5-bit code whose last two symbols are simply never
                // legal, and a 30-entry table would be incomplete (and so
                // rejected) instead.
                let dist = Huffman::new(&[5u8; 32])?;
                inflate_symbols(br, sink, &lit, &dist)?;
            }
            2 => {
                let (lit, dist) = read_dynamic_tables(br)?;
                inflate_symbols(br, sink, &lit, &dist)?;
            }
            _ => bail!("reserved deflate block type 3"),
        }
        if last {
            return Ok(());
        }
    }
}

/// Read the code-length-coded literal and distance tables of a dynamic block.
fn read_dynamic_tables(br: &mut BitReader<'_>) -> Result<(Huffman, Huffman)> {
    let hlit = br.bits(5)? as usize + 257;
    let hdist = br.bits(5)? as usize + 1;
    let hclen = br.bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        bail!("dynamic block declares too many codes");
    }

    let mut clen = [0u8; 19];
    for &slot in CLEN_ORDER.iter().take(hclen) {
        clen[slot] = br.bits(3)? as u8;
    }
    let clen_code = Huffman::new(&clen)?;

    let total = hlit + hdist;
    let mut lengths = vec![0u8; total];
    let mut i = 0;
    while i < total {
        let sym = clen_code.decode(br)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    bail!("code-length repeat with no previous length");
                }
                let prev = lengths[i - 1];
                let n = 3 + br.bits(2)? as usize;
                if i + n > total {
                    bail!("code-length repeat overruns the table");
                }
                lengths[i..i + n].fill(prev);
                i += n;
            }
            17 => {
                let n = 3 + br.bits(3)? as usize;
                if i + n > total {
                    bail!("code-length zero-run overruns the table");
                }
                i += n;
            }
            18 => {
                let n = 11 + br.bits(7)? as usize;
                if i + n > total {
                    bail!("code-length zero-run overruns the table");
                }
                i += n;
            }
            _ => bail!("invalid code-length symbol {sym}"),
        }
    }

    let lit = Huffman::new(&lengths[..hlit])?;
    let dist = Huffman::new(&lengths[hlit..])?;
    Ok((lit, dist))
}

/// Decode literal/length/distance symbols until the end-of-block marker.
fn inflate_symbols<W: Write>(
    br: &mut BitReader<'_>,
    sink: &mut Sink<'_, W>,
    lit: &Huffman,
    dist: &Huffman,
) -> Result<()> {
    loop {
        let sym = lit.decode(br)?;
        match sym {
            0..=255 => sink.push(sym as u8)?,
            256 => return Ok(()),
            257..=285 => {
                let idx = sym as usize - 257;
                let len = LENGTH_BASE[idx] as usize + br.bits(LENGTH_EXTRA[idx] as u32)? as usize;
                let dsym = dist.decode(br)? as usize;
                if dsym >= DIST_BASE.len() {
                    bail!("invalid distance symbol {dsym}");
                }
                let d = DIST_BASE[dsym] as usize + br.bits(DIST_EXTRA[dsym] as u32)? as usize;
                sink.copy_back(d, len)?;
            }
            _ => bail!("invalid literal/length symbol {sym}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Gzip container
// ---------------------------------------------------------------------------

/// Parse one gzip member header, returning the offset of its deflate stream.
fn parse_header(gz: &[u8]) -> Result<usize> {
    if gz.len() < 18 {
        bail!("gzip stream is too short to hold a header and trailer");
    }
    if gz[0] != 0x1f || gz[1] != 0x8b {
        bail!("not a gzip stream (bad magic)");
    }
    if gz[2] != 8 {
        bail!("unsupported gzip compression method {}", gz[2]);
    }
    let flags = gz[3];
    if flags & 0xe0 != 0 {
        bail!("reserved gzip header flags set");
    }
    let mut p = 10;
    if flags & 0x04 != 0 {
        // FEXTRA
        if p + 2 > gz.len() {
            bail!("truncated gzip FEXTRA length");
        }
        let xlen = u16::from_le_bytes([gz[p], gz[p + 1]]) as usize;
        p += 2 + xlen;
        if p > gz.len() {
            bail!("truncated gzip FEXTRA field");
        }
    }
    for flag in [0x08u8, 0x10] {
        // FNAME, FCOMMENT: NUL-terminated strings.
        if flags & flag != 0 {
            let end = gz[p..]
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| anyhow::anyhow!("unterminated gzip header string"))?;
            p += end + 1;
        }
    }
    if flags & 0x02 != 0 {
        // FHCRC
        p += 2;
        if p > gz.len() {
            bail!("truncated gzip header CRC");
        }
    }
    Ok(p)
}

/// Decompress a gzip stream into `out`, returning the number of bytes written.
///
/// Concatenated members are decoded in sequence, as `gzip -d` does. The CRC-32
/// and ISIZE trailer of every member is verified.
pub fn gunzip_to_writer<W: Write>(gz: &[u8], out: &mut W) -> Result<u64> {
    let mut offset = 0usize;
    let mut total = 0u64;

    loop {
        let body = parse_header(&gz[offset..])?;
        let start = offset + body;
        let mut br = BitReader::new(&gz[start..]);

        let (written, crc) = {
            let mut sink = Sink::new(out);
            inflate_blocks(&mut br, &mut sink)?;
            sink.finish()?
        };

        // The trailer sits on the next byte boundary after the last block.
        let end = start + br.byte_pos();
        if end + 8 > gz.len() {
            bail!("truncated gzip trailer");
        }
        let want_crc = u32::from_le_bytes([gz[end], gz[end + 1], gz[end + 2], gz[end + 3]]);
        let want_len =
            u32::from_le_bytes([gz[end + 4], gz[end + 5], gz[end + 6], gz[end + 7]]);
        if crc != want_crc {
            bail!("gzip CRC-32 mismatch: expected {want_crc:08x}, got {crc:08x}");
        }
        if want_len != (written as u32) {
            bail!(
                "gzip length mismatch: trailer says {want_len}, decompressed {}",
                written as u32
            );
        }

        total += written;
        offset = end + 8;

        // Trailing NUL padding is legal; anything else must be another member.
        if gz[offset..].iter().all(|&b| b == 0) {
            return Ok(total);
        }
    }
}

/// Decompress a gzip stream into a fresh `Vec`.
pub fn gunzip(gz: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    gunzip_to_writer(gz, &mut out)?;
    Ok(out)
}


#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    /// Compress with `flate2` — kept as a dev-dependency precisely so the
    /// in-house decoder is tested against the reference encoder rather than
    /// against itself.
    fn gzip(data: &[u8], level: u32) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::new(level));
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// Deterministic pseudo-random bytes (xorshift), so a failure reproduces.
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn round_trips_every_compression_level() {
        let data = b"the quick brown fox jumps over the lazy dog".repeat(50);
        // 0 is a stored block, 1 and 6 and 9 exercise fixed and dynamic ones.
        for level in [0, 1, 6, 9] {
            let gz = gzip(&data, level);
            assert_eq!(gunzip(&gz).unwrap(), data, "level {level}");
        }
    }

    #[test]
    fn round_trips_empty_input() {
        let gz = gzip(b"", 6);
        assert_eq!(gunzip(&gz).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn round_trips_a_single_byte() {
        let gz = gzip(b"x", 6);
        assert_eq!(gunzip(&gz).unwrap(), b"x");
    }

    #[test]
    fn round_trips_incompressible_data() {
        // High-entropy input makes the encoder emit stored blocks even at
        // level 9, and is the case a length/CRC bug shows up in immediately.
        let data = pseudo_random(300_000, 0x2b7e_1516);
        for level in [1, 9] {
            let gz = gzip(&data, level);
            assert_eq!(gunzip(&gz).unwrap(), data, "level {level}");
        }
    }

    #[test]
    fn round_trips_across_the_32k_window() {
        // 4 MiB with matches far beyond the window boundary: catches an
        // over-eager flush that drops bytes a later back-reference needs.
        let mut data = pseudo_random(64 * 1024, 99);
        for _ in 0..6 {
            let dup = data.clone();
            data.extend_from_slice(&dup);
        }
        assert!(data.len() >= 4 * 1024 * 1024);
        let gz = gzip(&data, 9);
        let out = gunzip(&gz).unwrap();
        assert_eq!(out.len(), data.len());
        assert!(out == data);
    }

    #[test]
    fn round_trips_a_long_run_of_one_byte() {
        // Overlapping copies (distance 1, length 258) are the run-length case.
        let data = vec![0x5au8; 1_000_000];
        let gz = gzip(&data, 9);
        assert_eq!(gunzip(&gz).unwrap(), data);
    }

    #[test]
    fn streams_into_a_writer_without_buffering_everything() {
        let data = pseudo_random(2 * 1024 * 1024, 7);
        let gz = gzip(&data, 6);
        let mut out = Vec::new();
        let n = gunzip_to_writer(&gz, &mut out).unwrap();
        assert_eq!(n as usize, data.len());
        assert_eq!(out, data);
    }

    #[test]
    fn decodes_concatenated_members() {
        let mut gz = gzip(b"first half;", 6);
        gz.extend_from_slice(&gzip(b"second half", 6));
        assert_eq!(gunzip(&gz).unwrap(), b"first half;second half");
    }

    #[test]
    fn accepts_a_header_with_a_filename() {
        // gzip(1) sets FNAME; flate2's builder is the closest equivalent.
        let mut gz = Vec::new();
        {
            let mut enc = flate2::GzBuilder::new()
                .filename("xray-linux-amd64")
                .comment("vendored blob")
                .write(&mut gz, Compression::new(6));
            enc.write_all(b"payload").unwrap();
            enc.finish().unwrap();
        }
        assert_eq!(gunzip(&gz).unwrap(), b"payload");
    }

    #[test]
    fn rejects_a_non_gzip_stream() {
        let err = gunzip(b"not compressed at all, no really").unwrap_err();
        assert!(err.to_string().contains("magic"), "{err}");
    }

    #[test]
    fn rejects_a_corrupt_crc() {
        let mut gz = gzip(b"tamper with my checksum", 6);
        let n = gz.len();
        gz[n - 8] ^= 0xff;
        let err = gunzip(&gz).unwrap_err();
        assert!(err.to_string().contains("CRC-32 mismatch"), "{err}");
    }

    #[test]
    fn rejects_a_corrupt_length() {
        let mut gz = gzip(b"tamper with my length", 6);
        let n = gz.len();
        gz[n - 4] ^= 0x0f;
        let err = gunzip(&gz).unwrap_err();
        assert!(err.to_string().contains("length mismatch"), "{err}");
    }

    #[test]
    fn rejects_truncation() {
        let gz = gzip(&pseudo_random(200_000, 5), 6);
        for cut in [12, gz.len() / 2, gz.len() - 9] {
            assert!(gunzip(&gz[..cut]).is_err(), "truncation at {cut} accepted");
        }
    }

    #[test]
    fn rejects_corrupt_deflate_payload() {
        let data = pseudo_random(100_000, 11);
        let gz = gzip(&data, 9);
        let mut broken = gz.clone();
        // Flip bits inside the compressed body, away from header and trailer.
        for byte in &mut broken[40..80] {
            *byte ^= 0xa5;
        }
        // Either the bitstream is rejected outright or the CRC catches it; a
        // silent wrong answer is the only unacceptable outcome.
        if let Ok(out) = gunzip(&broken) {
            assert_ne!(out, data, "corrupt stream decoded to the original");
        }
    }

    #[test]
    fn crc32_matches_known_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xe8b7_be43);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414f_a339);
    }

    #[test]
    fn reverse_bits_is_its_own_inverse() {
        for n in 1..=15u32 {
            // Only values representable in `n` bits are meaningful inputs.
            for v in [0u32, 1, 2, (1 << n) - 1, (1 << (n - 1)) | 1] {
                let v = v & ((1 << n) - 1);
                assert_eq!(reverse_bits(reverse_bits(v, n), n), v, "n={n} v={v}");
            }
        }
        // Spot-check the bit order itself, not just the involution.
        assert_eq!(reverse_bits(0b1, 3), 0b100);
        assert_eq!(reverse_bits(0b110, 3), 0b011);
    }

    #[test]
    fn rejects_an_over_subscribed_huffman_code() {
        // Four symbols claiming 1 bit each cannot fit in a 1-bit code.
        assert!(Huffman::new(&[1, 1, 1, 1]).is_err());
    }

    #[test]
    fn accepts_a_single_symbol_code() {
        // The one incomplete code DEFLATE permits: a block with exactly one
        // distance symbol. Real encoders emit this.
        let h = Huffman::new(&[1, 0, 0, 0]).expect("single-symbol code is legal");
        assert_eq!(h.bits, 1);
    }

    #[test]
    fn rejects_an_incomplete_multi_symbol_code() {
        // Two symbols at 2 bits leaves half the code space unused.
        assert!(Huffman::new(&[2, 2, 0, 0]).is_err());
    }
}
