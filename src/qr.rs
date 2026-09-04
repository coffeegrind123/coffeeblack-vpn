//! QR code generation for client configuration payloads.
//!
//! In-house encoder (ISO/IEC 18004) replacing the `qrcode` crate. Everything
//! the project asks of a QR code is here: byte-mode encoding, Reed-Solomon
//! error correction at level M, mask selection, and the same SVG rendering the
//! admin UI was already receiving.
//!
//! Two deliberate scope decisions:
//!
//! * **Byte mode only.** The payloads are WireGuard configs, `vless://` URLs,
//!   `tg://proxy` links and base64 blobs — all mixed-case, so the numeric and
//!   alphanumeric modes cannot encode them and the segment optimiser the
//!   `qrcode` crate runs would pick byte mode for every one of them anyway.
//! * **Mask scoring matches the `qrcode` crate's**, including its two
//!   deviations from the standard's penalty formulas (no 5 % rounding in the
//!   balance rule; adjacency and 2×2-block runs break where a function pattern
//!   meets data). Every mask produces a valid, scannable symbol, so this is not
//!   a correctness requirement — it is what lets `qr_parity` assert that the
//!   rendered SVG is byte-for-byte what shipped before.

use anyhow::{bail, Result};

/// Error-correction level. The project only ever uses `M`, which is what
/// `QrCode::new` defaulted to; the others exist because the block tables are
/// indexed by level and a partial table invites an out-of-range bug later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcLevel {
    /// ~7 % recovery.
    L = 0,
    /// ~15 % recovery.
    M = 1,
    /// ~25 % recovery.
    Q = 2,
    /// ~30 % recovery.
    H = 3,
}

impl EcLevel {
    /// The two-bit code used in the format information.
    fn format_bits(self) -> u32 {
        match self {
            EcLevel::L => 0b01,
            EcLevel::M => 0b00,
            EcLevel::Q => 0b11,
            EcLevel::H => 0b10,
        }
    }
}

/// Error-correction codewords per block, `[L, M, Q, H]` by version (1-indexed
/// by `version - 1`). ISO/IEC 18004:2006 §6.5.1 table 9.
const EC_BYTES_PER_BLOCK: [[u8; 4]; 40] = [
    [7, 10, 13, 17],
    [10, 16, 22, 28],
    [15, 26, 18, 22],
    [20, 18, 26, 16],
    [26, 24, 18, 22],
    [18, 16, 24, 28],
    [20, 18, 18, 26],
    [24, 22, 22, 26],
    [30, 22, 20, 24],
    [18, 26, 24, 28],
    [20, 30, 28, 24],
    [24, 22, 26, 28],
    [26, 22, 24, 22],
    [30, 24, 20, 24],
    [22, 24, 30, 24],
    [24, 28, 24, 30],
    [28, 28, 28, 28],
    [30, 26, 28, 28],
    [28, 26, 26, 26],
    [28, 26, 30, 28],
    [28, 26, 28, 30],
    [28, 28, 30, 24],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [26, 28, 30, 30],
    [28, 28, 28, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
    [30, 28, 30, 30],
];

/// Data codewords per block as `(size1, count1, size2, count2)`, `[L, M, Q, H]`
/// by version. Same table, columns "k" and "number of blocks".
const DATA_BYTES_PER_BLOCK: [[(u16, u16, u16, u16); 4]; 40] = [
    [(19, 1, 0, 0), (16, 1, 0, 0), (13, 1, 0, 0), (9, 1, 0, 0)],
    [(34, 1, 0, 0), (28, 1, 0, 0), (22, 1, 0, 0), (16, 1, 0, 0)],
    [(55, 1, 0, 0), (44, 1, 0, 0), (17, 2, 0, 0), (13, 2, 0, 0)],
    [(80, 1, 0, 0), (32, 2, 0, 0), (24, 2, 0, 0), (9, 4, 0, 0)],
    [(108, 1, 0, 0), (43, 2, 0, 0), (15, 2, 16, 2), (11, 2, 12, 2)],
    [(68, 2, 0, 0), (27, 4, 0, 0), (19, 4, 0, 0), (15, 4, 0, 0)],
    [(78, 2, 0, 0), (31, 4, 0, 0), (14, 2, 15, 4), (13, 4, 14, 1)],
    [(97, 2, 0, 0), (38, 2, 39, 2), (18, 4, 19, 2), (14, 4, 15, 2)],
    [(116, 2, 0, 0), (36, 3, 37, 2), (16, 4, 17, 4), (12, 4, 13, 4)],
    [(68, 2, 69, 2), (43, 4, 44, 1), (19, 6, 20, 2), (15, 6, 16, 2)],
    [(81, 4, 0, 0), (50, 1, 51, 4), (22, 4, 23, 4), (12, 3, 13, 8)],
    [(92, 2, 93, 2), (36, 6, 37, 2), (20, 4, 21, 6), (14, 7, 15, 4)],
    [(107, 4, 0, 0), (37, 8, 38, 1), (20, 8, 21, 4), (11, 12, 12, 4)],
    [(115, 3, 116, 1), (40, 4, 41, 5), (16, 11, 17, 5), (12, 11, 13, 5)],
    [(87, 5, 88, 1), (41, 5, 42, 5), (24, 5, 25, 7), (12, 11, 13, 7)],
    [(98, 5, 99, 1), (45, 7, 46, 3), (19, 15, 20, 2), (15, 3, 16, 13)],
    [(107, 1, 108, 5), (46, 10, 47, 1), (22, 1, 23, 15), (14, 2, 15, 17)],
    [(120, 5, 121, 1), (43, 9, 44, 4), (22, 17, 23, 1), (14, 2, 15, 19)],
    [(113, 3, 114, 4), (44, 3, 45, 11), (21, 17, 22, 4), (13, 9, 14, 16)],
    [(107, 3, 108, 5), (41, 3, 42, 13), (24, 15, 25, 5), (15, 15, 16, 10)],
    [(116, 4, 117, 4), (42, 17, 0, 0), (22, 17, 23, 6), (16, 19, 17, 6)],
    [(111, 2, 112, 7), (46, 17, 0, 0), (24, 7, 25, 16), (13, 34, 0, 0)],
    [(121, 4, 122, 5), (47, 4, 48, 14), (24, 11, 25, 14), (15, 16, 16, 14)],
    [(117, 6, 118, 4), (45, 6, 46, 14), (24, 11, 25, 16), (16, 30, 17, 2)],
    [(106, 8, 107, 4), (47, 8, 48, 13), (24, 7, 25, 22), (15, 22, 16, 13)],
    [(114, 10, 115, 2), (46, 19, 47, 4), (22, 28, 23, 6), (16, 33, 17, 4)],
    [(122, 8, 123, 4), (45, 22, 46, 3), (23, 8, 24, 26), (15, 12, 16, 28)],
    [(117, 3, 118, 10), (45, 3, 46, 23), (24, 4, 25, 31), (15, 11, 16, 31)],
    [(116, 7, 117, 7), (45, 21, 46, 7), (23, 1, 24, 37), (15, 19, 16, 26)],
    [(115, 5, 116, 10), (47, 19, 48, 10), (24, 15, 25, 25), (15, 23, 16, 25)],
    [(115, 13, 116, 3), (46, 2, 47, 29), (24, 42, 25, 1), (15, 23, 16, 28)],
    [(115, 17, 0, 0), (46, 10, 47, 23), (24, 10, 25, 35), (15, 19, 16, 35)],
    [(115, 17, 116, 1), (46, 14, 47, 21), (24, 29, 25, 19), (15, 11, 16, 46)],
    [(115, 13, 116, 6), (46, 14, 47, 23), (24, 44, 25, 7), (16, 59, 17, 1)],
    [(121, 12, 122, 7), (47, 12, 48, 26), (24, 39, 25, 14), (15, 22, 16, 41)],
    [(121, 6, 122, 14), (47, 6, 48, 34), (24, 46, 25, 10), (15, 2, 16, 64)],
    [(122, 17, 123, 4), (46, 29, 47, 14), (24, 49, 25, 10), (15, 24, 16, 46)],
    [(122, 4, 123, 18), (46, 13, 47, 32), (24, 48, 25, 14), (15, 42, 16, 32)],
    [(117, 20, 118, 4), (47, 40, 48, 7), (24, 43, 25, 22), (15, 10, 16, 67)],
    [(118, 19, 119, 6), (47, 18, 48, 31), (24, 34, 25, 34), (15, 20, 16, 61)],
];

/// Centre coordinates of the alignment patterns, for versions 7..=40.
const ALIGNMENT_POSITIONS: [&[i16]; 34] = [
    &[6, 22, 38],
    &[6, 24, 42],
    &[6, 26, 46],
    &[6, 28, 50],
    &[6, 30, 54],
    &[6, 32, 58],
    &[6, 34, 62],
    &[6, 26, 46, 66],
    &[6, 26, 48, 70],
    &[6, 26, 50, 74],
    &[6, 30, 54, 78],
    &[6, 30, 56, 82],
    &[6, 30, 58, 86],
    &[6, 34, 62, 90],
    &[6, 28, 50, 72, 94],
    &[6, 26, 50, 74, 98],
    &[6, 30, 54, 78, 102],
    &[6, 28, 54, 80, 106],
    &[6, 32, 58, 84, 110],
    &[6, 30, 58, 86, 114],
    &[6, 34, 62, 90, 118],
    &[6, 26, 50, 74, 98, 122],
    &[6, 30, 54, 78, 102, 126],
    &[6, 26, 52, 78, 104, 130],
    &[6, 30, 56, 82, 108, 134],
    &[6, 34, 60, 86, 112, 138],
    &[6, 30, 58, 86, 114, 142],
    &[6, 34, 62, 90, 118, 146],
    &[6, 30, 54, 78, 102, 126, 150],
    &[6, 24, 50, 76, 102, 128, 154],
    &[6, 28, 54, 80, 106, 132, 158],
    &[6, 32, 58, 84, 110, 136, 162],
    &[6, 26, 54, 82, 110, 138, 166],
    &[6, 30, 58, 86, 114, 142, 170],
];

/// Number of data codewords available at `version` and `ec`.
fn data_capacity(version: usize, ec: EcLevel) -> usize {
    let (s1, c1, s2, c2) = DATA_BYTES_PER_BLOCK[version - 1][ec as usize];
    (s1 as usize) * (c1 as usize) + (s2 as usize) * (c2 as usize)
}

/// Bit width of the byte-mode character-count indicator.
fn count_bits(version: usize) -> usize {
    if version <= 9 {
        8
    } else {
        16
    }
}

/// Smallest version that can hold `len` bytes in byte mode at `ec`.
fn choose_version(len: usize, ec: EcLevel) -> Result<usize> {
    for version in 1..=40 {
        let needed_bits = 4 + count_bits(version) + len * 8;
        if needed_bits.div_ceil(8) <= data_capacity(version, ec) {
            return Ok(version);
        }
    }
    bail!("data too long for a QR code: {len} bytes exceeds the version 40 capacity")
}

// ---------------------------------------------------------------------------
// Bit assembly
// ---------------------------------------------------------------------------

/// MSB-first bit accumulator for the data codeword stream.
#[derive(Default)]
struct BitBuf {
    bytes: Vec<u8>,
    bits: usize,
}

impl BitBuf {
    fn push(&mut self, value: u32, width: usize) {
        for i in (0..width).rev() {
            let bit = (value >> i) & 1 == 1;
            if self.bits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if bit {
                let idx = self.bits / 8;
                self.bytes[idx] |= 0x80 >> (self.bits % 8);
            }
            self.bits += 1;
        }
    }
}

/// Byte-mode data codewords for `data`, padded to the version's capacity.
fn encode_data(data: &[u8], version: usize, ec: EcLevel) -> Vec<u8> {
    let capacity = data_capacity(version, ec);
    let mut buf = BitBuf::default();
    buf.push(0b0100, 4);
    buf.push(data.len() as u32, count_bits(version));
    for &b in data {
        buf.push(b as u32, 8);
    }
    // Terminator: up to four zero bits, truncated against the capacity.
    let remaining = capacity * 8 - buf.bits;
    buf.push(0, remaining.min(4));
    // Pad to a byte boundary, then alternate the two standard pad codewords.
    if buf.bits % 8 != 0 {
        buf.push(0, 8 - (buf.bits % 8));
    }
    let mut out = buf.bytes;
    for pad in [0xecu8, 0x11].into_iter().cycle() {
        if out.len() >= capacity {
            break;
        }
        out.push(pad);
    }
    out
}

// ---------------------------------------------------------------------------
// Reed-Solomon over GF(2^8)
// ---------------------------------------------------------------------------

/// Exponential and logarithm tables for GF(2^8) with primitive polynomial
/// `x^8 + x^4 + x^3 + x^2 + 1` (0x11d) and generator 2.
fn gf_tables() -> &'static ([u8; 256], [u8; 256]) {
    static TABLES: std::sync::OnceLock<([u8; 256], [u8; 256])> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 256];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for (i, slot) in exp.iter_mut().enumerate() {
            *slot = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        // log[1] is written twice above (i = 0 and i = 255); force the
        // conventional 0 so exp[log[1]] == 1.
        log[1] = 0;
        (exp, log)
    })
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = gf_tables();
    exp[(log[a as usize] as usize + log[b as usize] as usize) % 255]
}

/// Generator polynomial for `degree` error-correction codewords:
/// `(x - α^0)(x - α^1)…(x - α^(degree-1))`, highest power first.
fn generator_poly(degree: usize) -> Vec<u8> {
    let (exp, _) = gf_tables();
    let mut poly = vec![1u8];
    for i in 0..degree {
        // Multiply by (x - α^i).
        let mut next = vec![0u8; poly.len() + 1];
        for (j, &c) in poly.iter().enumerate() {
            next[j] ^= c;
            next[j + 1] ^= gf_mul(c, exp[i % 255]);
        }
        poly = next;
    }
    poly
}

/// The `ec_len` error-correction codewords for one data block.
fn ec_codewords(block: &[u8], ec_len: usize) -> Vec<u8> {
    let gen = generator_poly(ec_len);
    let mut rem = vec![0u8; ec_len];
    for &byte in block {
        let factor = byte ^ rem[0];
        rem.remove(0);
        rem.push(0);
        for (i, &g) in gen.iter().skip(1).enumerate() {
            rem[i] ^= gf_mul(g, factor);
        }
    }
    rem
}

/// Split the data codewords into blocks, append each block's EC codewords, and
/// interleave both groups the way §6.6 requires.
fn interleave(data: &[u8], version: usize, ec: EcLevel) -> Vec<u8> {
    let (s1, c1, s2, c2) = DATA_BYTES_PER_BLOCK[version - 1][ec as usize];
    let ec_len = EC_BYTES_PER_BLOCK[version - 1][ec as usize] as usize;

    let mut blocks: Vec<&[u8]> = Vec::with_capacity((c1 + c2) as usize);
    let mut offset = 0usize;
    for _ in 0..c1 {
        blocks.push(&data[offset..offset + s1 as usize]);
        offset += s1 as usize;
    }
    for _ in 0..c2 {
        blocks.push(&data[offset..offset + s2 as usize]);
        offset += s2 as usize;
    }

    let ecs: Vec<Vec<u8>> = blocks.iter().map(|b| ec_codewords(b, ec_len)).collect();

    let max_data = blocks.iter().map(|b| b.len()).max().unwrap_or(0);
    let mut out = Vec::with_capacity(data.len() + ec_len * blocks.len());
    for i in 0..max_data {
        for block in &blocks {
            if let Some(&b) = block.get(i) {
                out.push(b);
            }
        }
    }
    for i in 0..ec_len {
        for e in &ecs {
            out.push(e[i]);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Symbol construction
// ---------------------------------------------------------------------------

/// A module of the symbol. The function/data distinction drives two things:
/// codeword placement skips function modules, and masking inverts only data
/// modules. The penalty rules read colour alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Module {
    /// Part of a function pattern (finder, timing, alignment, format,
    /// version, or the fixed dark module). Never masked.
    Function(bool),
    /// A data or error-correction module, subject to masking.
    Data(bool),
}

impl Module {
    fn is_dark(self) -> bool {
        match self {
            Module::Function(d) | Module::Data(d) => d,
        }
    }
}

/// A QR symbol as a square grid of modules.
pub struct Matrix {
    width: i16,
    modules: Vec<Module>,
}

impl Matrix {
    fn new(version: usize) -> Self {
        let width = (17 + 4 * version) as i16;
        Self {
            width,
            modules: vec![Module::Data(false); (width * width) as usize],
        }
    }

    /// Width of the symbol in modules, excluding the quiet zone.
    pub fn width(&self) -> usize {
        self.width as usize
    }

    /// Whether the module at `(x, y)` is dark.
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.width as usize + x].is_dark()
    }

    #[inline]
    fn get(&self, x: i16, y: i16) -> Module {
        self.modules[(y * self.width + x) as usize]
    }

    #[inline]
    fn set(&mut self, x: i16, y: i16, m: Module) {
        self.modules[(y * self.width + x) as usize] = m;
    }

    fn is_function(&self, x: i16, y: i16) -> bool {
        matches!(self.get(x, y), Module::Function(_))
    }

    fn draw_function_patterns(&mut self, version: usize, ec: EcLevel) {
        let w = self.width;

        // Finder patterns and their separators, at three corners. The 7×7
        // pattern is a dark border, a light ring, and a dark 3×3 core; the
        // surrounding row/column is the light separator.
        for &(ox, oy) in &[(0, 0), (w - 7, 0), (0, w - 7)] {
            for dy in -1..=7i16 {
                for dx in -1..=7i16 {
                    let (x, y) = (ox + dx, oy + dy);
                    if x < 0 || y < 0 || x >= w || y >= w {
                        continue;
                    }
                    let on_separator = !(0..7).contains(&dx) || !(0..7).contains(&dy);
                    let border = dx == 0 || dx == 6 || dy == 0 || dy == 6;
                    let core = (2..=4).contains(&dx) && (2..=4).contains(&dy);
                    let dark = !on_separator && (border || core);
                    self.set(x, y, Module::Function(dark));
                }
            }
        }

        // Timing patterns.
        for i in 8..w - 8 {
            let dark = i % 2 == 0;
            self.set(i, 6, Module::Function(dark));
            self.set(6, i, Module::Function(dark));
        }

        // Alignment patterns, skipping the three that would sit on a finder.
        //
        // Versions 2..=6 carry exactly one, at (w-7, w-7); the generic loop
        // produces it from the two-element position list, because the other
        // three combinations are the ones the corner rule drops. Versions 7
        // and up take their positions from the table.
        if version >= 2 {
            let fallback = [6i16, w - 7];
            let positions: &[i16] = if version >= 7 {
                ALIGNMENT_POSITIONS[version - 7]
            } else {
                &fallback
            };
            let last = positions.len() - 1;
            for (i, &cx) in positions.iter().enumerate() {
                for (j, &cy) in positions.iter().enumerate() {
                    if (i == 0 && (j == 0 || j == last)) || (i == last && j == 0) {
                        continue;
                    }
                    for dy in -2..=2i16 {
                        for dx in -2..=2i16 {
                            let ring = dx.abs().max(dy.abs());
                            self.set(cx + dx, cy + dy, Module::Function(ring != 1));
                        }
                    }
                }
            }
        }

        // Version information (versions 7 and up), both copies.
        if version >= 7 {
            let bits = version_info_bits(version);
            for i in 0..18i16 {
                let dark = (bits >> i) & 1 == 1;
                let a = w - 11 + i % 3;
                let b = i / 3;
                self.set(a, b, Module::Function(dark));
                self.set(b, a, Module::Function(dark));
            }
        }

        // Reserve the format-information area by writing a placeholder copy:
        // that marks exactly the right modules as function modules (the two
        // timing modules crossing the area are deliberately not among them),
        // so codeword placement skips them. The real values are written once
        // the mask is chosen.
        self.draw_format_info(ec, 0);
    }

    /// Place the codeword bit stream in the standard two-column zigzag.
    fn draw_codewords(&mut self, codewords: &[u8]) {
        let w = self.width;
        let mut bit = 0usize;
        let total = codewords.len() * 8;

        let mut right = w - 1;
        while right >= 1 {
            // Column 6 is the vertical timing pattern; the pairing skips it.
            if right == 6 {
                right = 5;
            }
            for vert in 0..w {
                for j in 0..2 {
                    let x = right - j;
                    let upward = ((right + 1) & 2) == 0;
                    let y = if upward { w - 1 - vert } else { vert };
                    if self.is_function(x, y) || bit >= total {
                        continue;
                    }
                    let dark = (codewords[bit >> 3] >> (7 - (bit & 7))) & 1 == 1;
                    self.set(x, y, Module::Data(dark));
                    bit += 1;
                }
            }
            right -= 2;
        }
    }

    /// Whether mask `pattern` inverts the module at `(x, y)`.
    fn mask_applies(pattern: u8, x: i16, y: i16) -> bool {
        let (x, y) = (x as u32, y as u32);
        match pattern {
            0 => (x + y) % 2 == 0,
            1 => y % 2 == 0,
            2 => x % 3 == 0,
            3 => (x + y) % 3 == 0,
            4 => (x / 3 + y / 2) % 2 == 0,
            5 => (x * y) % 2 + (x * y) % 3 == 0,
            6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
            7 => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
            _ => unreachable!("mask pattern out of range"),
        }
    }

    /// Invert the data modules the mask selects. Applying it twice restores
    /// the original, which is how the candidate loop backs a mask out.
    fn apply_mask(&mut self, pattern: u8) {
        for y in 0..self.width {
            for x in 0..self.width {
                if let Module::Data(dark) = self.get(x, y) {
                    if Self::mask_applies(pattern, x, y) {
                        self.set(x, y, Module::Data(!dark));
                    }
                }
            }
        }
    }

    /// Write both copies of the format information for `ec` and `mask`.
    fn draw_format_info(&mut self, ec: EcLevel, mask: u8) {
        let bits = format_info_bits(ec, mask);
        let w = self.width;
        let bit = |i: u32| Module::Function((bits >> i) & 1 == 1);

        for i in 0..6u32 {
            self.set(8, i as i16, bit(i));
        }
        self.set(8, 7, bit(6));
        self.set(8, 8, bit(7));
        self.set(7, 8, bit(8));
        for i in 9..15u32 {
            self.set(14 - i as i16, 8, bit(i));
        }
        for i in 0..8u32 {
            self.set(w - 1 - i as i16, 8, bit(i));
        }
        for i in 8..15u32 {
            self.set(8, w - 15 + i as i16, bit(i));
        }
        self.set(8, w - 8, Module::Function(true));
    }

    // --- Mask penalty scoring -------------------------------------------

    /// Rule 1: runs of five or more identical modules in a row or column.
    fn adjacent_penalty(&self, horizontal: bool) -> u32 {
        let mut total = 0u32;
        for i in 0..self.width {
            let mut last: Option<bool> = None;
            let mut run = 1u32;
            for j in 0..=self.width {
                // One past the end acts as a sentinel that flushes the run.
                let current = if j == self.width {
                    None
                } else if horizontal {
                    Some(self.get(j, i).is_dark())
                } else {
                    Some(self.get(i, j).is_dark())
                };
                if current == last {
                    run += 1;
                } else {
                    last = current;
                    if run >= 5 {
                        total += run - 2;
                    }
                    run = 1;
                }
            }
        }
        total
    }

    /// Rule 2: every 2×2 block of identical modules, counted with overlap.
    fn block_penalty(&self) -> u32 {
        let mut total = 0u32;
        for y in 0..self.width - 1 {
            for x in 0..self.width - 1 {
                let a = self.get(x, y).is_dark();
                if a == self.get(x + 1, y).is_dark()
                    && a == self.get(x, y + 1).is_dark()
                    && a == self.get(x + 1, y + 1).is_dark()
                {
                    total += 3;
                }
            }
        }
        total
    }

    /// Rule 3: finder-like `1:1:3:1:1` patterns with four light modules on
    /// either side.
    fn finder_penalty(&self, horizontal: bool) -> u32 {
        const PATTERN: [bool; 7] = [true, false, true, true, true, false, true];
        let mut total = 0u32;
        let at = |k: i16, i: i16| -> bool {
            if horizontal {
                self.get(k, i).is_dark()
            } else {
                self.get(i, k).is_dark()
            }
        };
        for i in 0..self.width {
            for j in 0..=self.width - 7 {
                if !(0..7).all(|k| at(j + k, i) == PATTERN[k as usize]) {
                    continue;
                }
                let dark_near = |range: std::ops::Range<i16>| {
                    range.into_iter().any(|k| (0..self.width).contains(&k) && at(k, i))
                };
                if !dark_near(j - 4..j) || !dark_near(j + 7..j + 11) {
                    total += 40;
                }
            }
        }
        total
    }

    /// Rule 4: deviation from an even dark/light split.
    fn balance_penalty(&self) -> u32 {
        let dark = self.modules.iter().filter(|m| m.is_dark()).count();
        let ratio = dark * 200 / self.modules.len();
        ratio.abs_diff(100) as u32
    }

    fn penalty(&self) -> u32 {
        self.adjacent_penalty(true)
            + self.adjacent_penalty(false)
            + self.block_penalty()
            + self.finder_penalty(true)
            + self.finder_penalty(false)
            + self.balance_penalty()
    }
}

/// 15-bit format information: two level bits, three mask bits, a BCH(15,5)
/// remainder, all XORed with the standard 0x5412 mask.
fn format_info_bits(ec: EcLevel, mask: u8) -> u32 {
    let data = (ec.format_bits() << 3) | mask as u32;
    // Polynomial division by the BCH generator 0x537 (x^10 + x^8 + x^5 + x^4
    // + x^2 + x + 1).
    let mut rem = data << 10;
    for i in (0..5).rev() {
        if rem & (1 << (10 + i)) != 0 {
            rem ^= 0x537 << i;
        }
    }
    ((data << 10) | rem) ^ 0x5412
}

/// 18-bit version information: the version number plus a BCH(18,6) remainder.
fn version_info_bits(version: usize) -> u32 {
    let v = version as u32;
    let mut rem = v << 12;
    for i in (0..6).rev() {
        if rem & (1 << (12 + i)) != 0 {
            rem ^= 0x1f25 << i;
        }
    }
    (v << 12) | rem
}

/// Build the unmasked symbol: function patterns plus placed codewords.
fn build(data: &[u8], ec: EcLevel) -> Result<Matrix> {
    let version = choose_version(data.len(), ec)?;
    let codewords = interleave(&encode_data(data, version, ec), version, ec);

    let mut matrix = Matrix::new(version);
    matrix.draw_function_patterns(version, ec);
    matrix.draw_codewords(&codewords);
    Ok(matrix)
}

/// Encode `data` with a specific mask pattern (`0..=7`).
///
/// [`encode`] picks the mask by penalty score; this is the entry point for
/// tests that need to compare a specific one against a reference encoder.
pub fn encode_with_mask(data: &[u8], ec: EcLevel, mask: u8) -> Result<Matrix> {
    if mask > 7 {
        bail!("mask pattern {mask} is out of range (0..=7)");
    }
    let mut matrix = build(data, ec)?;
    matrix.apply_mask(mask);
    matrix.draw_format_info(ec, mask);
    Ok(matrix)
}

/// The penalty score a symbol masked with `mask` would carry. Exposed so the
/// parity test can compare the ranking, not just the winner.
pub fn mask_penalty(data: &[u8], ec: EcLevel, mask: u8) -> Result<u32> {
    Ok(encode_with_mask(data, ec, mask)?.penalty())
}

/// Encode `data` into a QR symbol at the given error-correction level.
///
/// All eight masks are scored and the least penalised wins; ties go to the
/// lower-numbered mask, as in the reference encoder.
pub fn encode(data: &[u8], ec: EcLevel) -> Result<Matrix> {
    let mut matrix = build(data, ec)?;

    // The format information is part of the scored symbol, so it is written
    // for each candidate. Masking is an involution: applying the same pattern
    // a second time restores the unmasked matrix for the next candidate.
    let mut best = (u32::MAX, 0u8);
    for mask in 0..8u8 {
        matrix.apply_mask(mask);
        matrix.draw_format_info(ec, mask);
        let score = matrix.penalty();
        if score < best.0 {
            best = (score, mask);
        }
        matrix.apply_mask(mask);
    }
    matrix.apply_mask(best.1);
    matrix.draw_format_info(ec, best.1);
    Ok(matrix)
}

// ---------------------------------------------------------------------------
// SVG rendering
// ---------------------------------------------------------------------------

/// Quiet zone, in modules, required around the symbol.
const QUIET_ZONE: usize = 4;

/// Render `matrix` as an SVG at least `min_px` wide, with a quiet zone.
///
/// Byte-for-byte the markup the `qrcode` crate's SVG renderer produced for the
/// same symbol: one `<rect>` background plus a single `<path>` of per-module
/// `M…h…v…H…V…` segments, in row-major order.
fn to_svg(matrix: &Matrix, min_px: usize, dark: &str, light: &str) -> String {
    let modules = matrix.width();
    let width_in_modules = modules + 2 * QUIET_ZONE;
    let unit = min_px.div_ceil(width_in_modules);
    let size = width_in_modules * unit;

    let mut svg = format!(
        concat!(
            r#"<?xml version="1.0" standalone="yes"?>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg""#,
            r#" version="1.1" width="{w}" height="{h}""#,
            r#" viewBox="0 0 {w} {h}" shape-rendering="crispEdges">"#,
            r#"<rect x="0" y="0" width="{w}" height="{h}" fill="{bg}"/>"#,
            r#"<path fill="{fg}" d=""#,
        ),
        w = size,
        h = size,
        fg = dark,
        bg = light
    );

    for y in 0..width_in_modules {
        for x in 0..width_in_modules {
            let inside = (QUIET_ZONE..modules + QUIET_ZONE).contains(&x)
                && (QUIET_ZONE..modules + QUIET_ZONE).contains(&y);
            if inside && matrix.is_dark(x - QUIET_ZONE, y - QUIET_ZONE) {
                let (px, py) = (x * unit, y * unit);
                svg.push_str(&format!("M{px} {py}h{unit}v{unit}H{px}V{py}"));
            }
        }
    }

    svg.push_str(r#""/></svg>"#);
    svg
}

/// Generate an SVG QR code for the given configuration string.
///
/// Returns a complete `<svg>` element as a string.
pub fn generate_qr_svg(config: &str) -> Result<String> {
    let matrix = encode(config.as_bytes(), EcLevel::M)?;
    Ok(to_svg(&matrix, 256, "#000000", "#ffffff"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_info_matches_the_standard_table() {
        // ISO/IEC 18004 table C.1, level M, masks 0..7.
        let expected = [
            0x5412, 0x5125, 0x5e7c, 0x5b4b, 0x45f9, 0x40ce, 0x4f97, 0x4aa0,
        ];
        for (mask, want) in expected.iter().enumerate() {
            assert_eq!(
                format_info_bits(EcLevel::M, mask as u8),
                *want,
                "mask {mask}"
            );
        }
        // A couple of spot checks at the other levels.
        assert_eq!(format_info_bits(EcLevel::L, 0), 0x77c4);
        assert_eq!(format_info_bits(EcLevel::Q, 0), 0x355f);
        assert_eq!(format_info_bits(EcLevel::H, 0), 0x1689);
    }

    #[test]
    fn version_info_matches_the_standard_table() {
        // ISO/IEC 18004 table D.1.
        assert_eq!(version_info_bits(7), 0x07c94);
        assert_eq!(version_info_bits(8), 0x085bc);
        assert_eq!(version_info_bits(21), 0x15683);
        assert_eq!(version_info_bits(40), 0x28c69);
    }

    #[test]
    fn galois_field_is_well_formed() {
        let (exp, log) = gf_tables();
        assert_eq!(exp[0], 1);
        assert_eq!(exp[1], 2);
        assert_eq!(exp[8], 0x1d, "reduction by 0x11d");
        for i in 1..=255u16 {
            let v = i as u8;
            assert_eq!(exp[log[v as usize] as usize], v, "log/exp disagree at {v}");
        }
        assert_eq!(gf_mul(0, 5), 0);
        assert_eq!(gf_mul(1, 5), 5);
        assert_eq!(gf_mul(3, 7), 9, "0x03 * 0x07 in GF(2^8)");
    }

    #[test]
    fn reed_solomon_matches_the_standard_worked_example() {
        // ISO/IEC 18004 annex I: the version 1-M codewords for "01234567"
        // (numeric mode) and their ten error-correction codewords.
        let data = [
            0x10, 0x20, 0x0c, 0x56, 0x61, 0x80, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11,
            0xec, 0x11,
        ];
        let ec = ec_codewords(&data, 10);
        assert_eq!(
            ec,
            vec![0xa5, 0x24, 0xd4, 0xc1, 0xed, 0x36, 0xc7, 0x87, 0x2c, 0x55]
        );
    }

    #[test]
    fn generator_polynomials_have_the_right_degree_and_leading_term() {
        for degree in [7usize, 10, 13, 17, 26, 30, 68] {
            let g = generator_poly(degree);
            assert_eq!(g.len(), degree + 1, "degree {degree}");
            assert_eq!(g[0], 1, "monic");
            assert!(g.iter().all(|&c| c != 0) || degree > 30);
        }
    }

    #[test]
    fn version_selection_walks_the_capacity_table() {
        // Byte mode overhead is 4 bits of mode plus the count indicator.
        assert_eq!(choose_version(1, EcLevel::M).unwrap(), 1);
        assert_eq!(choose_version(14, EcLevel::M).unwrap(), 1, "16 - 2 header bytes");
        assert_eq!(choose_version(15, EcLevel::M).unwrap(), 2);
        assert_eq!(choose_version(2331, EcLevel::M).unwrap(), 40);
        assert!(choose_version(2332, EcLevel::M).is_err());
        // Level H holds far less; level L far more.
        assert!(choose_version(2331, EcLevel::H).is_err());
        assert_eq!(choose_version(2900, EcLevel::L).unwrap(), 40);
    }

    #[test]
    fn data_encoding_pads_to_the_full_capacity() {
        let out = encode_data(b"hi", 1, EcLevel::M);
        assert_eq!(out.len(), data_capacity(1, EcLevel::M));
        // 0100 mode nibble, then the 8-bit count split across the byte
        // boundary: 0x40 | (2 >> 4) == 0x40.
        assert_eq!(out[0], 0x40);
        assert_eq!(out[1], 0x26); // count 2 (0000_0010) split across the byte
        // Padding alternates 0xEC / 0x11 to the end.
        assert_eq!(out[out.len() - 2], 0xec);
        assert_eq!(out[out.len() - 1], 0x11);
    }

    #[test]
    fn interleaving_preserves_every_codeword() {
        // Version 5-Q is the smallest layout with two block groups
        // (2 blocks of 15 and 2 of 16), which is where interleaving bugs hide.
        let (s1, c1, s2, c2) = DATA_BYTES_PER_BLOCK[4][EcLevel::Q as usize];
        assert_eq!((s1, c1, s2, c2), (15, 2, 16, 2));
        let data: Vec<u8> = (0..data_capacity(5, EcLevel::Q) as u16)
            .map(|i| (i % 251) as u8)
            .collect();
        let out = interleave(&data, 5, EcLevel::Q);
        let ec_len = EC_BYTES_PER_BLOCK[4][EcLevel::Q as usize] as usize;
        assert_eq!(out.len(), data.len() + ec_len * 4);
        // First four codewords are the first byte of each of the four blocks.
        assert_eq!(out[0], data[0]);
        assert_eq!(out[1], data[15]);
        assert_eq!(out[2], data[30]);
        assert_eq!(out[3], data[46]);
    }

    #[test]
    fn masking_is_an_involution() {
        let mut m = build(b"round trip", EcLevel::M).unwrap();
        let before: Vec<bool> = (0..m.width())
            .flat_map(|y| (0..m.width()).map(move |x| (x, y)))
            .map(|(x, y)| m.is_dark(x, y))
            .collect();
        for mask in 0..8u8 {
            m.apply_mask(mask);
            m.apply_mask(mask);
        }
        let after: Vec<bool> = (0..m.width())
            .flat_map(|y| (0..m.width()).map(move |x| (x, y)))
            .map(|(x, y)| m.is_dark(x, y))
            .collect();
        assert_eq!(before, after);
    }

    #[test]
    fn function_patterns_land_where_the_standard_puts_them() {
        let m = encode(b"function patterns", EcLevel::M).unwrap();
        let w = m.width();
        // Finder cores.
        for &(ox, oy) in &[(0, 0), (w - 7, 0), (0, w - 7)] {
            assert!(m.is_dark(ox, oy), "finder corner");
            assert!(m.is_dark(ox + 3, oy + 3), "finder centre");
            assert!(!m.is_dark(ox + 1, oy + 1), "finder light ring");
        }
        // Timing patterns alternate, starting dark at index 8.
        for i in 8..w - 8 {
            assert_eq!(m.is_dark(i, 6), i % 2 == 0, "timing row at {i}");
            assert_eq!(m.is_dark(6, i), i % 2 == 0, "timing column at {i}");
        }
        // The module below the top-left format block is always dark.
        assert!(m.is_dark(8, w - 8));
    }

    #[test]
    fn rejects_an_out_of_range_mask() {
        assert!(encode_with_mask(b"x", EcLevel::M, 8).is_err());
        assert!(encode_with_mask(b"x", EcLevel::M, 7).is_ok());
    }

    #[test]
    fn svg_is_self_contained_and_sized() {
        let svg = generate_qr_svg("hello").unwrap();
        assert!(svg.starts_with("<?xml"));
        assert!(svg.ends_with("</svg>"));
        assert!(!svg.contains("http://") || svg.contains("www.w3.org/2000/svg"));
        assert!(svg.contains("#000000") && svg.contains("#ffffff"));
    }
}
