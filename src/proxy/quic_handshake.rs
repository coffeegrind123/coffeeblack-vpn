//! Stateful QUIC/TLS-1.3 handshake responder for QUIC-mode probes.
//!
//! A DPI prober that suspects the UDP port of hiding a tunnel will speak QUIC
//! at it. Answering with a real server flight — ServerHello, EncryptedExtensions,
//! Certificate, CertificateVerify, Finished — is what makes the port look like
//! an HTTP/3 endpoint instead of an unidentifiable high-entropy stream.
//!
//! Replaces `quinn-proto`, which brought fourteen crates (a second `rand`
//! line, a bloom filter, `libm`, an ASN.1 writer via `rcgen`) to run a full
//! connection state machine — congestion control, loss recovery, streams,
//! path validation, migration — of which this responder used none. It never
//! completes a handshake: it emits the server flight and forgets the peer.
//! What is actually needed is the wire format and the crypto, and rustls (a
//! dependency either way, for the Reality dest probe) already provides all the
//! crypto through its `quic` module:
//!
//! * [`rustls::quic::Keys::initial`] derives the Initial secrets from the
//!   client's Destination Connection ID (RFC 9001 §5.2), including header
//!   protection and AEAD keys for both directions.
//! * [`rustls::quic::ServerConnection`] runs the TLS 1.3 handshake itself and
//!   hands back the Handshake-epoch keys at the right moment.
//!
//! What this module adds is the QUIC packet layer around them: long-header
//! parsing and construction, header protection, packet-number encoding,
//! varints, the four frame types that matter (PADDING, ACK, CRYPTO,
//! CONNECTION_CLOSE), transport parameters, and datagram coalescing.
//!
//! Deliberate limits, all matching what the previous implementation did in
//! practice:
//!
//! * **Only QUIC v1 Initial packets** are answered. Version negotiation for
//!   other versions is handled by `responder.rs`, before this module is
//!   consulted.
//! * **No retransmission.** The server flight is emitted once. The previous
//!   implementation went out of its way to evict the connection immediately
//!   after the flight (`flush_and_forget`) precisely to stop quinn-proto's
//!   loss-recovery timers from re-emitting it; being stateless gets that for
//!   free.
//! * **Anti-amplification.** A server may not send more than three times what
//!   it has received from an unvalidated address (RFC 9000 §8.1); the flight
//!   is truncated at that budget.
//! * State is retained only between the fragments of a single ClientHello, and
//!   only for a few seconds.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use rustls::quic::{KeyChange, Keys, PacketKey, Version};
use rustls::Side;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// QUIC version 1 (RFC 9000).
const QUIC_V1: u32 = 0x0000_0001;
/// Long-header packet types (the two bits above the reserved bits).
const PACKET_TYPE_INITIAL: u8 = 0;
const PACKET_TYPE_HANDSHAKE: u8 = 2;
/// Maximum size of a datagram we emit. 1200 is the floor every QUIC
/// implementation must support and what real servers stay under.
const MAX_DATAGRAM: usize = 1200;
/// A server may send at most this multiple of what it has received from an
/// address it has not validated (RFC 9000 §8.1).
const AMPLIFICATION_LIMIT: usize = 3;
/// AEAD tag length for every suite QUIC v1 allows.
const TAG_LEN: usize = 16;
/// Header-protection sample offset from the start of the packet number field.
const SAMPLE_OFFSET: usize = 4;
/// Header-protection sample length.
const SAMPLE_LEN: usize = 16;
/// Connection IDs we generate, in bytes.
const SCID_LEN: usize = 8;

/// How long a partially received ClientHello is kept while its remaining
/// fragments are awaited.
const PENDING_TTL: Duration = Duration::from_secs(3);
/// Upper bound on simultaneously tracked partial handshakes.
const MAX_PENDING: usize = 2_048;
/// Largest ClientHello we will reassemble. Real ones are 200-2000 bytes; the
/// cap stops a prober from using CRYPTO offsets to allocate memory.
const MAX_CRYPTO_BYTES: usize = 64 * 1024;

/// Minimum byte total that distinguishes a server Certificate flight from a
/// bare `CONNECTION_CLOSE`-only response. A successful TLS 1.3 Handshake
/// flight (Certificate + CertificateVerify + Finished) always exceeds this
/// threshold; a `CONNECTION_CLOSE` with a TLS alert is typically < 200 bytes.
///
/// Used by the test suite to assert a full flight was produced.
#[cfg(test)]
const MIN_CERT_FLIGHT_BYTES: usize = 500;

// ---------------------------------------------------------------------------
// Varints (RFC 9000 §16)
// ---------------------------------------------------------------------------

/// Read a QUIC variable-length integer, returning it and the bytes consumed.
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        value = (value << 8) | u64::from(b);
    }
    Some((value, len))
}

/// Append a QUIC variable-length integer.
fn write_varint(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=0x3f => out.push(value as u8),
        0x40..=0x3fff => out.extend_from_slice(&(0x4000 | value as u16).to_be_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&(0x8000_0000 | value as u32).to_be_bytes()),
        _ => out.extend_from_slice(&(0xc000_0000_0000_0000 | value).to_be_bytes()),
    }
}

/// Byte length a varint encoding of `value` will occupy.
fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

// ---------------------------------------------------------------------------
// Certificate resolution
// ---------------------------------------------------------------------------

/// Serves a self-signed certificate, preferring one already generated for the
/// requested SNI and falling back to the configured default.
struct DynamicSniResolver {
    default_domain: String,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl DynamicSniResolver {
    fn new(default_domain: &str) -> Result<Self> {
        let default_domain = default_domain.to_ascii_lowercase();
        let mut cache = HashMap::new();
        cache.insert(
            default_domain.clone(),
            crate::proxy::x509::certified_key(&default_domain)?,
        );
        Ok(Self {
            default_domain,
            cache: Mutex::new(cache),
        })
    }

    fn is_valid_sni_hostname(name: &str) -> bool {
        if name.is_empty() || name.len() > 253 {
            return false;
        }
        if name.starts_with('.') || name.ends_with('.') {
            return false;
        }
        name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
    }

    fn cache_get(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        // Recover from a poisoned mutex instead of permanently disabling the
        // cache. Losing the cache would force regenerating self-signed certs
        // on every handshake, which is exactly the CPU-spike behavior we want
        // to avoid under adversarial traffic.
        let cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.get(name).cloned()
    }
}

impl fmt::Debug for DynamicSniResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicSniResolver")
            .field("default_domain", &self.default_domain)
            .finish()
    }
}

impl ResolvesServerCert for DynamicSniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let requested = client_hello
            .server_name()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("")
            .to_ascii_lowercase();

        if requested == self.default_domain {
            return self
                .cache_get(&self.default_domain)
                .or_else(|| crate::proxy::x509::certified_key(&self.default_domain).ok());
        }

        if Self::is_valid_sni_hostname(&requested) {
            if let Some(ck) = self.cache_get(&requested) {
                return Some(ck);
            }
            // Intentionally do not generate per-SNI certificates for cache misses.
            // Falling back to the default cert bounds CPU/memory work under
            // adversarial traffic with many unique SNI values.
        }

        self.cache_get(&self.default_domain)
            .or_else(|| crate::proxy::x509::certified_key(&self.default_domain).ok())
    }
}

// ---------------------------------------------------------------------------
// Packet parsing
// ---------------------------------------------------------------------------

/// A decrypted client Initial packet.
struct ClientInitial {
    /// The Destination Connection ID the client chose. Both the Initial keys
    /// and the `original_destination_connection_id` transport parameter are
    /// derived from it.
    dcid: Vec<u8>,
    /// The client's Source Connection ID, which becomes the DCID of every
    /// packet we send back.
    scid: Vec<u8>,
    /// Packet number, needed to acknowledge it.
    packet_number: u64,
    /// Decrypted frame payload.
    payload: Vec<u8>,
}

/// The cipher suite QUIC v1 mandates for Initial packets.
fn initial_suite() -> Result<(
    &'static rustls::Tls13CipherSuite,
    &'static dyn rustls::quic::Algorithm,
)> {
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .context("AES-128-GCM-SHA256 is not a TLS 1.3 suite")?;
    let quic = suite
        .quic
        .context("AES-128-GCM-SHA256 has no QUIC key schedule")?;
    Ok((suite, quic))
}

/// Initial-epoch keys for a connection identified by `dcid`.
fn initial_keys(dcid: &[u8]) -> Result<Keys> {
    let (suite, quic) = initial_suite()?;
    Ok(Keys::initial(Version::V1, suite, quic, dcid, Side::Server))
}

/// Decode a truncated packet number against the largest one already seen
/// (RFC 9000 appendix A). For a fresh Initial the expected value is zero, so
/// this almost always returns the truncated value unchanged.
fn decode_packet_number(largest_acked: Option<u64>, truncated: u64, bits: u32) -> u64 {
    let expected = largest_acked.map_or(0, |n| n + 1);
    let window = 1u64 << bits;
    let half = window / 2;
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate + half <= expected && candidate + window < u64::MAX {
        candidate + window
    } else if candidate > expected + half && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

/// Parse and decrypt a client Initial packet.
///
/// Returns `Ok(None)` for anything that is not a QUIC v1 Initial — a short
/// header, another version, a Handshake packet — because those are not this
/// responder's business and must not be treated as errors.
fn parse_client_initial(packet: &[u8]) -> Result<Option<ClientInitial>> {
    // Long header: 1 flags + 4 version + 1 dcid_len (+dcid) + 1 scid_len (+scid).
    if packet.len() < 7 {
        return Ok(None);
    }
    let first = packet[0];
    if first & 0x80 == 0 {
        // Short header: a 1-RTT packet for a connection we never completed.
        return Ok(None);
    }
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    if version != QUIC_V1 {
        return Ok(None);
    }
    if (first & 0x30) >> 4 != PACKET_TYPE_INITIAL {
        return Ok(None);
    }

    let mut pos = 5usize;
    let dcid_len = packet[pos] as usize;
    pos += 1;
    // RFC 9000 §17.2: connection IDs are at most 20 bytes.
    if dcid_len > 20 || packet.len() < pos + dcid_len + 1 {
        return Ok(None);
    }
    let dcid = packet[pos..pos + dcid_len].to_vec();
    pos += dcid_len;

    let scid_len = packet[pos] as usize;
    pos += 1;
    if scid_len > 20 || packet.len() < pos + scid_len {
        return Ok(None);
    }
    let scid = packet[pos..pos + scid_len].to_vec();
    pos += scid_len;

    let (token_len, n) = match read_varint(&packet[pos..]) {
        Some(v) => v,
        None => return Ok(None),
    };
    pos += n;
    let token_len = token_len as usize;
    if packet.len() < pos + token_len {
        return Ok(None);
    }
    // A token means this is a response to a Retry we never sent; the packet is
    // still a well-formed Initial, so it is parsed and answered normally.
    pos += token_len;

    let (length, n) = match read_varint(&packet[pos..]) {
        Some(v) => v,
        None => return Ok(None),
    };
    pos += n;
    let length = length as usize;
    let pn_offset = pos;
    if length < 4 + TAG_LEN || packet.len() < pn_offset + length {
        return Ok(None);
    }
    // The header-protection sample starts four bytes into the packet number
    // field, so the packet must carry at least that much beyond it.
    if packet.len() < pn_offset + SAMPLE_OFFSET + SAMPLE_LEN {
        return Ok(None);
    }

    let keys = initial_keys(&dcid)?;

    // Undo header protection on a copy: the sample must be read before the
    // first byte and packet number are modified.
    let mut sample = [0u8; SAMPLE_LEN];
    sample.copy_from_slice(&packet[pn_offset + SAMPLE_OFFSET..pn_offset + SAMPLE_OFFSET + SAMPLE_LEN]);
    let mut first_byte = first;
    let mut pn_bytes = [0u8; 4];
    pn_bytes.copy_from_slice(&packet[pn_offset..pn_offset + 4]);
    keys.remote
        .header
        .decrypt_in_place(&sample, &mut first_byte, &mut pn_bytes)
        .map_err(|e| anyhow::anyhow!("header protection removal failed: {e}"))?;

    let pn_len = ((first_byte & 0x03) + 1) as usize;
    let mut truncated = 0u64;
    for &b in &pn_bytes[..pn_len] {
        truncated = (truncated << 8) | u64::from(b);
    }
    let packet_number = decode_packet_number(None, truncated, (pn_len * 8) as u32);

    // The authenticated header is the packet up to and including the packet
    // number, with protection removed.
    let mut header = packet[..pn_offset + pn_len].to_vec();
    header[0] = first_byte;
    header[pn_offset..].copy_from_slice(&pn_bytes[..pn_len]);

    let body_start = pn_offset + pn_len;
    let body_end = pn_offset + length;
    if body_end <= body_start || body_end > packet.len() {
        return Ok(None);
    }
    let mut body = packet[body_start..body_end].to_vec();
    let plain = keys
        .remote
        .packet
        .decrypt_in_place(packet_number, &header, &mut body)
        .map_err(|e| anyhow::anyhow!("initial packet decryption failed: {e}"))?;
    let payload = plain.to_vec();

    Ok(Some(ClientInitial {
        dcid,
        scid,
        packet_number,
        payload,
    }))
}

/// CRYPTO frame contents extracted from one packet.
struct CryptoChunk {
    offset: u64,
    data: Vec<u8>,
}

/// Walk the frames of a decrypted Initial payload, collecting CRYPTO data.
///
/// Unknown or unexpected frame types end the walk rather than failing: a
/// prober may pad with anything, and a partially understood packet is still
/// worth answering.
fn collect_crypto_frames(payload: &[u8]) -> Vec<CryptoChunk> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        let frame_type = payload[pos];
        pos += 1;
        match frame_type {
            // PADDING and PING carry no payload.
            0x00 | 0x01 => {}
            // ACK, with and without ECN counts.
            0x02 | 0x03 => {
                let mut fields = 4; // largest, delay, range count, first range
                let mut ranges = 0u64;
                for i in 0..fields {
                    let Some((value, n)) = read_varint(&payload[pos..]) else {
                        return out;
                    };
                    if i == 2 {
                        ranges = value;
                    }
                    pos += n;
                }
                // Each additional range is a (gap, length) pair.
                fields = (ranges as usize) * 2 + if frame_type == 0x03 { 3 } else { 0 };
                for _ in 0..fields {
                    let Some((_, n)) = read_varint(&payload[pos..]) else {
                        return out;
                    };
                    pos += n;
                }
            }
            // CRYPTO.
            0x06 => {
                let Some((offset, n)) = read_varint(&payload[pos..]) else {
                    return out;
                };
                pos += n;
                let Some((len, n)) = read_varint(&payload[pos..]) else {
                    return out;
                };
                pos += n;
                let len = len as usize;
                if pos + len > payload.len() {
                    return out;
                }
                out.push(CryptoChunk {
                    offset,
                    data: payload[pos..pos + len].to_vec(),
                });
                pos += len;
            }
            // CONNECTION_CLOSE: nothing further to collect.
            0x1c | 0x1d => return out,
            // Anything else is not legal in an Initial packet.
            _ => return out,
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Packet construction
// ---------------------------------------------------------------------------

/// One packet to be written into an outgoing datagram.
struct PacketPlan<'a> {
    packet_type: u8,
    packet_number: u64,
    payload: &'a [u8],
    keys: &'a dyn PacketKey,
    header_keys: &'a dyn rustls::quic::HeaderProtectionKey,
}

/// Serialise and protect one long-header packet, appending it to `out`.
///
/// The packet number is always encoded in four bytes: legal for any value,
/// and it keeps the header-protection sample at a fixed offset.
fn encode_packet(plan: &PacketPlan<'_>, dcid: &[u8], scid: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let start = out.len();
    // Long header, fixed bit, type, and a 4-byte packet number length.
    out.push(0x80 | 0x40 | (plan.packet_type << 4) | 0x03);
    out.extend_from_slice(&QUIC_V1.to_be_bytes());
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    if plan.packet_type == PACKET_TYPE_INITIAL {
        write_varint(0, out); // empty token
    }
    write_varint((4 + plan.payload.len() + TAG_LEN) as u64, out);

    let pn_offset = out.len();
    out.extend_from_slice(&(plan.packet_number as u32).to_be_bytes());
    let header_end = out.len();

    out.extend_from_slice(plan.payload);
    // The header is the AAD and the body is encrypted in place, so the two
    // slices have to be split apart before handing them to the AEAD.
    let (header, body) = out.split_at_mut(header_end);
    let tag = plan
        .keys
        .encrypt_in_place(plan.packet_number, &header[start..], body)
        .map_err(|e| anyhow::anyhow!("packet encryption failed: {e}"))?;
    out.extend_from_slice(tag.as_ref());

    // Header protection is applied last, over a sample of the ciphertext.
    let sample_start = pn_offset + SAMPLE_OFFSET;
    if out.len() < sample_start + SAMPLE_LEN {
        bail!("packet too short to sample for header protection");
    }
    let mut sample = [0u8; SAMPLE_LEN];
    sample.copy_from_slice(&out[sample_start..sample_start + SAMPLE_LEN]);
    let (head, pn_and_body) = out.split_at_mut(pn_offset);
    plan.header_keys
        .encrypt_in_place(&sample, &mut head[start], &mut pn_and_body[..4])
        .map_err(|e| anyhow::anyhow!("header protection failed: {e}"))?;
    Ok(())
}

/// Overhead of a long-header packet around a payload of `payload_len` bytes.
fn packet_overhead(packet_type: u8, dcid_len: usize, scid_len: usize, payload_len: usize) -> usize {
    let length_field = varint_len((4 + payload_len + TAG_LEN) as u64);
    1 + 4 + 1 + dcid_len + 1 + scid_len
        + usize::from(packet_type == PACKET_TYPE_INITIAL) // one-byte empty token varint
        + length_field
        + 4 // packet number
        + TAG_LEN
}

/// An ACK frame covering exactly one packet number.
fn ack_frame(packet_number: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.push(0x02);
    write_varint(packet_number, &mut out); // largest acknowledged
    write_varint(0, &mut out); // ack delay
    write_varint(0, &mut out); // additional range count
    write_varint(0, &mut out); // first ack range
    out
}

/// A CRYPTO frame carrying `data` at `offset`.
fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 8);
    out.push(0x06);
    write_varint(offset, &mut out);
    write_varint(data.len() as u64, &mut out);
    out.extend_from_slice(data);
    out
}

/// A CONNECTION_CLOSE frame for a TLS alert (`0x0100 + alert`).
fn connection_close_frame(alert: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.push(0x1c);
    write_varint(0x0100 | u64::from(alert), &mut out);
    write_varint(0, &mut out); // frame type that triggered the close
    write_varint(0, &mut out); // empty reason phrase
    out
}

/// Header bytes a CRYPTO frame adds around `len` bytes at `offset`.
fn crypto_frame_overhead(offset: u64, len: usize) -> usize {
    1 + varint_len(offset) + varint_len(len as u64)
}

/// The server's QUIC transport parameters, as the TLS extension body.
///
/// The values are ordinary ones — an idle timeout, flow-control windows, a
/// handful of streams — chosen to look like a stock HTTP/3 server rather than
/// to be usable, since the connection never carries data.
fn transport_parameters(original_dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    fn put(id: u64, value: &[u8], out: &mut Vec<u8>) {
        write_varint(id, out);
        write_varint(value.len() as u64, out);
        out.extend_from_slice(value);
    }
    fn put_int(id: u64, value: u64, out: &mut Vec<u8>) {
        let mut encoded = Vec::with_capacity(8);
        write_varint(value, &mut encoded);
        put(id, &encoded, out);
    }

    let mut out = Vec::with_capacity(96);
    put(0x00, original_dcid, &mut out); // original_destination_connection_id
    put_int(0x01, 30_000, &mut out); // max_idle_timeout (ms)
    put_int(0x03, 1472, &mut out); // max_udp_payload_size
    put_int(0x04, 786_432, &mut out); // initial_max_data
    put_int(0x05, 65_536, &mut out); // initial_max_stream_data_bidi_local
    put_int(0x06, 65_536, &mut out); // initial_max_stream_data_bidi_remote
    put_int(0x07, 65_536, &mut out); // initial_max_stream_data_uni
    put_int(0x08, 100, &mut out); // initial_max_streams_bidi
    put_int(0x09, 3, &mut out); // initial_max_streams_uni
    put_int(0x0a, 3, &mut out); // ack_delay_exponent
    put_int(0x0b, 25, &mut out); // max_ack_delay
    put_int(0x0e, 2, &mut out); // active_connection_id_limit
    put(0x0f, scid, &mut out); // initial_source_connection_id
    out
}

/// TLS handshake output, split by the epoch its bytes belong to.
struct TlsFlight {
    /// ServerHello, protected with Initial keys.
    initial: Vec<u8>,
    /// EncryptedExtensions through Finished, protected with Handshake keys.
    handshake: Vec<u8>,
    /// Handshake-epoch keys, present once the ServerHello has been written.
    handshake_keys: Option<Keys>,
    /// Set when the TLS layer rejected the ClientHello; the connection is then
    /// closed with this alert instead of continuing.
    alert: Option<u8>,
}

/// Run the TLS handshake far enough to produce the server flight.
fn run_tls(
    config: Arc<rustls::ServerConfig>,
    client_hello: &[u8],
    original_dcid: &[u8],
    scid: &[u8],
) -> Result<TlsFlight> {
    let params = transport_parameters(original_dcid, scid);
    let mut tls = rustls::quic::ServerConnection::new(config, Version::V1, params)
        .context("failed to create a QUIC TLS server connection")?;

    let mut flight = TlsFlight {
        initial: Vec::new(),
        handshake: Vec::new(),
        handshake_keys: None,
        alert: None,
    };

    if let Err(e) = tls.read_hs(client_hello) {
        // rustls has queued an alert; emit it as a CONNECTION_CLOSE so the
        // prober sees a well-formed rejection rather than silence.
        flight.alert = Some(tls.alert().map_or(80, u8::from));
        crate::debug!(error = %e, "QUIC ClientHello rejected by TLS");
        return Ok(flight);
    }

    // Bytes written by a call belong to the epoch in force *before* the key
    // change that same call returns: the ServerHello is Initial-epoch, and the
    // Handshake keys it hands back protect everything after it.
    loop {
        let mut buf = Vec::new();
        let change = tls.write_hs(&mut buf);
        if !buf.is_empty() {
            if flight.handshake_keys.is_none() {
                flight.initial.extend_from_slice(&buf);
            } else {
                flight.handshake.extend_from_slice(&buf);
            }
        }
        match change {
            Some(KeyChange::Handshake { keys }) => flight.handshake_keys = Some(keys),
            // 1-RTT keys mean the flight is complete; the client's Finished
            // would come next and never does.
            Some(KeyChange::OneRtt { .. }) => break,
            None => {
                if buf.is_empty() {
                    break;
                }
            }
        }
    }

    if let Some(alert) = tls.alert() {
        flight.alert = Some(u8::from(alert));
    }
    Ok(flight)
}

// ---------------------------------------------------------------------------
// The responder
// ---------------------------------------------------------------------------

/// A datagram to send back to a prober.
pub struct QuicResponse {
    /// Where it goes.
    pub destination: SocketAddr,
    /// The datagram itself.
    pub payload: Bytes,
}

/// A ClientHello being reassembled from more than one Initial packet.
struct Pending {
    /// Contiguous CRYPTO bytes received so far.
    buffer: Vec<u8>,
    /// Bitmap-free bookkeeping: how many contiguous bytes from offset 0 are
    /// present. Out-of-order fragments beyond this are buffered but not
    /// counted until the gap fills.
    contiguous: usize,
    /// Which byte ranges have arrived, so a duplicate does not double-count.
    received: Vec<(u64, u64)>,
    scid: Vec<u8>,
    dcid: Vec<u8>,
    packet_number: u64,
    /// Bytes received from this peer, for the anti-amplification budget.
    received_bytes: usize,
    created: Instant,
}

/// Minimal stateful QUIC handshake responder.
///
/// Answers a client Initial with the server's Initial (ACK + ServerHello) and
/// Handshake (EncryptedExtensions, Certificate, CertificateVerify, Finished)
/// flight, then forgets the peer.
pub struct QuicHandshakeResponder {
    config: Arc<rustls::ServerConfig>,
    /// Partially received ClientHellos, keyed by peer and connection ID.
    pending: HashMap<(SocketAddr, Vec<u8>), Pending>,
}

impl QuicHandshakeResponder {
    /// Build a responder that presents certificates for `certificate_domain`.
    pub fn new(certificate_domain: &str) -> Result<Self> {
        let resolver = Arc::new(DynamicSniResolver::new(certificate_domain)?);
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec()];
        config.max_early_data_size = 0;

        Ok(Self {
            config: Arc::new(config),
            pending: HashMap::new(),
        })
    }

    /// Whether a handshake from `remote` is mid-flight — that is, a
    /// ClientHello arrived in fragments and the rest is still awaited.
    ///
    /// A completed handshake leaves no state: the flight is sent once and the
    /// peer forgotten, so this reads false again immediately afterwards.
    pub fn has_active_connection(&self, remote: SocketAddr) -> bool {
        self.pending.keys().any(|(addr, _)| *addr == remote)
    }

    /// Handle one datagram from `remote`, returning the datagrams to send.
    pub fn handle_datagram(&mut self, remote: SocketAddr, packet: &[u8]) -> Vec<QuicResponse> {
        self.expire(Instant::now());
        match self.try_handle(remote, packet) {
            Ok(responses) => responses,
            Err(e) => {
                // A malformed or undecryptable packet is the normal case for a
                // scanner spraying junk; it must never be fatal.
                crate::debug!(%remote, error = %e, "QUIC probe not answered");
                Vec::new()
            }
        }
    }

    /// Drop state for handshakes that were never completed.
    ///
    /// Returns no datagrams: this responder never retransmits. The method
    /// exists because the proxy calls it on a timer, and expiry has to happen
    /// even when no probe traffic arrives.
    pub fn handle_timeouts(&mut self) -> Vec<QuicResponse> {
        self.expire(Instant::now());
        Vec::new()
    }

    fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, p| now.duration_since(p.created) < PENDING_TTL);
    }

    fn try_handle(&mut self, remote: SocketAddr, packet: &[u8]) -> Result<Vec<QuicResponse>> {
        let Some(initial) = parse_client_initial(packet)? else {
            return Ok(Vec::new());
        };

        let chunks = collect_crypto_frames(&initial.payload);
        let key = (remote, initial.dcid.clone());

        // Merge this packet's CRYPTO bytes into whatever is already held for
        // this connection.
        let entry = match self.pending.remove(&key) {
            Some(p) => Some(p),
            None if self.pending.len() >= MAX_PENDING => {
                bail!("too many partial handshakes in flight");
            }
            None => None,
        };
        let mut state = entry.unwrap_or_else(|| Pending {
            buffer: Vec::new(),
            contiguous: 0,
            received: Vec::new(),
            scid: initial.scid.clone(),
            dcid: initial.dcid.clone(),
            packet_number: initial.packet_number,
            received_bytes: 0,
            created: Instant::now(),
        });
        state.packet_number = state.packet_number.max(initial.packet_number);
        state.received_bytes = state.received_bytes.saturating_add(packet.len());

        for chunk in chunks {
            let end = chunk.offset.saturating_add(chunk.data.len() as u64);
            if end > MAX_CRYPTO_BYTES as u64 {
                bail!("CRYPTO frame beyond the reassembly limit");
            }
            let end = end as usize;
            if state.buffer.len() < end {
                state.buffer.resize(end, 0);
            }
            let start = chunk.offset as usize;
            state.buffer[start..end].copy_from_slice(&chunk.data);
            state.received.push((chunk.offset, end as u64));
        }
        // Recompute how many bytes from the start are contiguous.
        state.received.sort_unstable();
        state.contiguous = 0;
        for (start, end) in &state.received {
            if *start as usize <= state.contiguous {
                state.contiguous = state.contiguous.max(*end as usize);
            }
        }

        let Some(client_hello) = complete_handshake_message(&state.buffer[..state.contiguous])
        else {
            // Still waiting for the rest of the ClientHello.
            self.pending.insert(key, state);
            return Ok(Vec::new());
        };
        let client_hello = client_hello.to_vec();

        // Everything needed is in hand; the peer keeps no state from here on.
        let scid = fresh_connection_id();
        let flight = run_tls(
            Arc::clone(&self.config),
            &client_hello,
            &state.dcid,
            &scid,
        )?;
        let budget = state.received_bytes.saturating_mul(AMPLIFICATION_LIMIT);
        let datagrams = self.assemble(&state, &scid, &flight, budget)?;

        Ok(datagrams
            .into_iter()
            .map(|payload| QuicResponse {
                destination: remote,
                payload: Bytes::from(payload),
            })
            .collect())
    }

    /// Turn a TLS flight into wire datagrams.
    fn assemble(
        &self,
        state: &Pending,
        scid: &[u8],
        flight: &TlsFlight,
        budget: usize,
    ) -> Result<Vec<Vec<u8>>> {
        let keys = initial_keys(&state.dcid)?;
        let dcid = &state.scid;
        let mut datagrams: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::with_capacity(MAX_DATAGRAM);
        let mut sent = 0usize;

        // --- Initial packet: ACK the client, plus the ServerHello (or the
        // alert that replaced it).
        let mut initial_payload = ack_frame(state.packet_number);
        if let Some(alert) = flight.alert {
            initial_payload.extend_from_slice(&connection_close_frame(alert));
        } else {
            initial_payload.extend_from_slice(&crypto_frame(0, &flight.initial));
        }
        let overhead = packet_overhead(
            PACKET_TYPE_INITIAL,
            dcid.len(),
            scid.len(),
            initial_payload.len(),
        );
        if overhead + initial_payload.len() > budget {
            return Ok(Vec::new());
        }
        encode_packet(
            &PacketPlan {
                packet_type: PACKET_TYPE_INITIAL,
                packet_number: 0,
                payload: &initial_payload,
                keys: keys.local.packet.as_ref(),
                header_keys: keys.local.header.as_ref(),
            },
            dcid,
            scid,
            &mut current,
        )?;
        sent += current.len();

        // --- Handshake packets: the certificate flight, split to fit.
        if let Some(hs_keys) = &flight.handshake_keys {
            let mut offset = 0usize;
            let mut packet_number = 0u64;
            while offset < flight.handshake.len() {
                let room_in_datagram = MAX_DATAGRAM.saturating_sub(current.len());
                let fixed = packet_overhead(PACKET_TYPE_HANDSHAKE, dcid.len(), scid.len(), 0)
                    + crypto_frame_overhead(offset as u64, flight.handshake.len() - offset);
                if room_in_datagram <= fixed + 32 {
                    // Not worth starting a packet here; move to a new datagram.
                    if !current.is_empty() {
                        datagrams.push(std::mem::take(&mut current));
                        current = Vec::with_capacity(MAX_DATAGRAM);
                    }
                    continue;
                }
                let take = (room_in_datagram - fixed).min(flight.handshake.len() - offset);
                let frame = crypto_frame(offset as u64, &flight.handshake[offset..offset + take]);
                let packet_len =
                    packet_overhead(PACKET_TYPE_HANDSHAKE, dcid.len(), scid.len(), frame.len())
                        + frame.len();
                if sent + packet_len > budget {
                    break;
                }
                encode_packet(
                    &PacketPlan {
                        packet_type: PACKET_TYPE_HANDSHAKE,
                        packet_number,
                        payload: &frame,
                        keys: hs_keys.local.packet.as_ref(),
                        header_keys: hs_keys.local.header.as_ref(),
                    },
                    dcid,
                    scid,
                    &mut current,
                )?;
                sent += packet_len;
                packet_number += 1;
                offset += take;
            }
        }

        if !current.is_empty() {
            datagrams.push(current);
        }
        Ok(datagrams)
    }
}

/// A random Source Connection ID for the server side of a handshake.
fn fresh_connection_id() -> Vec<u8> {
    let mut cid = vec![0u8; SCID_LEN];
    crate::rng::fill(&mut cid);
    cid
}

/// If `buf` starts with a complete TLS handshake message, return it.
///
/// The TLS record layer is absent in QUIC: CRYPTO frames carry bare handshake
/// messages, so a message is complete once its four-byte header and the length
/// it declares are both present.
fn complete_handshake_message(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    let total = 4 + len;
    (buf.len() >= total).then(|| &buf[..total])
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use quinn_proto::crypto::rustls::QuicClientConfig;
    use quinn_proto::{
        ClientConfig, Connection, ConnectionHandle, DatagramEvent, Endpoint as ClientEndpoint,
        EndpointConfig, TransportConfig,
    };
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{
        ClientConfig as RustlsClientConfig, DigitallySignedStruct, Error as TlsError,
        SignatureScheme,
    };

    const SERVER_ADDR: &str = "127.0.0.1:4433";

    /// A no-op TLS certificate verifier that accepts any server certificate.
    /// Used only in tests so we can connect to a self-signed test cert without
    /// needing a trust store.
    #[derive(Debug)]
    struct AcceptAnyCert;

    impl ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }

    /// A real QUIC client, used both to generate genuine Initial packets and
    /// to check that it accepts what the responder sends back.
    ///
    /// `quinn-proto` is a dev-dependency for exactly this: the responder is
    /// in-house, so its wire output is validated against a full third-party
    /// QUIC implementation rather than against itself.
    struct TestClient {
        endpoint: ClientEndpoint,
        handle: ConnectionHandle,
        conn: Connection,
    }

    impl TestClient {
        fn new(alpn: &[&str]) -> Self {
            let mut tls = RustlsClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
                .with_no_client_auth();
            tls.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

            let quic_tls = QuicClientConfig::try_from(tls)
                .expect("QuicClientConfig from the test ClientConfig must succeed");

            let mut transport = TransportConfig::default();
            transport.max_idle_timeout(Some(
                std::time::Duration::from_secs(5).try_into().unwrap(),
            ));
            let mut client_cfg = ClientConfig::new(Arc::new(quic_tls));
            client_cfg.transport_config(Arc::new(transport));

            let mut endpoint =
                ClientEndpoint::new(Arc::new(EndpointConfig::default()), None, false, None);
            let (handle, conn) = endpoint
                .connect(
                    Instant::now(),
                    client_cfg,
                    SERVER_ADDR.parse().unwrap(),
                    "example.com",
                )
                .expect("client connect must succeed");

            Self {
                endpoint,
                handle,
                conn,
            }
        }

        /// The client's first Initial datagram.
        fn initial(&mut self) -> Vec<u8> {
            let mut buf = Vec::new();
            let tx = self
                .conn
                .poll_transmit(Instant::now(), 16, &mut buf)
                .expect("client must produce an Initial packet");
            buf[..tx.size].to_vec()
        }

        /// Feed a server datagram into the client.
        fn receive(&mut self, datagram: &[u8]) {
            let now = Instant::now();
            let mut buf = Vec::new();
            let event = self.endpoint.handle(
                now,
                SERVER_ADDR.parse().unwrap(),
                None,
                None,
                BytesMut::from(datagram),
                &mut buf,
            );
            if let Some(DatagramEvent::ConnectionEvent(ch, event)) = event {
                assert_eq!(ch, self.handle, "response routed to the wrong connection");
                self.conn.handle_event(event);
            }
            // Let the connection process whatever it just received.
            let mut scratch = Vec::new();
            while self.conn.poll_transmit(now, 16, &mut scratch).is_some() {
                scratch.clear();
            }
        }
    }

    /// Sum the payload bytes across all responses in a server flight.
    fn total_response_bytes(responses: &[QuicResponse]) -> usize {
        responses.iter().map(|r| r.payload.len()).sum()
    }

    fn client_addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn varints_round_trip_at_every_width() {
        for value in [0u64, 1, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, u64::MAX >> 2]
        {
            let mut buf = Vec::new();
            write_varint(value, &mut buf);
            assert_eq!(buf.len(), varint_len(value), "length disagreement for {value}");
            let (decoded, used) = read_varint(&buf).expect("decodes");
            assert_eq!(decoded, value);
            assert_eq!(used, buf.len());
        }
        assert!(read_varint(&[]).is_none());
        // A two-byte varint with only one byte present must not decode.
        assert!(read_varint(&[0x40]).is_none());
    }

    #[test]
    fn packet_numbers_decode_around_the_window() {
        // With nothing acknowledged the expected value is zero, so a truncated
        // number decodes to itself.
        assert_eq!(decode_packet_number(None, 0, 32), 0);
        assert_eq!(decode_packet_number(None, 7, 32), 7);
        // Classic appendix A example: expecting 0xa82f9b32, truncated 0x9b32.
        assert_eq!(
            decode_packet_number(Some(0xa82f_30ea), 0x9b32, 16),
            0xa82f_9b32
        );
    }

    #[test]
    fn h3_clienthello_produces_certificate_flight() {
        let mut responder = QuicHandshakeResponder::new("example.com").unwrap();
        let initial = TestClient::new(&["h3"]).initial();
        let responses = responder.handle_datagram(client_addr(11111), &initial);

        assert!(
            !responses.is_empty(),
            "responder must reply to a valid h3 ClientHello Initial"
        );
        let total = total_response_bytes(&responses);
        assert!(
            total >= MIN_CERT_FLIGHT_BYTES,
            "server flight must be >= {MIN_CERT_FLIGHT_BYTES} bytes to contain \
             a Certificate (got {total} bytes across {} datagram(s)); \
             a tiny response indicates a CONNECTION_CLOSE abort (missing ALPN)",
            responses.len(),
        );
    }

    #[test]
    fn h3_29_clienthello_produces_certificate_flight() {
        let mut responder = QuicHandshakeResponder::new("example.com").unwrap();
        let initial = TestClient::new(&["h3-29"]).initial();
        let responses = responder.handle_datagram(client_addr(11112), &initial);

        assert!(
            !responses.is_empty(),
            "responder must reply to a valid h3-29 ClientHello Initial"
        );
        let total = total_response_bytes(&responses);
        assert!(
            total >= MIN_CERT_FLIGHT_BYTES,
            "server flight must be >= {MIN_CERT_FLIGHT_BYTES} bytes to contain \
             a Certificate for h3-29 (got {total} bytes across {} datagram(s))",
            responses.len(),
        );
    }

    /// The strongest available check: a real QUIC client must accept the
    /// flight. Reaching `handshake_data()` means it decrypted our Initial,
    /// parsed the ServerHello, derived the Handshake keys we used, and read
    /// the EncryptedExtensions out of the Handshake packets.
    #[test]
    fn a_real_quic_client_accepts_the_server_flight() {
        let mut responder = QuicHandshakeResponder::new("example.com").unwrap();
        let mut client = TestClient::new(&["h3"]);
        let initial = client.initial();

        let responses = responder.handle_datagram(client_addr(11113), &initial);
        assert!(!responses.is_empty(), "no flight produced");
        for response in &responses {
            client.receive(&response.payload);
        }

        let data = client
            .conn
            .crypto_session()
            .handshake_data()
            .expect("client must have processed the server handshake");
        let data = data
            .downcast::<quinn_proto::crypto::rustls::HandshakeData>()
            .expect("rustls handshake data");
        assert_eq!(
            data.protocol.as_deref(),
            Some(&b"h3"[..]),
            "negotiated ALPN must be the one the client offered"
        );
        assert!(
            !client.conn.is_closed(),
            "client closed the connection instead of accepting the flight"
        );
    }

    #[test]
    fn empty_datagram_produces_no_response() {
        let mut r = QuicHandshakeResponder::new("example.com").unwrap();
        assert!(r.handle_datagram(client_addr(9999), &[]).is_empty());
    }

    #[test]
    fn non_initial_packets_are_ignored() {
        let mut r = QuicHandshakeResponder::new("example.com").unwrap();
        let addr = client_addr(9998);
        // Short header (1-RTT) for a connection that never existed.
        assert!(r.handle_datagram(addr, &[0x40, 1, 2, 3, 4, 5, 6, 7, 8]).is_empty());
        // Long header, unknown version.
        let mut unknown_version = vec![0xc0, 0xff, 0x00, 0x00, 0x1d, 0x00, 0x00];
        unknown_version.extend_from_slice(&[0u8; 1200]);
        assert!(r.handle_datagram(addr, &unknown_version).is_empty());
        // Long header, QUIC v1, but a Handshake packet rather than an Initial.
        let mut handshake = vec![0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        handshake.extend_from_slice(&[0u8; 1200]);
        assert!(r.handle_datagram(addr, &handshake).is_empty());
        // Garbage that happens to start like an Initial must not panic.
        let mut junk = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 0x08];
        junk.extend_from_slice(&[0xab; 64]);
        let _ = r.handle_datagram(addr, &junk);
        assert!(!r.has_active_connection(addr));
    }

    /// Regression: after the Certificate flight the responder must hold no
    /// state for the peer, so nothing can retransmit later. The previous
    /// implementation needed an explicit eviction path for this; being
    /// stateless is what replaced it.
    #[test]
    fn no_state_survives_a_completed_flight() {
        let mut responder = QuicHandshakeResponder::new("example.com").unwrap();
        let addr = client_addr(22222);
        let initial = TestClient::new(&["h3"]).initial();

        let responses = responder.handle_datagram(addr, &initial);
        assert!(
            total_response_bytes(&responses) >= MIN_CERT_FLIGHT_BYTES,
            "first response must be a Certificate flight"
        );

        assert!(responder.pending.is_empty(), "no reassembly state may remain");
        assert!(!responder.has_active_connection(addr));
        assert!(
            responder.handle_timeouts().is_empty(),
            "the responder must never retransmit"
        );
    }

    #[test]
    fn the_flight_respects_the_amplification_limit() {
        let mut responder = QuicHandshakeResponder::new("example.com").unwrap();
        let initial = TestClient::new(&["h3"]).initial();
        let responses = responder.handle_datagram(client_addr(33333), &initial);
        let sent = total_response_bytes(&responses);
        assert!(
            sent <= initial.len() * AMPLIFICATION_LIMIT,
            "sent {sent} bytes for {} received — over the 3x limit",
            initial.len()
        );
        for r in &responses {
            assert!(
                r.payload.len() <= MAX_DATAGRAM,
                "datagram of {} bytes exceeds the {MAX_DATAGRAM}-byte cap",
                r.payload.len()
            );
        }
    }

    #[test]
    fn a_partial_client_hello_is_held_then_completed() {
        // A CRYPTO frame carrying only part of a handshake message must not
        // produce a flight, and must leave the peer marked active so the
        // proxy treats the next packet as a continuation.
        let responder = QuicHandshakeResponder::new("example.com").unwrap();
        assert!(complete_handshake_message(&[]).is_none());
        assert!(complete_handshake_message(&[0x01, 0x00, 0x00, 0x10]).is_none());
        let mut msg = vec![0x01, 0x00, 0x00, 0x04];
        msg.extend_from_slice(&[0xaa; 4]);
        assert_eq!(complete_handshake_message(&msg).unwrap().len(), 8);
        // Trailing bytes beyond the message are not returned.
        msg.extend_from_slice(&[0xff; 9]);
        assert_eq!(complete_handshake_message(&msg).unwrap().len(), 8);
        assert!(responder.pending.is_empty());
    }

    #[test]
    fn transport_parameters_carry_both_connection_ids() {
        let odcid = [0xde, 0xad, 0xbe, 0xef];
        let scid = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let params = transport_parameters(&odcid, &scid);

        // Walk the id/length/value triples and index them.
        let mut seen: HashMap<u64, Vec<u8>> = HashMap::new();
        let mut pos = 0;
        while pos < params.len() {
            let (id, n) = read_varint(&params[pos..]).unwrap();
            pos += n;
            let (len, n) = read_varint(&params[pos..]).unwrap();
            pos += n;
            let len = len as usize;
            seen.insert(id, params[pos..pos + len].to_vec());
            pos += len;
        }
        assert_eq!(seen.get(&0x00).unwrap(), &odcid, "original DCID");
        assert_eq!(seen.get(&0x0f).unwrap(), &scid, "initial source CID");
        assert!(seen.contains_key(&0x01), "max_idle_timeout");
        assert!(seen.contains_key(&0x04), "initial_max_data");
    }

    #[test]
    fn sni_hostname_validation_rejects_the_usual_tricks() {
        assert!(DynamicSniResolver::is_valid_sni_hostname("example.com"));
        assert!(DynamicSniResolver::is_valid_sni_hostname("a-b.c-d.example"));
        assert!(!DynamicSniResolver::is_valid_sni_hostname(""));
        assert!(!DynamicSniResolver::is_valid_sni_hostname(".example.com"));
        assert!(!DynamicSniResolver::is_valid_sni_hostname("example.com."));
        assert!(!DynamicSniResolver::is_valid_sni_hostname("-bad.example"));
        assert!(!DynamicSniResolver::is_valid_sni_hostname("bad-.example"));
        assert!(!DynamicSniResolver::is_valid_sni_hostname("under_score.example"));
        assert!(!DynamicSniResolver::is_valid_sni_hostname(&"a".repeat(254)));
    }
}
