//! Self-signed X.509 certificate generation for the QUIC probe responder.
//!
//! Replaces `rcgen` (and the `yasna` DER writer under it). The responder needs
//! exactly one shape of certificate — an ECDSA P-256 leaf, self-signed, with a
//! single dNSName SAN — so what `rcgen` contributed was a general certificate
//! builder we used one corner of.
//!
//! The key pair and the signature come from `ring`, which is already the
//! project's crypto provider (rustls builds on it). Everything else here is
//! DER: a handful of TLV writers and the ASN.1 from RFC 5280 §4.1.
//!
//! The certificate is deliberately unremarkable — a one-year validity window
//! starting a day ago, a random 16-byte serial, `CN` equal to the SAN, and the
//! basic-constraints / key-usage / EKU extensions a real server leaf carries.
//! A probe that parses it should see a plausible (if untrusted) certificate,
//! which is the entire point of the imitation.

use anyhow::{Context, Result};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

/// DER tag numbers used below.
mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0c;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
    pub const UTC_TIME: u8 = 0x17;
}

/// Encode a DER length.
fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        // Long form: 0x80 | number of length bytes, then big-endian length.
        let bytes = len.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
}

/// Write one tag-length-value.
fn tlv(tag: u8, value: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    der_len(value.len(), out);
    out.extend_from_slice(value);
}

/// Build a tag-length-value as its own buffer.
fn tlv_vec(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    tlv(tag, value, &mut out);
    out
}

/// A DER `INTEGER` holding an unsigned big-endian value, with the leading zero
/// byte ASN.1 requires when the high bit would otherwise mark it negative.
fn integer(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    let trimmed = &bytes[start..];
    let mut value = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        value.push(0);
    }
    value.extend_from_slice(trimmed);
    tlv_vec(tag::INTEGER, &value)
}

/// A DER `BIT STRING` with no unused trailing bits.
fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(bytes.len() + 1);
    value.push(0); // unused bits
    value.extend_from_slice(bytes);
    tlv_vec(tag::BIT_STRING, &value)
}

/// Concatenate DER elements into a `SEQUENCE`.
fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    let mut inner = Vec::new();
    for p in parts {
        inner.extend_from_slice(p);
    }
    tlv_vec(tag::SEQUENCE, &inner)
}

/// `AlgorithmIdentifier` for `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
fn alg_ecdsa_sha256() -> Vec<u8> {
    sequence(&[&tlv_vec(
        tag::OID,
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
    )])
}

/// `SubjectPublicKeyInfo` for an uncompressed P-256 point.
fn spki(public_key: &[u8]) -> Vec<u8> {
    // id-ecPublicKey (1.2.840.10045.2.1) with the prime256v1 named curve
    // (1.2.840.10045.3.1.7).
    let alg = sequence(&[
        &tlv_vec(tag::OID, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
        &tlv_vec(tag::OID, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
    ]);
    sequence(&[&alg, &bit_string(public_key)])
}

/// A `Name` holding a single `CN=<common_name>` attribute.
fn common_name(common_name: &str) -> Vec<u8> {
    // AttributeType id-at-commonName is 2.5.4.3.
    let atv = sequence(&[
        &tlv_vec(tag::OID, &[0x55, 0x04, 0x03]),
        &tlv_vec(tag::UTF8_STRING, common_name.as_bytes()),
    ]);
    let rdn = tlv_vec(tag::SET, &atv);
    tlv_vec(tag::SEQUENCE, &rdn)
}

/// Format a Unix timestamp as an ASN.1 `UTCTime` (`YYMMDDhhmmssZ`).
///
/// UTCTime cannot express years from 2050 on; certificates that far out would
/// need GeneralizedTime. The validity window here is a year wide, so that
/// limit is decades away and is asserted rather than handled.
fn utc_time(ts: time::OffsetDateTime) -> Result<Vec<u8>> {
    anyhow::ensure!(
        (1950..2050).contains(&ts.year()),
        "UTCTime cannot represent the year {}",
        ts.year()
    );
    let text = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        ts.year() % 100,
        u8::from(ts.month()),
        ts.day(),
        ts.hour(),
        ts.minute(),
        ts.second()
    );
    Ok(tlv_vec(tag::UTC_TIME, text.as_bytes()))
}

/// One X.509 extension: `SEQUENCE { OID, [critical BOOLEAN], OCTET STRING }`.
fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let oid = tlv_vec(tag::OID, oid);
    let wrapped = tlv_vec(tag::OCTET_STRING, value);
    if critical {
        let flag = tlv_vec(tag::BOOLEAN, &[0xff]);
        sequence(&[&oid, &flag, &wrapped])
    } else {
        sequence(&[&oid, &wrapped])
    }
}

/// A generated certificate and the key that signed it.
pub struct SelfSigned {
    /// DER-encoded certificate.
    pub cert_der: Vec<u8>,
    /// PKCS#8 DER-encoded private key.
    pub key_pkcs8: Vec<u8>,
}

/// Generate a self-signed ECDSA P-256 certificate for `dns_name`.
pub fn generate(dns_name: &str) -> Result<SelfSigned> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| anyhow::anyhow!("failed to generate a P-256 key pair"))?;
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|_| anyhow::anyhow!("generated key pair failed to parse"))?;

    let mut serial = [0u8; 16];
    crate::rng::fill(&mut serial);
    // Keep the serial positive: a leading high bit would make it a negative
    // INTEGER, which some parsers reject outright.
    serial[0] &= 0x7f;
    serial[0] |= 0x01;

    let now = crate::datetime::now_utc();
    let not_before = now - time::Duration::days(1);
    let not_after = now + time::Duration::days(365);

    let name = common_name(dns_name);
    let validity = sequence(&[&utc_time(not_before)?, &utc_time(not_after)?]);

    // Extensions: basicConstraints (CA:FALSE), keyUsage (digitalSignature),
    // extKeyUsage (serverAuth), subjectAltName (the dNSName).
    let basic_constraints = extension(&[0x55, 0x1d, 0x13], true, &sequence(&[]));
    let key_usage = extension(
        &[0x55, 0x1d, 0x0f],
        true,
        // BIT STRING with 7 unused bits and the digitalSignature bit set.
        &tlv_vec(tag::BIT_STRING, &[0x07, 0x80]),
    );
    let ext_key_usage = extension(
        &[0x55, 0x1d, 0x25],
        false,
        // id-kp-serverAuth 1.3.6.1.5.5.7.3.1
        &sequence(&[&tlv_vec(
            tag::OID,
            &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01],
        )]),
    );
    // GeneralName dNSName is context tag [2], primitive.
    let san = extension(
        &[0x55, 0x1d, 0x11],
        false,
        &tlv_vec(tag::SEQUENCE, &tlv_vec(0x82, dns_name.as_bytes())),
    );
    let extensions = sequence(&[&basic_constraints, &key_usage, &ext_key_usage, &san]);
    // [3] EXPLICIT Extensions
    let extensions = tlv_vec(0xa3, &extensions);

    // [0] EXPLICIT Version, v3 == 2.
    let version = tlv_vec(0xa0, &integer(&[2]));

    let tbs = sequence(&[
        &version,
        &integer(&serial),
        &alg_ecdsa_sha256(),
        &name,
        &validity,
        &name,
        &spki(key_pair.public_key().as_ref()),
        &extensions,
    ]);

    let signature = key_pair
        .sign(&rng, &tbs)
        .map_err(|_| anyhow::anyhow!("failed to sign the certificate"))?;

    let cert_der = sequence(&[
        &tbs,
        &alg_ecdsa_sha256(),
        &bit_string(signature.as_ref()),
    ]);

    Ok(SelfSigned {
        cert_der,
        key_pkcs8: pkcs8.as_ref().to_vec(),
    })
}

/// Generate a certificate and wrap it as a rustls [`CertifiedKey`], ready for
/// a `ResolvesServerCert` implementation.
///
/// [`CertifiedKey`]: rustls::sign::CertifiedKey
pub fn certified_key(dns_name: &str) -> Result<std::sync::Arc<rustls::sign::CertifiedKey>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let generated = generate(dns_name)
        .with_context(|| format!("failed to generate a certificate for '{dns_name}'"))?;
    let key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(generated.key_pkcs8).into();
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .context("generated private key is not supported by the ring provider")?;
    Ok(std::sync::Arc::new(rustls::sign::CertifiedKey::new(
        vec![CertificateDer::from(generated.cert_der)],
        signing_key,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal DER walker for the assertions below: returns (tag, value,
    /// rest) for the element at the front of `der`.
    fn read_tlv(der: &[u8]) -> (u8, &[u8], &[u8]) {
        let tag = der[0];
        let first = der[1];
        let (len, header) = if first < 0x80 {
            (first as usize, 2)
        } else {
            let n = (first & 0x7f) as usize;
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | der[2 + i] as usize;
            }
            (len, 2 + n)
        };
        (tag, &der[header..header + len], &der[header + len..])
    }

    #[test]
    fn der_lengths_use_the_shortest_form() {
        let mut out = Vec::new();
        der_len(0, &mut out);
        assert_eq!(out, vec![0x00]);
        out.clear();
        der_len(127, &mut out);
        assert_eq!(out, vec![0x7f]);
        out.clear();
        der_len(128, &mut out);
        assert_eq!(out, vec![0x81, 0x80]);
        out.clear();
        der_len(300, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x2c]);
        out.clear();
        der_len(70000, &mut out);
        assert_eq!(out, vec![0x83, 0x01, 0x11, 0x70]);
    }

    #[test]
    fn integers_stay_positive() {
        // High bit set: a leading zero must be inserted.
        assert_eq!(integer(&[0xff]), vec![0x02, 0x02, 0x00, 0xff]);
        // Leading zeros are trimmed.
        assert_eq!(integer(&[0x00, 0x00, 0x2a]), vec![0x02, 0x01, 0x2a]);
        // All-zero collapses to a single zero byte.
        assert_eq!(integer(&[0x00, 0x00]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn utc_time_is_zero_padded() {
        let ts = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let der = utc_time(ts).unwrap();
        let (tag, value, _) = read_tlv(&der);
        assert_eq!(tag, 0x17);
        assert_eq!(value.len(), 13);
        assert!(value.ends_with(b"Z"));
        assert!(value.iter().all(|b| b.is_ascii_digit() || *b == b'Z'));
    }

    #[test]
    fn certificate_has_the_expected_der_structure() {
        let cert = generate("www.example.com").expect("generate");
        let (tag, body, rest) = read_tlv(&cert.cert_der);
        assert_eq!(tag, 0x30, "Certificate is a SEQUENCE");
        assert!(rest.is_empty(), "no trailing bytes after the certificate");

        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        let (tbs_tag, tbs, after_tbs) = read_tlv(body);
        assert_eq!(tbs_tag, 0x30);
        let (alg_tag, _alg, after_alg) = read_tlv(after_tbs);
        assert_eq!(alg_tag, 0x30);
        let (sig_tag, sig, tail) = read_tlv(after_alg);
        assert_eq!(sig_tag, 0x03, "signatureValue is a BIT STRING");
        assert_eq!(sig[0], 0, "no unused bits");
        assert!(tail.is_empty());

        // TBSCertificate starts with [0] EXPLICIT version = 2 (v3).
        let (ver_tag, ver, _) = read_tlv(tbs);
        assert_eq!(ver_tag, 0xa0);
        assert_eq!(ver, &[0x02, 0x01, 0x02]);
    }

    #[test]
    fn certificate_carries_the_dns_name_in_cn_and_san() {
        let cert = generate("vpn.example.org").expect("generate");
        let needle = b"vpn.example.org";
        let occurrences = cert
            .cert_der
            .windows(needle.len())
            .filter(|w| *w == needle)
            .count();
        assert_eq!(
            occurrences, 3,
            "the name appears as the issuer CN, the subject CN (the certificate \
             is self-signed, so those are the same Name) and the dNSName SAN"
        );
    }

    #[test]
    fn signature_verifies_against_the_embedded_public_key() {
        use ring::signature;

        let cert = generate("verify.example").expect("generate");
        let (_, body, _) = read_tlv(&cert.cert_der);
        let (_, tbs, after_tbs) = read_tlv(body);
        // Re-encode the TBS exactly as it appears inside the certificate: the
        // signature covers the tag and length too, not just the contents.
        let tbs_der = &body[..tbs.len() + (body.len() - tbs.len() - after_tbs.len())];
        let (_, _, after_alg) = read_tlv(after_tbs);
        let (_, sig, _) = read_tlv(after_alg);

        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &cert.key_pkcs8,
            &SystemRandom::new(),
        )
        .expect("key parses");
        let public = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            key_pair.public_key().as_ref(),
        );
        public
            .verify(tbs_der, &sig[1..])
            .expect("the certificate signature must verify");
    }

    #[test]
    fn each_certificate_is_unique() {
        let a = generate("dup.example").unwrap();
        let b = generate("dup.example").unwrap();
        assert_ne!(a.cert_der, b.cert_der, "serial and key must be fresh");
        assert_ne!(a.key_pkcs8, b.key_pkcs8);
    }

    #[test]
    fn rustls_accepts_the_generated_key_pair() {
        let ck = certified_key("rustls.example").expect("certified key");
        assert_eq!(ck.cert.len(), 1);
        assert!(!ck.cert[0].as_ref().is_empty());
    }
}
