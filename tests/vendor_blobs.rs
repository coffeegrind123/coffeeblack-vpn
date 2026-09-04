//! End-to-end check of the in-house gzip decoder against the real vendored
//! blobs.
//!
//! `src/inflate.rs`'s unit tests decode what `flate2`'s encoder produces. This
//! one decodes what actually ships: every `vendor/*.gz` artifact, verified
//! against the SHA-256 recorded in the matching `vendor/*_VERSION` pin file —
//! the same bytes `build.rs` embeds and the runtime extractors check.
//!
//! The blobs are CI artifacts and are not committed, so each case skips (with
//! a note) when its file is absent. A build machine that has run
//! `scripts/build.sh` exercises all of them.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use coffeeblack_vpn::encoding::hex_encode;
use coffeeblack_vpn::inflate;
use sha2::{Digest, Sha256};

fn vendor_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor")
}

/// Collect every `<NAME>_AMD64_SHA256 = <hex>` assignment from the pin files.
fn pinned_shas() -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pin in [
        "XRAY_VERSION",
        "TELEMT_VERSION",
        "MDNSVPN_VERSION",
        "DNS_BUNDLE_VERSION",
    ] {
        let path = vendor_dir().join(pin);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            if let Some(name) = key.strip_suffix("_AMD64_SHA256") {
                if !value.is_empty() {
                    out.insert(name.to_ascii_lowercase().replace('_', "-"), value.to_string());
                }
            }
        }
    }
    out
}

#[test]
fn every_vendored_blob_decompresses_to_its_pinned_sha256() {
    let shas = pinned_shas();
    assert!(
        !shas.is_empty(),
        "no pinned SHAs parsed from vendor/*_VERSION — the pin format changed"
    );

    let mut checked = 0;
    for (name, expected) in &shas {
        let blob = vendor_dir().join(format!("{name}-linux-amd64.gz"));
        if !blob.exists() {
            eprintln!("skipping {name}: {} not present", blob.display());
            continue;
        }
        let gz = std::fs::read(&blob).expect("read vendored blob");

        // Streaming path (what the on-disk extractors use).
        let mut streamed = Vec::new();
        let written = inflate::gunzip_to_writer(&gz, &mut streamed)
            .unwrap_or_else(|e| panic!("gunzip {name}: {e}"));
        assert_eq!(written as usize, streamed.len());

        // One-shot path (what the memfd loader uses) must agree byte for byte.
        let oneshot = inflate::gunzip(&gz).expect("one-shot gunzip");
        assert_eq!(oneshot, streamed, "{name}: streaming and one-shot disagree");

        let mut h = Sha256::new();
        h.update(&streamed);
        let actual = hex_encode(h.finalize());
        assert_eq!(
            &actual, expected,
            "{name}: decompressed SHA-256 does not match vendor pin"
        );

        // Every blob is an ELF; a decoder that silently truncated would still
        // hash differently, but this makes the failure obvious.
        assert_eq!(&streamed[..4], b"\x7fELF", "{name}: not an ELF");
        checked += 1;
    }

    eprintln!("verified {checked} of {} pinned blobs", shas.len());
}
