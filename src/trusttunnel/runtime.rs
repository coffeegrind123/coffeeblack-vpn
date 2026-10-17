//! Extract the bundled TrustTunnel endpoint ELF onto disk so the supervisor has
//! something to `exec`. The blob is gzipped and embedded via
//! `include_bytes!`; we decompress on demand, verify against the SHA
//! recorded in `vendor/TRUSTTUNNEL_VERSION`, and `chmod 755` so the kernel
//! will execve it.
//!
//! Re-extraction is skipped when the on-disk ELF already matches the
//! embedded SHA — keeps second-and-subsequent startups fast.
//!
//! Mirror of `src/mdnsvpn/runtime.rs`, `src/mtproxy/runtime.rs` and
//! `src/xray/runtime.rs`. Kept structurally identical so a future cleanup
//! pass can deduplicate them via a shared helper.

use std::fs;
use std::io::{Read, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use crate::config::CONFIG;
use crate::trusttunnel::{TRUSTTUNNEL_SHA256, TRUSTTUNNEL_VERSION};

/// Gzipped TrustTunnel endpoint ELF, picked at build time by `build.rs` based on
/// `CARGO_CFG_TARGET_ARCH`. ~6.9 MiB compressed; ~16 MiB extracted.
const TRUSTTUNNEL_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trusttunnel.gz"));

/// Idempotently materialise the bundled TrustTunnel endpoint ELF at
/// `<trusttunnel_dir>/trusttunnel_endpoint`. Returns the absolute path. Safe to call
/// repeatedly — the function short-circuits when the existing file
/// already hashes to `TRUSTTUNNEL_SHA256`.
pub fn extract_bundled_binary() -> Result<PathBuf> {
    // In-memory mode: exec TrustTunnel from an anonymous memfd, never disk.
    if CONFIG.in_memory {
        return crate::memexec::load("trusttunnel_endpoint", TRUSTTUNNEL_GZ, TRUSTTUNNEL_SHA256);
    }

    let dir = PathBuf::from(&CONFIG.trusttunnel_dir);
    fs::create_dir_all(&dir)
        .with_context(|| format!("create trusttunnel runtime dir {}", dir.display()))?;
    let target = dir.join("trusttunnel_endpoint");

    if matches_embedded_sha(&target).unwrap_or(false) {
        crate::debug!(
            path = %target.display(),
            "trusttunnel_endpoint ELF already extracted; skipping"
        );
        return Ok(target);
    }

    let tmp = dir.join("trusttunnel_endpoint.partial");
    {
        let mut out = fs::File::create(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        crate::inflate::gunzip_to_writer(TRUSTTUNNEL_GZ, &mut out)
            .with_context(|| format!("decompress trusttunnel_endpoint ELF to {}", tmp.display()))?;
        out.flush().ok();
    }

    let actual = sha256_file(&tmp)?;
    if actual != TRUSTTUNNEL_SHA256 {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!(
            "extracted trusttunnel_endpoint SHA-256 mismatch: expected {TRUSTTUNNEL_SHA256}, got {actual}. \
             vendor/TRUSTTUNNEL_VERSION is out of sync with vendor/trusttunnel-linux-amd64.gz."
        ));
    }

    let perms = fs::Permissions::from_mode(0o755);
    fs::set_permissions(&tmp, perms)
        .with_context(|| format!("chmod 0755 {}", tmp.display()))?;

    fs::rename(&tmp, &target)
        .with_context(|| format!("rename {} → {}", tmp.display(), target.display()))?;

    crate::info!(
        path = %target.display(),
        version = TRUSTTUNNEL_VERSION,
        sha256 = TRUSTTUNNEL_SHA256,
        "Extracted bundled TrustTunnel binary"
    );
    Ok(target)
}

fn matches_embedded_sha(path: &Path) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    Ok(sha256_file(path)? == TRUSTTUNNEL_SHA256)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path)
        .with_context(|| format!("open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("read {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(crate::encoding::hex_encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_sha_is_64_hex_chars() {
        assert_eq!(TRUSTTUNNEL_SHA256.len(), 64, "COFFEEBLACK_TRUSTTUNNEL_SHA256 must be a hex SHA-256");
        assert!(TRUSTTUNNEL_SHA256.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn embedded_version_is_set() {
        // TrustTunnel tags are `v`-prefixed semver (`v1.1.0`). Just
        // sanity-check that the string is populated when bundled.
        assert!(
            !TRUSTTUNNEL_VERSION.is_empty(),
            "COFFEEBLACK_TRUSTTUNNEL_VERSION must be populated when bundled"
        );
    }
}
