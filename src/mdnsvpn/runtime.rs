//! Extract the bundled MasterDnsVPN ELF onto disk so the supervisor has
//! something to `exec`. The blob is gzipped and embedded via
//! `include_bytes!`; we decompress on demand, verify against the SHA
//! recorded in `vendor/MDNSVPN_VERSION`, and `chmod 755` so the kernel
//! will execve it.
//!
//! Re-extraction is skipped when the on-disk ELF already matches the
//! embedded SHA — keeps second-and-subsequent startups fast.
//!
//! Mirror of `src/mtproxy/runtime.rs` and `src/xray/runtime.rs`. Kept
//! structurally identical so a future cleanup pass can deduplicate the
//! three via a shared helper.

use std::fs;
use std::io::{Read, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use crate::config::CONFIG;
use crate::mdnsvpn::{MDNSVPN_SHA256, MDNSVPN_VERSION};

/// Gzipped MasterDnsVPN ELF, picked at build time by `build.rs` based on
/// `CARGO_CFG_TARGET_ARCH`. ~1.9 MiB compressed; ~4.5 MiB extracted.
const MDNSVPN_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mdnsvpn.gz"));

/// Idempotently materialise the bundled MasterDnsVPN ELF at
/// `<mdnsvpn_dir>/mdnsvpn`. Returns the absolute path. Safe to call
/// repeatedly — the function short-circuits when the existing file
/// already hashes to `MDNSVPN_SHA256`.
pub fn extract_bundled_binary() -> Result<PathBuf> {
    // In-memory mode: exec MasterDnsVPN from an anonymous memfd, never disk.
    if CONFIG.in_memory {
        return crate::memexec::load("mdnsvpn", MDNSVPN_GZ, MDNSVPN_SHA256);
    }

    let dir = PathBuf::from(&CONFIG.mdnsvpn_dir);
    fs::create_dir_all(&dir)
        .with_context(|| format!("create mdnsvpn runtime dir {}", dir.display()))?;
    let target = dir.join("mdnsvpn");

    if matches_embedded_sha(&target).unwrap_or(false) {
        crate::debug!(
            path = %target.display(),
            "mdnsvpn ELF already extracted; skipping"
        );
        return Ok(target);
    }

    let tmp = dir.join("mdnsvpn.partial");
    {
        let mut out = fs::File::create(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        crate::inflate::gunzip_to_writer(MDNSVPN_GZ, &mut out)
            .with_context(|| format!("decompress mdnsvpn ELF to {}", tmp.display()))?;
        out.flush().ok();
    }

    let actual = sha256_file(&tmp)?;
    if actual != MDNSVPN_SHA256 {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!(
            "extracted mdnsvpn SHA-256 mismatch: expected {MDNSVPN_SHA256}, got {actual}. \
             vendor/MDNSVPN_VERSION is out of sync with vendor/mdnsvpn-linux-amd64.gz."
        ));
    }

    let perms = fs::Permissions::from_mode(0o755);
    fs::set_permissions(&tmp, perms)
        .with_context(|| format!("chmod 0755 {}", tmp.display()))?;

    fs::rename(&tmp, &target)
        .with_context(|| format!("rename {} → {}", tmp.display(), target.display()))?;

    crate::info!(
        path = %target.display(),
        version = MDNSVPN_VERSION,
        sha256 = MDNSVPN_SHA256,
        "Extracted bundled MasterDnsVPN binary"
    );
    Ok(target)
}

fn matches_embedded_sha(path: &Path) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    Ok(sha256_file(path)? == MDNSVPN_SHA256)
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
        assert_eq!(MDNSVPN_SHA256.len(), 64, "COFFEEBLACK_MDNSVPN_SHA256 must be a hex SHA-256");
        assert!(MDNSVPN_SHA256.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn embedded_version_is_set() {
        // MasterDnsVPN uses date-stamped tags like
        // `v2026.05.10.180256-27c7e11`. Just sanity-check that the
        // string is populated when the bundle is present.
        assert!(
            !MDNSVPN_VERSION.is_empty(),
            "COFFEEBLACK_MDNSVPN_VERSION must be populated when bundled"
        );
    }
}
