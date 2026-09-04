//! Extract the bundled Xray ELF onto disk so the supervisor has something
//! to `exec`. The blob is gzipped and embedded via `include_bytes!`; we
//! decompress on demand, verify against the SHA recorded in
//! `vendor/XRAY_VERSION`, and `chmod 755` so the kernel will execve it.
//!
//! Re-extraction is skipped when the on-disk ELF already matches the
//! embedded SHA, which keeps the second-and-subsequent startups fast (no
//! point streaming 36 MB through flate2 every boot).
//!
//! Operators who want to track Xray independently of awg-easy-rs releases
//! can set `XRAY_BIN_PATH=/usr/local/bin/xray` and bypass this module
//! entirely — the supervisor honours that env var first.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use crate::config::CONFIG;

/// Embedded Xray-core release tag (see vendor/XRAY_VERSION).
pub const XRAY_VERSION: &str = env!("AWG_EASY_XRAY_VERSION");

/// SHA-256 of the *uncompressed* Xray ELF for the current target arch.
pub const XRAY_SHA256: &str = env!("AWG_EASY_XRAY_SHA256");

/// Gzipped Xray ELF, picked at build time by `build.rs` based on
/// `CARGO_CFG_TARGET_ARCH`. ~12-13 MiB compressed; ~35 MiB extracted.
const XRAY_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xray.gz"));

/// Resolve the path the supervisor should `exec`. Falls back to the
/// bundled binary unless `XRAY_BIN_PATH` is set, in which case we trust
/// the operator's binary verbatim.
///
/// In `IN_MEMORY` mode the bundled binary is exec'd from an anonymous
/// memfd (see [`crate::memexec`]) and never touches disk; an operator
/// `XRAY_BIN_PATH` override is still honoured verbatim as a real path.
pub fn resolve_binary() -> Result<PathBuf> {
    if let Some(ref override_path) = CONFIG.xray_binary_override {
        let p = PathBuf::from(override_path);
        if !p.is_file() {
            return Err(anyhow!(
                "XRAY_BIN_PATH={} is set but the file does not exist or is not regular",
                p.display()
            ));
        }
        return Ok(p);
    }
    if CONFIG.in_memory {
        return crate::memexec::load("xray", XRAY_GZ, XRAY_SHA256);
    }
    extract_bundled_binary()
}

/// Idempotently materialise the bundled Xray ELF at `<xray_dir>/xray`.
/// Returns the absolute path. Safe to call repeatedly — the function
/// short-circuits when the existing file already hashes to `XRAY_SHA256`.
pub fn extract_bundled_binary() -> Result<PathBuf> {
    let dir = PathBuf::from(&CONFIG.xray_dir);
    fs::create_dir_all(&dir)
        .with_context(|| format!("create xray runtime dir {}", dir.display()))?;
    let target = dir.join("xray");

    if matches_embedded_sha(&target).unwrap_or(false) {
        crate::debug!(
            path = %target.display(),
            "xray ELF already extracted; skipping"
        );
        return Ok(target);
    }

    // Decompress directly to the target path via a temp sibling so a crash
    // mid-extract can't leave a half-written ELF that an old SHA check
    // would later mistake for "ready".
    let tmp = dir.join("xray.partial");
    {
        let mut out = fs::File::create(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        crate::inflate::gunzip_to_writer(XRAY_GZ, &mut out)
            .with_context(|| format!("decompress xray ELF to {}", tmp.display()))?;
        out.flush().ok();
    }

    // Verify before promoting — `include_bytes!` is reliable, but a
    // mismatched vendor/XRAY_VERSION would otherwise silently install a
    // mystery binary.
    let actual = sha256_file(&tmp)?;
    if actual != XRAY_SHA256 {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!(
            "extracted xray SHA-256 mismatch: expected {XRAY_SHA256}, got {actual}. \
             vendor/XRAY_VERSION is out of sync with vendor/xray-linux-*.gz."
        ));
    }

    // chmod 755 before rename — operators sometimes mount xray_dir from a
    // volume with a tighter umask.
    let perms = fs::Permissions::from_mode(0o755);
    fs::set_permissions(&tmp, perms)
        .with_context(|| format!("chmod 0755 {}", tmp.display()))?;

    fs::rename(&tmp, &target)
        .with_context(|| format!("rename {} → {}", tmp.display(), target.display()))?;

    crate::info!(
        path = %target.display(),
        version = XRAY_VERSION,
        sha256 = XRAY_SHA256,
        "Extracted bundled Xray binary"
    );
    Ok(target)
}

fn matches_embedded_sha(path: &Path) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    Ok(sha256_file(path)? == XRAY_SHA256)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path)
        .with_context(|| format!("open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).with_context(|| format!("read {}", path.display()))?;
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
    use std::sync::Mutex;

    // Serialise tests that share the global xray_dir to avoid file-system
    // races when run with `--test-threads`.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn embedded_sha_is_64_hex_chars() {
        // Sanity: build.rs must set this for bundled targets.
        assert_eq!(XRAY_SHA256.len(), 64, "AWG_EASY_XRAY_SHA256 must be a hex SHA-256");
        assert!(XRAY_SHA256.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn embedded_version_is_set() {
        assert!(XRAY_VERSION.starts_with('v'), "XRAY_VERSION should look like vN.N.N");
    }

    #[test]
    #[serial_test::serial(xray_e2e_env)]
    fn extract_then_skip_is_idempotent() {
        let _g = TEST_LOCK.lock().unwrap();
        let tmpdir = tempdir_for_test();
        std::env::set_var("WG_EASY_XRAY_DIR", &tmpdir);
        // Force a fresh CONFIG read for this thread is not possible (it's a
        // LazyLock), so we reach into extract_bundled_binary's behaviour by
        // testing decompression+SHA invariants directly via a private dir.
        let dir = std::path::PathBuf::from(&tmpdir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("xray");
        // First decompress.
        let mut out = std::fs::File::create(&target).unwrap();
        crate::inflate::gunzip_to_writer(XRAY_GZ, &mut out).unwrap();
        let sha = sha256_file(&target).unwrap();
        assert_eq!(sha, XRAY_SHA256, "decompressed ELF must match embedded SHA");
        // Re-running the SHA check must agree.
        assert!(matches_embedded_sha(&target).unwrap());
        // Tampering should flip the result.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&target)
                .unwrap();
            f.write_all(b"corrupted").unwrap();
        }
        assert!(!matches_embedded_sha(&target).unwrap());
        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    fn tempdir_for_test() -> String {
        // Avoid pulling in the `tempfile` crate just for one test path.
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        format!("/tmp/awg-easy-rs-xray-test-{pid}-{nanos}")
    }
}
