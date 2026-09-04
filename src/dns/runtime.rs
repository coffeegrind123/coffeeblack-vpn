//! Extract bundled DNS-stack ELFs onto disk so the supervisor (and tor's
//! ClientTransportPlugin spawner) have something to `exec`. Mirrors
//! `src/xray/runtime.rs` — gz-compressed blobs are embedded via
//! `include_bytes!`, decompressed on demand, SHA-verified, and chmod'd
//! to 0755.
//!
//! Why five separate include_bytes! vs. one tarball: per-binary
//! re-extraction is idempotent (skip when on-disk SHA matches), so a
//! `dnscrypt-proxy` version bump only re-decompresses dnscrypt-proxy,
//! not the whole bundle. Also: tor's ClientTransportPlugin discovery
//! needs `lyrebird` / `snowflake` / `webtunnel` at known paths *before*
//! tor itself starts, regardless of whether they were just extracted.
//!
//! The whole module is compiled `#[cfg(dns_bundled)]` — when the bundle
//! is absent, `mod.rs` re-exports a no-op surface so callers get a
//! clear "not bundled" error instead of a build break.

#![cfg(dns_bundled)]

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use crate::config::CONFIG;

/// One bundled binary. Fields are `&'static str` so the array can live
/// in a `const` and the per-binary `include_bytes!` calls compile away
/// to direct slice references.
pub struct BundledBinary {
    /// Filename to use on disk (also what tor's torrc references for PTs).
    pub name: &'static str,
    /// SHA-256 of the uncompressed ELF, lowercase hex. Empty string when
    /// the binary isn't bundled for the current target — the constructor
    /// rejects these so we never reach the extractor with no SHA.
    pub sha256: &'static str,
    /// Upstream version (informational; surfaced to /about).
    pub version: &'static str,
    /// Gzipped ELF, picked at build time by `build.rs`.
    pub gz: &'static [u8],
}

// `include_bytes!` only takes a literal path, so we expand each binary
// inline. build.rs guarantees these files exist when `dns_bundled` is
// active.
const DNSCRYPT_PROXY_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dnscrypt-proxy.gz"));
const TOR_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tor.gz"));
const LYREBIRD_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/lyrebird.gz"));
const SNOWFLAKE_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/snowflake.gz"));
const WEBTUNNEL_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/webtunnel.gz"));

/// Static table of every bundled binary. Order doesn't matter at
/// runtime; this is what `extract_all` iterates.
pub const BINARIES: &[BundledBinary] = &[
    BundledBinary {
        name: "dnscrypt-proxy",
        sha256: env!("AWG_EASY_DNS_DNSCRYPT_PROXY_SHA256"),
        version: env!("AWG_EASY_DNS_DNSCRYPT_PROXY_VERSION"),
        gz: DNSCRYPT_PROXY_GZ,
    },
    BundledBinary {
        name: "tor",
        sha256: env!("AWG_EASY_DNS_TOR_SHA256"),
        version: env!("AWG_EASY_DNS_TOR_VERSION"),
        gz: TOR_GZ,
    },
    BundledBinary {
        name: "lyrebird",
        sha256: env!("AWG_EASY_DNS_LYREBIRD_SHA256"),
        version: env!("AWG_EASY_DNS_LYREBIRD_VERSION"),
        gz: LYREBIRD_GZ,
    },
    BundledBinary {
        name: "snowflake",
        sha256: env!("AWG_EASY_DNS_SNOWFLAKE_SHA256"),
        version: env!("AWG_EASY_DNS_SNOWFLAKE_VERSION"),
        gz: SNOWFLAKE_GZ,
    },
    BundledBinary {
        name: "webtunnel",
        sha256: env!("AWG_EASY_DNS_WEBTUNNEL_SHA256"),
        version: env!("AWG_EASY_DNS_WEBTUNNEL_VERSION"),
        gz: WEBTUNNEL_GZ,
    },
];

/// Extract every bundled binary into `<dns_dir>/bin/`. Idempotent —
/// any binary whose on-disk SHA already matches the embedded SHA is
/// skipped. Returns the absolute path to `<dns_dir>/bin/` so callers
/// can compose tor's `ClientTransportPlugin` paths against it.
pub fn extract_all() -> Result<PathBuf> {
    let bin_dir = bin_dir();
    fs::create_dir_all(&bin_dir)
        .with_context(|| format!("create dns bin dir {}", bin_dir.display()))?;

    for bin in BINARIES {
        extract_one(bin, &bin_dir)?;
    }
    Ok(bin_dir)
}

/// Extract a single binary on demand. Used by callers (e.g. the tor
/// supervisor) that want to surface a pinpoint error if just one
/// binary fails its SHA check, instead of failing the whole bundle.
pub fn extract(name: &str) -> Result<PathBuf> {
    let bin_dir = bin_dir();
    fs::create_dir_all(&bin_dir)
        .with_context(|| format!("create dns bin dir {}", bin_dir.display()))?;
    let bin = BINARIES
        .iter()
        .find(|b| b.name == name)
        .ok_or_else(|| anyhow!("unknown bundled binary {name:?}"))?;
    extract_one(bin, &bin_dir)?;
    Ok(bin_dir.join(bin.name))
}

/// Resolve a path the supervisor can `exec` for a binary it launches
/// *itself* — `dnscrypt-proxy` and `tor`. In `IN_MEMORY` mode the ELF is
/// loaded into an anonymous memfd (never disk); otherwise it is extracted
/// to `<dns_dir>/bin/` as before.
///
/// This is deliberately **not** used for tor's pluggable-transport
/// plugins (`lyrebird` / `snowflake` / `webtunnel`): tor `exec`s those by
/// the path written into the torrc, and a memfd lives only in *our*
/// descriptor table, so PT plugins must always be materialised on the
/// (tmpfs) filesystem via [`extract`].
pub fn resolve_exec(name: &str) -> Result<PathBuf> {
    if CONFIG.in_memory {
        let bin = BINARIES
            .iter()
            .find(|b| b.name == name)
            .ok_or_else(|| anyhow!("unknown bundled binary {name:?}"))?;
        return crate::memexec::load(bin.name, bin.gz, bin.sha256);
    }
    extract(name)
}

/// Path operators should set in `dns_dir` config — exposed so the
/// supervisor can build absolute paths without re-deriving from CONFIG
/// every call.
pub fn bin_dir() -> PathBuf {
    PathBuf::from(&CONFIG.dns_dir).join("bin")
}

fn extract_one(bin: &BundledBinary, bin_dir: &Path) -> Result<()> {
    let target = bin_dir.join(bin.name);

    if matches_embedded_sha(&target, bin.sha256).unwrap_or(false) {
        crate::debug!(
            name = bin.name,
            path = %target.display(),
            "DNS bundle: ELF already extracted; skipping"
        );
        return Ok(());
    }

    // Decompress to a sibling temp file then atomic-rename — same
    // crash-safety pattern as xray/runtime.rs. A SIGKILL during
    // decompress can't leave a half-written ELF that a later SHA check
    // would mistake for "ready" because the partial never gets the
    // canonical name.
    let tmp = bin_dir.join(format!("{}.partial", bin.name));
    {
        let mut out = fs::File::create(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        crate::inflate::gunzip_to_writer(bin.gz, &mut out)
            .with_context(|| format!("decompress {} ELF to {}", bin.name, tmp.display()))?;
    }

    let actual = sha256_file(&tmp)?;
    if actual != bin.sha256 {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!(
            "extracted {} SHA-256 mismatch: expected {}, got {actual}. \
             vendor/DNS_BUNDLE_VERSION is out of sync with vendor/{}-linux-*.gz.",
            bin.name,
            bin.sha256,
            bin.name,
        ));
    }

    let perms = fs::Permissions::from_mode(0o755);
    fs::set_permissions(&tmp, perms)
        .with_context(|| format!("chmod 0755 {}", tmp.display()))?;

    fs::rename(&tmp, &target)
        .with_context(|| format!("rename {} → {}", tmp.display(), target.display()))?;

    crate::info!(
        name = bin.name,
        path = %target.display(),
        version = bin.version,
        sha256 = bin.sha256,
        "Extracted bundled DNS-stack binary"
    );
    Ok(())
}

fn matches_embedded_sha(path: &Path, expected: &str) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    Ok(sha256_file(path)? == expected)
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
    fn every_binary_has_a_64_hex_sha() {
        // Sanity: build.rs must have populated each SHA when dns_bundled
        // was set. Empty SHAs would mean we built with an incomplete
        // bundle — that should have prevented `dns_bundled` from being
        // emitted in the first place.
        for bin in BINARIES {
            assert_eq!(
                bin.sha256.len(),
                64,
                "AWG_EASY_DNS_{}_SHA256 must be a hex SHA-256 (got {} chars)",
                bin.name.to_uppercase(),
                bin.sha256.len()
            );
            assert!(
                bin.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                "AWG_EASY_DNS_{}_SHA256 contains non-hex characters",
                bin.name.to_uppercase()
            );
            assert!(!bin.version.is_empty(), "{} version is blank", bin.name);
            assert!(!bin.gz.is_empty(), "{} gz blob is empty", bin.name);
        }
    }

    #[test]
    fn binaries_table_has_no_duplicate_names() {
        let mut seen = std::collections::HashSet::new();
        for bin in BINARIES {
            assert!(seen.insert(bin.name), "duplicate binary {}", bin.name);
        }
    }
}
