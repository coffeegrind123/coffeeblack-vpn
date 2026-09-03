//! Build-time embedding of the vendored ELFs for the target architecture.
//!
//! Four independent bundles, each gated by its own `cfg`:
//!
//! - `xray_bundled`    — Xray-core (single ELF, ~13 MB compressed) for the
//!   Browsing-mode VLESS+Reality+Vision flow. Pinned in
//!   `vendor/XRAY_VERSION`.
//! - `dns_bundled`     — DNS stack: dnscrypt-proxy, tor, lyrebird,
//!   snowflake, webtunnel. Five ELFs per architecture. Pinned in
//!   `vendor/DNS_BUNDLE_VERSION`. The bundle is all-or-nothing per
//!   target arch — partial bundles are intentionally rejected so
//!   runtime supervisor code can rely on every component being present.
//! - `telemt_bundled`  — telemt (single ELF, ~6 MB compressed) — Rust +
//!   Tokio MTProxy server for Telegram (Fake-TLS / SNI fronting, per-user
//!   secrets via runtime HTTP API). Pinned in `vendor/TELEMT_VERSION`.
//! - `mdnsvpn_bundled` — MasterDnsVPN (Go) server (single ELF, ~2 MB
//!   compressed). DNS-tunnel VPN server: clients pack TCP/SOCKS5 traffic
//!   into DNS queries through public resolvers, server listens on UDP/53
//!   for the tunnel envelopes and re-emits the inner TCP through a real
//!   socks5/forwarder. Pinned in `vendor/MDNSVPN_VERSION`.
//!
//! All three bundles surface their version + per-binary SHA-256 to the
//! rest of the crate via `cargo:rustc-env=AWG_EASY_*` constants so the
//! runtime extractor can verify-on-extract and the `/about` page can
//! display what shipped.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Each name here corresponds to a `<NAME>_VERSION` /
/// `<NAME>_AMD64_SHA256` pair in `vendor/DNS_BUNDLE_VERSION` and a
/// `vendor/<file>-linux-amd64.gz` blob. Adding a binary to the bundle
/// means appending one row here + dropping the blob + updating the
/// version file. (x86_64 only — arm64 was dropped intentionally.)
const DNS_BUNDLE_BINARIES: &[DnsBinary] = &[
    DnsBinary {
        // Logical name used in env-var prefix / sha key
        env_prefix: "DNSCRYPT_PROXY",
        // Filename root (must match `vendor/<file>-linux-<arch>.gz`)
        file_root: "dnscrypt-proxy",
    },
    DnsBinary { env_prefix: "TOR",       file_root: "tor" },
    DnsBinary { env_prefix: "LYREBIRD",  file_root: "lyrebird" },
    DnsBinary { env_prefix: "SNOWFLAKE", file_root: "snowflake" },
    DnsBinary { env_prefix: "WEBTUNNEL", file_root: "webtunnel" },
];

struct DnsBinary {
    env_prefix: &'static str,
    file_root: &'static str,
}

fn main() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));

    process_xray_bundle(&target_os, &target_arch, &out_dir, &manifest_dir);
    process_dns_bundle(&target_os, &target_arch, &out_dir, &manifest_dir);
    process_telemt_bundle(&target_os, &target_arch, &out_dir, &manifest_dir);
    process_mdnsvpn_bundle(&target_os, &target_arch, &out_dir, &manifest_dir);
}

// ---------------------------------------------------------------------------
// Xray bundle (existing)
// ---------------------------------------------------------------------------

fn process_xray_bundle(
    target_os: &str,
    target_arch: &str,
    out_dir: &Path,
    manifest_dir: &Path,
) {
    println!("cargo:rerun-if-changed=vendor/XRAY_VERSION");
    println!("cargo:rerun-if-changed=vendor/xray-linux-amd64.gz");
    // Always declare the cfg so `#[cfg(xray_bundled)]` doesn't warn on
    // builds where the blob is absent.
    println!("cargo:rustc-check-cfg=cfg(xray_bundled)");

    let version_path = manifest_dir.join("vendor/XRAY_VERSION");
    let version_text = fs::read_to_string(&version_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", version_path.display()));
    let kv = parse_kv(&version_text);
    let xray_version = kv
        .get("XRAY_VERSION")
        .expect("XRAY_VERSION not set in vendor/XRAY_VERSION");

    // x86_64 is the only supported target. arm64 was removed intentionally
    // (see vendor/README.md).
    let bundle = match (target_os, target_arch) {
        ("linux", "x86_64") => Some(("xray-linux-amd64.gz", "XRAY_AMD64_SHA256")),
        _ => None,
    };

    let Some((blob_name, sha_key)) = bundle else {
        println!("cargo:rustc-env=AWG_EASY_XRAY_VERSION={xray_version}");
        println!("cargo:rustc-env=AWG_EASY_XRAY_SHA256=");
        println!(
            "cargo:warning=Xray bundled mode is not available for target {target_os}-{target_arch}; \
             awg-easy-rs will build without Browsing-mode support."
        );
        return;
    };

    let blob_src = manifest_dir.join("vendor").join(blob_name);
    let expected_sha = kv.get(sha_key).map(String::as_str).unwrap_or("");

    // The blob is a release artifact produced by `scripts/build.sh`
    // (or the `Build and Release` workflow). On a fresh checkout
    // without that step having run, the file is absent — proceed
    // without the bundle so contributors can still `cargo check`,
    // mirroring the DNS bundle's missing-blob tolerance.
    if !blob_src.is_file() || expected_sha.is_empty() {
        println!("cargo:rustc-env=AWG_EASY_XRAY_VERSION={xray_version}");
        println!("cargo:rustc-env=AWG_EASY_XRAY_SHA256=");
        println!(
            "cargo:warning=Xray blob missing ({}) — building without xray_bundled. \
             Run scripts/build.sh to materialise it from the pinned version.",
            blob_src.display()
        );
        return;
    }

    let blob_dst = out_dir.join("xray.gz");
    fs::copy(&blob_src, &blob_dst).unwrap_or_else(|e| {
        panic!("copy {} → {}: {e}", blob_src.display(), blob_dst.display())
    });

    println!("cargo:rustc-env=AWG_EASY_XRAY_VERSION={xray_version}");
    println!("cargo:rustc-env=AWG_EASY_XRAY_SHA256={expected_sha}");
    println!("cargo:rustc-cfg=xray_bundled");
}

// ---------------------------------------------------------------------------
// DNS bundle
// ---------------------------------------------------------------------------

fn process_dns_bundle(
    target_os: &str,
    target_arch: &str,
    out_dir: &Path,
    manifest_dir: &Path,
) {
    println!("cargo:rerun-if-changed=vendor/DNS_BUNDLE_VERSION");
    for bin in DNS_BUNDLE_BINARIES {
        println!(
            "cargo:rerun-if-changed=vendor/{}-linux-amd64.gz",
            bin.file_root
        );
    }
    // Always declare the cfg so `#[cfg(dns_bundled)]` doesn't warn on
    // builds where the bundle is absent.
    println!("cargo:rustc-check-cfg=cfg(dns_bundled)");

    let version_path = manifest_dir.join("vendor/DNS_BUNDLE_VERSION");
    let version_text = match fs::read_to_string(&version_path) {
        Ok(s) => s,
        Err(e) => {
            // Non-fatal — DNS bundling is opt-in. Build proceeds without it.
            println!(
                "cargo:warning=DNS bundle version file missing ({}); skipping DNS bundle",
                e
            );
            for bin in DNS_BUNDLE_BINARIES {
                println!("cargo:rustc-env=AWG_EASY_DNS_{}_VERSION=", bin.env_prefix);
                println!("cargo:rustc-env=AWG_EASY_DNS_{}_SHA256=", bin.env_prefix);
            }
            println!("cargo:rustc-env=AWG_EASY_DNS_BUNDLE_INCOMPLETE=DNS_BUNDLE_VERSION missing");
            return;
        }
    };
    let kv = parse_kv(&version_text);

    // Map target_arch to (suffix used in filenames, suffix used in SHA keys).
    // x86_64 is the only supported target — arm64 was removed.
    let arch = match (target_os, target_arch) {
        ("linux", "x86_64") => Some(("amd64", "AMD64")),
        _ => None,
    };

    let Some((file_arch, sha_arch)) = arch else {
        println!(
            "cargo:warning=DNS bundle is not available for target {target_os}-{target_arch}; \
             awg-easy-rs will build without bundled DNS support."
        );
        for bin in DNS_BUNDLE_BINARIES {
            println!("cargo:rustc-env=AWG_EASY_DNS_{}_VERSION=", bin.env_prefix);
            println!("cargo:rustc-env=AWG_EASY_DNS_{}_SHA256=", bin.env_prefix);
        }
        println!(
            "cargo:rustc-env=AWG_EASY_DNS_BUNDLE_INCOMPLETE=unsupported target \
{target_os}-{target_arch}"
        );
        return;
    };

    // First pass: gate on completeness. Every binary in the bundle must
    // have both a non-empty version AND a non-empty SHA for THIS arch.
    // Partial bundles → no `dns_bundled` cfg, supervisor code stays out
    // of the build entirely. We still emit per-binary env vars (blank
    // if missing) so /about can show what would have shipped.
    let mut missing: Vec<String> = Vec::new();
    for bin in DNS_BUNDLE_BINARIES {
        let ver_key = format!("{}_VERSION", bin.env_prefix);
        let sha_key = format!("{}_{}_SHA256", bin.env_prefix, sha_arch);
        let ver = kv.get(&ver_key).map(|s| s.as_str()).unwrap_or("");
        let sha = kv.get(&sha_key).map(|s| s.as_str()).unwrap_or("");
        let blob_path = manifest_dir
            .join("vendor")
            .join(format!("{}-linux-{}.gz", bin.file_root, file_arch));
        if ver.is_empty() {
            missing.push(format!("{} (no version pinned)", bin.env_prefix));
        } else if sha.is_empty() {
            missing.push(format!(
                "{} (no {} SHA pinned)",
                bin.env_prefix, sha_arch
            ));
        } else if !blob_path.exists() {
            missing.push(format!(
                "{} (vendor blob {} missing)",
                bin.env_prefix,
                blob_path.display()
            ));
        }
    }

    if !missing.is_empty() {
        println!(
            "cargo:warning=DNS bundle incomplete for {target_arch}, building without dns_bundled: {}",
            missing.join(", ")
        );
        for bin in DNS_BUNDLE_BINARIES {
            let ver = kv
                .get(&format!("{}_VERSION", bin.env_prefix))
                .cloned()
                .unwrap_or_default();
            let sha = kv
                .get(&format!("{}_{}_SHA256", bin.env_prefix, sha_arch))
                .cloned()
                .unwrap_or_default();
            println!("cargo:rustc-env=AWG_EASY_DNS_{}_VERSION={ver}", bin.env_prefix);
            println!("cargo:rustc-env=AWG_EASY_DNS_{}_SHA256={sha}", bin.env_prefix);
        }
        // The pins alone don't decide `dns_bundled` — the blobs have to be
        // on disk too, and they're CI artifacts (vendor/*.gz is untracked).
        // Surface *why* the bundle is off so the DNS bundle API (and the
        // tests) can tell a deliberate no-bundle build from a broken pin.
        println!(
            "cargo:rustc-env=AWG_EASY_DNS_BUNDLE_INCOMPLETE={}",
            missing.join(", ")
        );
        return;
    }

    // All present — copy each blob to OUT_DIR with a stable name the
    // runtime can `include_bytes!`. Names mirror the vendor file root.
    for bin in DNS_BUNDLE_BINARIES {
        let blob_src = manifest_dir
            .join("vendor")
            .join(format!("{}-linux-{}.gz", bin.file_root, file_arch));
        let blob_dst = out_dir.join(format!("{}.gz", bin.file_root));
        fs::copy(&blob_src, &blob_dst).unwrap_or_else(|e| {
            panic!(
                "copy {} → {}: {e}",
                blob_src.display(),
                blob_dst.display()
            )
        });

        let ver = &kv[&format!("{}_VERSION", bin.env_prefix)];
        let sha = &kv[&format!("{}_{}_SHA256", bin.env_prefix, sha_arch)];
        println!("cargo:rustc-env=AWG_EASY_DNS_{}_VERSION={ver}", bin.env_prefix);
        println!("cargo:rustc-env=AWG_EASY_DNS_{}_SHA256={sha}", bin.env_prefix);
    }
    println!("cargo:rustc-env=AWG_EASY_DNS_BUNDLE_INCOMPLETE=");
    println!("cargo:rustc-cfg=dns_bundled");
}

// ---------------------------------------------------------------------------
// Telemt bundle (Telegram MTProxy)
// ---------------------------------------------------------------------------

fn process_telemt_bundle(
    target_os: &str,
    target_arch: &str,
    out_dir: &Path,
    manifest_dir: &Path,
) {
    println!("cargo:rerun-if-changed=vendor/TELEMT_VERSION");
    println!("cargo:rerun-if-changed=vendor/telemt-linux-amd64.gz");
    println!("cargo:rustc-check-cfg=cfg(telemt_bundled)");

    let version_path = manifest_dir.join("vendor/TELEMT_VERSION");
    let version_text = fs::read_to_string(&version_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", version_path.display()));
    let kv = parse_kv(&version_text);
    let telemt_version = kv
        .get("TELEMT_VERSION")
        .expect("TELEMT_VERSION not set in vendor/TELEMT_VERSION");

    // Same arch story as the rest of the vendor tree: x86_64-linux only.
    let bundle = match (target_os, target_arch) {
        ("linux", "x86_64") => Some(("telemt-linux-amd64.gz", "TELEMT_AMD64_SHA256")),
        _ => None,
    };

    let Some((blob_name, sha_key)) = bundle else {
        println!("cargo:rustc-env=AWG_EASY_TELEMT_VERSION={telemt_version}");
        println!("cargo:rustc-env=AWG_EASY_TELEMT_SHA256=");
        println!(
            "cargo:warning=telemt bundled mode is not available for target {target_os}-{target_arch}; \
             awg-easy-rs will build without Telegram MTProxy support."
        );
        return;
    };

    let blob_src = manifest_dir.join("vendor").join(blob_name);
    let expected_sha = kv.get(sha_key).map(String::as_str).unwrap_or("");

    if !blob_src.is_file() || expected_sha.is_empty() {
        println!("cargo:rustc-env=AWG_EASY_TELEMT_VERSION={telemt_version}");
        println!("cargo:rustc-env=AWG_EASY_TELEMT_SHA256=");
        println!(
            "cargo:warning=telemt blob missing ({}) — building without telemt_bundled. \
             Run scripts/build.sh to materialise it from the pinned version.",
            blob_src.display()
        );
        return;
    }

    let blob_dst = out_dir.join("telemt.gz");
    fs::copy(&blob_src, &blob_dst).unwrap_or_else(|e| {
        panic!("copy {} → {}: {e}", blob_src.display(), blob_dst.display())
    });

    println!("cargo:rustc-env=AWG_EASY_TELEMT_VERSION={telemt_version}");
    println!("cargo:rustc-env=AWG_EASY_TELEMT_SHA256={expected_sha}");
    println!("cargo:rustc-cfg=telemt_bundled");
}

// ---------------------------------------------------------------------------
// MasterDnsVPN bundle (DNS-tunnel VPN — server side)
// ---------------------------------------------------------------------------

fn process_mdnsvpn_bundle(
    target_os: &str,
    target_arch: &str,
    out_dir: &Path,
    manifest_dir: &Path,
) {
    println!("cargo:rerun-if-changed=vendor/MDNSVPN_VERSION");
    println!("cargo:rerun-if-changed=vendor/mdnsvpn-linux-amd64.gz");
    println!("cargo:rustc-check-cfg=cfg(mdnsvpn_bundled)");

    let version_path = manifest_dir.join("vendor/MDNSVPN_VERSION");
    let version_text = fs::read_to_string(&version_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", version_path.display()));
    let kv = parse_kv(&version_text);
    let mdnsvpn_version = kv
        .get("MDNSVPN_VERSION")
        .expect("MDNSVPN_VERSION not set in vendor/MDNSVPN_VERSION");

    // Same arch story as the rest of the vendor tree: x86_64-linux only.
    let bundle = match (target_os, target_arch) {
        ("linux", "x86_64") => Some(("mdnsvpn-linux-amd64.gz", "MDNSVPN_AMD64_SHA256")),
        _ => None,
    };

    let Some((blob_name, sha_key)) = bundle else {
        println!("cargo:rustc-env=AWG_EASY_MDNSVPN_VERSION={mdnsvpn_version}");
        println!("cargo:rustc-env=AWG_EASY_MDNSVPN_SHA256=");
        println!(
            "cargo:warning=MasterDnsVPN bundled mode is not available for target {target_os}-{target_arch}; \
             awg-easy-rs will build without DNS-tunnel support."
        );
        return;
    };

    let blob_src = manifest_dir.join("vendor").join(blob_name);
    let expected_sha = kv.get(sha_key).map(String::as_str).unwrap_or("");

    if !blob_src.is_file() || expected_sha.is_empty() {
        println!("cargo:rustc-env=AWG_EASY_MDNSVPN_VERSION={mdnsvpn_version}");
        println!("cargo:rustc-env=AWG_EASY_MDNSVPN_SHA256=");
        println!(
            "cargo:warning=MasterDnsVPN blob missing ({}) — building without mdnsvpn_bundled. \
             Run scripts/build.sh to materialise it from the pinned version.",
            blob_src.display()
        );
        return;
    }

    let blob_dst = out_dir.join("mdnsvpn.gz");
    fs::copy(&blob_src, &blob_dst).unwrap_or_else(|e| {
        panic!("copy {} → {}: {e}", blob_src.display(), blob_dst.display())
    });

    println!("cargo:rustc-env=AWG_EASY_MDNSVPN_VERSION={mdnsvpn_version}");
    println!("cargo:rustc-env=AWG_EASY_MDNSVPN_SHA256={expected_sha}");
    println!("cargo:rustc-cfg=mdnsvpn_bundled");
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Parse `KEY = VALUE` lines into a map. Comments (`#`) and blank lines
/// are skipped. Whitespace around the `=` is tolerated. Identical to the
/// previous inline parser; lifted out so both bundle handlers can share it.
fn parse_kv(text: &str) -> HashMap<String, String> {
    let mut kv = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    kv
}
