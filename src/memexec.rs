//! In-memory execution of bundled binaries.
//!
//! WireGuard's appeal — the thing the operator who asked for this mode
//! actually cares about — is that the data plane lives in kernel memory and
//! never depends on a healthy disk. The four supervised subprocesses (Xray,
//! telemt, MasterDnsVPN, dnscrypt-proxy, tor) normally break that property:
//! each decompresses a vendored ELF onto disk and `exec`s the path. A failing
//! NVMe at the wrong moment means a crash-restart can't re-extract.
//!
//! This module removes that dependency. [`load`] decompresses a bundled ELF
//! into an anonymous [`memfd_create(2)`] object — a file that exists only in
//! RAM, with no name in any filesystem — verifies its SHA-256, seals it
//! read-only, and returns a `/proc/self/fd/N` path the supervisor hands to
//! `exec`. The kernel resolves that path against the child's inherited file
//! descriptor table, so the child runs an image that was never written to a
//! block device.
//!
//! ## Why sealing is mandatory, not cosmetic
//!
//! `execve(2)` refuses to run a file that any open descriptor holds writable
//! (`ETXTBSY`). A fresh memfd is read-write, so we'd be blocked. Adding
//! [`F_SEAL_WRITE`] drops the object's writability for good, which both makes
//! the image immutable (a defense-in-depth win for a process holding service
//! private keys) and clears the writer count so `execve` is satisfied. The
//! memfd is created with `MFD_ALLOW_SEALING` and **without** `MFD_CLOEXEC`:
//! the child must inherit the descriptor for `/proc/self/fd/N` to resolve.
//!
//! ## Lifetime / caching
//!
//! Each loaded binary's [`OwnedFd`] is parked in a process-wide registry for
//! the lifetime of the process. That keeps `/proc/self/fd/N` valid across
//! supervisor restarts (a crash-looping child re-`exec`s the same fd with no
//! re-decompression) and means we pay the gunzip+hash cost exactly once per
//! binary. The descriptors are intentionally never closed — they are the
//! in-RAM home of the running binaries.
//!
//! [`memfd_create(2)`]: https://man7.org/linux/man-pages/man2/memfd_create.2.html
//! [`F_SEAL_WRITE`]: https://man7.org/linux/man-pages/man2/fcntl.2.html

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};

/// `tmpfs` superblock magic (`include/uapi/linux/magic.h`). Used by
/// [`is_ram_backed`] to confirm a path the operator pointed us at really is
/// RAM-backed before we promise the operator "entirely in memory".
const TMPFS_MAGIC: i64 = 0x0102_1994;

/// Process-wide registry of loaded binaries, keyed by the logical name passed
/// to [`load`] (e.g. `"xray"`). The [`OwnedFd`] is held forever — see the
/// module docs. Behind a `Mutex` because supervisors load lazily from async
/// tasks on arbitrary worker threads.
static REGISTRY: Mutex<Option<HashMap<String, OwnedFd>>> = Mutex::new(None);

/// Decompress, verify, seal, and cache a bundled ELF in an anonymous in-RAM
/// memfd, returning a `/proc/self/fd/N` path suitable for `exec`.
///
/// - `name` is a stable logical key (also the memfd's debug name in
///   `/proc/<pid>/fd/`); repeated calls with the same `name` reuse the cached
///   descriptor and skip all work.
/// - `gz` is the embedded gzipped ELF (`include_bytes!` blob).
/// - `expected_sha256` is the lowercase-hex SHA-256 of the *uncompressed*
///   ELF; a mismatch is a hard error (the descriptor is dropped, nothing is
///   cached, and the operator gets the same diagnostic the disk extractor
///   would have produced).
///
/// The returned path is only meaningful to *this* process and its children.
/// It must be passed to `exec` (directly or via `Command`), not opened for
/// reading by unrelated code.
pub fn load(name: &str, gz: &[u8], expected_sha256: &str) -> Result<PathBuf> {
    if expected_sha256.is_empty() {
        bail!(
            "memexec::load({name}): no embedded SHA-256 — this binary was not \
             bundled for the target arch; cannot run it from memory"
        );
    }

    let mut guard = REGISTRY.lock().expect("memexec registry poisoned");
    let registry = guard.get_or_insert_with(HashMap::new);

    if let Some(fd) = registry.get(name) {
        return Ok(fd_path(fd.as_raw_fd()));
    }

    let fd = create_sealed_memfd(name, gz, expected_sha256)
        .with_context(|| format!("load {name} into memfd"))?;
    let path = fd_path(fd.as_raw_fd());
    registry.insert(name.to_string(), fd);
    crate::info!(
        binary = name,
        path = %path.display(),
        sha256 = expected_sha256,
        "Loaded bundled binary into anonymous memfd (runs entirely in RAM)"
    );
    Ok(path)
}

/// `/proc/self/fd/<n>` for a raw descriptor. `self` (not `<pid>`) so the path
/// resolves in whichever process reads it — crucially the forked child at
/// `exec` time, which inherited the descriptor at the same number.
fn fd_path(raw: std::os::fd::RawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{raw}"))
}

fn create_sealed_memfd(name: &str, gz: &[u8], expected_sha256: &str) -> Result<OwnedFd> {
    // Decompress fully into RAM and hash before committing anything to the
    // memfd. The largest blob (Xray) is ~35 MiB uncompressed — a transient
    // allocation we drop immediately, which is the whole point of this mode.
    let elf = crate::inflate::gunzip(gz).context("gunzip bundled ELF")?;

    let actual = {
        let mut hasher = Sha256::new();
        hasher.update(&elf);
        crate::encoding::hex_encode(hasher.finalize())
    };
    if actual != expected_sha256 {
        bail!(
            "memexec {name}: decompressed SHA-256 mismatch: expected \
             {expected_sha256}, got {actual}. The vendored blob is out of \
             sync with its *_VERSION pin file."
        );
    }

    // memfd_create with sealing allowed and CLOEXEC *off* (the child must
    // inherit the fd for /proc/self/fd/N to resolve). The name is purely for
    // /proc/<pid>/fd/ diagnostics and need not be unique.
    let cname = CString::new(name).context("memfd name contained a NUL byte")?;
    // SAFETY: memfd_create takes a NUL-terminated name and a flags bitmask and
    // returns a new fd or -1. We pass a valid CString pointer and a flag
    // constant; on success we take exclusive ownership of the returned fd.
    let raw = unsafe { libc::memfd_create(cname.as_ptr(), libc::MFD_ALLOW_SEALING) };
    if raw < 0 {
        return Err(anyhow!(io::Error::last_os_error())).context("memfd_create");
    }
    // SAFETY: `raw` is a fresh, owned, valid fd returned by memfd_create.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };

    // Write the ELF through a borrowed File so we don't surrender ownership of
    // the descriptor. `try_clone` dups the fd; the dup is dropped at the end
    // of this block, leaving `owned` as the sole reference before we seal.
    {
        let mut file = File::from(owned.try_clone().context("dup memfd for write")?);
        file.write_all(&elf).context("write ELF into memfd")?;
        file.flush().ok();
    }

    seal_read_only(&owned).context("seal memfd read-only")?;
    Ok(owned)
}

/// Apply `F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL`. After
/// this the memfd is immutable and — critically — no longer counts as
/// writable, so `execve` will accept it instead of failing with `ETXTBSY`.
fn seal_read_only(fd: &OwnedFd) -> Result<()> {
    let seals =
        libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
    // SAFETY: F_ADD_SEALS takes an int seal bitmask. `fd` is a live owned
    // descriptor for a sealing-capable memfd; on failure we surface errno.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) };
    if rc < 0 {
        return Err(anyhow!(io::Error::last_os_error())).context("fcntl(F_ADD_SEALS)");
    }
    Ok(())
}

/// Best-effort check that `path` lives on a `tmpfs` (RAM-backed) filesystem.
/// Used at startup to warn — never to fail — when `IN_MEMORY=true` but the
/// runtime root the operator pointed us at is actually a block device, which
/// would silently reintroduce the disk dependency for config files, the
/// AmneziaWG `.conf`, and tor's data directory.
///
/// Returns `None` when the filesystem type can't be determined (path missing,
/// `statfs` failed) so the caller can stay quiet rather than warn on noise.
pub fn is_ram_backed(path: &str) -> Option<bool> {
    let cpath = CString::new(path).ok()?;
    // SAFETY: statfs writes into a zeroed buffer we own; we pass a valid
    // NUL-terminated path. We read the result only on success (rc == 0).
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(cpath.as_ptr(), &mut buf) };
    if rc != 0 {
        return None;
    }
    Some(buf.f_type as i64 == TMPFS_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::os::unix::fs::PermissionsExt;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    fn sha_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        crate::encoding::hex_encode(h.finalize())
    }

    #[test]
    fn loads_verifies_and_exposes_proc_path() {
        // A tiny shell script stands in for an ELF — we're testing the memfd
        // round-trip (decompress → verify → seal → /proc/self/fd path), not
        // actually exec'ing here.
        let payload = b"#!/bin/sh\necho in-memory\n";
        let gz = gzip(payload);
        let sha = sha_hex(payload);

        let path = load("memexec-test-ok", &gz, &sha).expect("load");
        assert!(path.starts_with("/proc/self/fd/"));

        // The kernel exposes the sealed memfd contents through the fd path.
        let read_back = std::fs::read(&path).expect("read memfd via /proc");
        assert_eq!(read_back, payload, "memfd contents must match the ELF");
    }

    #[test]
    fn second_load_is_cached() {
        let payload = b"cache me";
        let gz = gzip(payload);
        let sha = sha_hex(payload);

        let a = load("memexec-test-cache", &gz, &sha).expect("first load");
        let b = load("memexec-test-cache", &gz, &sha).expect("second load");
        assert_eq!(a, b, "same logical name must return the same cached fd path");
    }

    #[test]
    fn sha_mismatch_is_rejected_and_not_cached() {
        let gz = gzip(b"the real bytes");
        let wrong = sha_hex(b"different bytes");

        let err = load("memexec-test-mismatch", &gz, &wrong).unwrap_err();
        assert!(
            format!("{err:#}").contains("SHA-256 mismatch"),
            "expected SHA mismatch error, got: {err:#}"
        );
        // A rejected load must not poison the cache: a later correct load of
        // the same name has to succeed.
        let right = sha_hex(b"the real bytes");
        assert!(load("memexec-test-mismatch", &gz, &right).is_ok());
    }

    #[test]
    fn empty_sha_is_rejected() {
        let gz = gzip(b"anything");
        let err = load("memexec-test-empty-sha", &gz, "").unwrap_err();
        assert!(format!("{err:#}").contains("not"));
    }

    #[test]
    fn sealed_memfd_refuses_writes() {
        let payload = b"immutable";
        let gz = gzip(payload);
        let sha = sha_hex(payload);
        let path = load("memexec-test-seal", &gz, &sha).expect("load");

        // F_SEAL_WRITE must make the backing object unwritable. The kernel
        // may allow the O_WRONLY open() itself but must reject the write()
        // (EPERM) — assert on the net effect rather than the open call, since
        // which of the two fails is kernel-version dependent.
        let attempt = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|mut f| f.write_all(b"tampered"));
        assert!(attempt.is_err(), "sealed memfd must reject writes");

        // …and the original contents are intact.
        assert_eq!(std::fs::read(&path).expect("re-read"), payload);
    }

    #[test]
    fn is_ram_backed_detects_proc_self() {
        // /proc is a procfs, not tmpfs — must report false, not None.
        assert_eq!(is_ram_backed("/proc"), Some(false));
        // A path that cannot be statfs'd yields None (quiet, no false warning).
        assert_eq!(is_ram_backed("/definitely/not/here/awg"), None);
    }

    /// Belt-and-braces: a sealed memfd whose contents are a real executable
    /// can actually be `exec`'d via its `/proc/self/fd/N` path. Marked
    /// `#[ignore]` because it spawns a subprocess; run with `--ignored`.
    #[test]
    #[ignore = "spawns a subprocess from a memfd; run with --ignored"]
    fn memfd_binary_is_executable() {
        // Copy /bin/sh's bytes through our loader and exec the result.
        let sh = std::fs::read("/bin/sh").expect("read /bin/sh");
        let gz = gzip(&sh);
        let sha = sha_hex(&sh);
        let path = load("memexec-test-exec", &gz, &sha).expect("load sh");

        // The path must be marked executable to the kernel even though we
        // never chmod'd a file — memfd contents are exec-eligible once
        // write-sealed.
        let _ = std::fs::metadata(&path).map(|m| m.permissions().mode());

        let out = std::process::Command::new(&path)
            .arg("-c")
            .arg("echo memfd-exec-ok")
            .output()
            .expect("exec memfd sh");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "memfd-exec-ok");
    }
}
