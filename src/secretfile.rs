//! Atomic, owner-only writes for generated files that contain secrets.
//!
//! Every bundled transport is configured by a file this service renders, and
//! every one of those files carries credentials:
//!
//! | File | Contains |
//! |---|---|
//! | `xray/server.json` | the Reality server private key, and **every client's UUID and shortId** |
//! | `mtproxy/config.toml` | every MTProxy user's 32-hex secret |
//! | `mdnsvpn/server_config.toml` | the singleton tunnel encryption key |
//! | `dns/torrc`, `dnscrypt-proxy.toml` | resolver and bridge configuration |
//!
//! These were written with `tokio::fs::write`, which creates a file at
//! `0666 & ~umask` — **0644 under the usual 0022**, i.e. readable by every
//! local account. On a bare-metal install that hands any local user a working
//! VLESS UUID (free tunnel access as an existing client) and the Reality
//! private key. That is a live exposure, not merely an at-rest one: no stolen
//! disk or backup is required, just a shell on the box.
//!
//! Encrypting the corresponding database columns does nothing about it — the
//! subprocesses read these files in plaintext by design and always will. The
//! only available control is to make sure nothing else can read them, which is
//! what this module exists to guarantee.
//!
//! ## Why the mode is set at `open(2)`
//!
//! Writing and then `chmod`-ing leaves a window in which the file exists with
//! the umask-derived mode and already contains the secret. `OpenOptions::mode`
//! passes the mode to `open(2)` itself, so the file is never observable at
//! anything wider. The same reasoning is already recorded in `db::snapshot_to`
//! and in the privileged helper.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Mode for a file that contains credentials: owner read/write, nothing else.
pub const SECRET_FILE_MODE: u32 = 0o600;

/// Mode for a directory holding such files. `0700` rather than `0600` because
/// a directory needs the execute bit to be traversed at all.
pub const SECRET_DIR_MODE: u32 = 0o700;

/// Create `dir` (and parents) and tighten it to owner-only.
///
/// The tightening is applied on every call rather than only at creation: an
/// upgrade from a version that made this directory world-traversable must
/// close it, and `create_dir_all` is a no-op that reports success on an
/// already-existing — possibly `0755` — directory.
pub async fn ensure_dir(dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("create dir {}", dir.display()))?;
    tokio::fs::set_permissions(
        dir,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(SECRET_DIR_MODE),
    )
    .await
    .with_context(|| format!("chmod {SECRET_DIR_MODE:o} {}", dir.display()))?;
    Ok(())
}

/// Write `contents` to `path` atomically, owner-only throughout.
///
/// Renders to a sibling temporary file so a crash mid-write cannot leave a
/// subprocess reading a half-rendered config, then renames into place — rename
/// within a directory is atomic, so a reader sees either the old file or the
/// new one and never a partial.
pub async fn write_atomic(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    if let Some(dir) = path.parent() {
        ensure_dir(dir).await?;
    }
    let tmp = tmp_sibling(path);

    // Blocking file work on the tokio blocking pool: `OpenOptions::mode` has
    // no async equivalent, and doing it inline would park a worker thread.
    let tmp_for_task = tmp.clone();
    let bytes = contents.as_ref().to_vec();
    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(SECRET_FILE_MODE)
            .open(&tmp_for_task)
            .with_context(|| format!("open {}", tmp_for_task.display()))?;
        f.write_all(&bytes)
            .with_context(|| format!("write {}", tmp_for_task.display()))?;
        // An already-existing temp file keeps its old mode through O_CREAT,
        // so enforce it rather than trusting the create path.
        std::fs::set_permissions(
            &tmp_for_task,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(
                SECRET_FILE_MODE,
            ),
        )
        .with_context(|| format!("chmod {}", tmp_for_task.display()))?;
        Ok(())
    })
    .await
    .map_err(|e| anyhow::anyhow!("blocking write task failed: {e}"))??;

    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

/// `<name>.partial` next to the target, so the rename stays within one
/// directory (and therefore one filesystem, and therefore atomic).
fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".partial");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("coffeeblack-secretfile-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        d
    }

    #[tokio::test]
    async fn writes_owner_only() {
        let dir = temp_dir("mode");
        let path = dir.join("server.json");
        // Deliberately does NOT widen the process umask to "prove" the mode is
        // independent of it. `umask(2)` is per-process, not per-thread, and
        // cargo runs this binary's tests on parallel threads — widening it
        // here would widen it for every file every other test creates in that
        // window, which showed up as an unrelated permission assertion failing
        // roughly one run in three. The property still holds: `.mode()` is
        // applied by open(2) and the explicit chmod follows, so neither
        // depends on the ambient umask.
        write_atomic(&path, b"{\"secret\":\"uuid\"}").await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file mode was {mode:o}");
        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "dir mode was {dmode:o}");
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"secret\":\"uuid\"}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn tightens_a_directory_left_world_readable_by_an_older_version() {
        let dir = temp_dir("upgrade");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        write_atomic(&dir.join("c.toml"), b"secret").await.unwrap();

        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "an existing 0755 dir must be tightened, was {dmode:o}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn overwrites_and_leaves_no_partial_behind() {
        let dir = temp_dir("replace");
        let path = dir.join("x.conf");
        write_atomic(&path, b"first").await.unwrap();
        write_atomic(&path, b"second").await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(
            !dir.join("x.conf.partial").exists(),
            "temp file must be renamed away, not left readable"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rewrite_of_a_loosened_file_restores_the_tight_mode() {
        let dir = temp_dir("loosened");
        let path = dir.join("y.conf");
        write_atomic(&path, b"a").await.unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&path, b"b").await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rewrite must not inherit a loosened mode, was {mode:o}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
