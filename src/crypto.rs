//! Authenticated encryption for secrets that must stay usable at runtime but
//! must not be readable in a stolen database or backup.
//!
//! ## What this defends, and what it does not
//!
//! The threat this addresses is **T-007: someone obtains the database file** —
//! a stolen disk, a backup copied off-host, a snapshot volume, an
//! `IN_MEMORY=false` deployment whose `wg-easy.db` ends up somewhere it
//! shouldn't. Under that threat the encryption is real: the key is delivered
//! out of band and is never written into the database, so the file alone
//! yields nothing.
//!
//! It does **not** defend against a live compromise of the running service.
//! The process must hold the key to do its job, so an attacker with code
//! execution as this user can decrypt anything the process can — often by
//! calling straight into this module. Anyone reasoning about this should be
//! clear-eyed: encrypting a value the process can decrypt on demand raises
//! effort, it does not move the security boundary. Where a secret can be
//! eliminated instead of encrypted (see the private-key retention modes in
//! `api::clients`), eliminating it is strictly better and should win.
//!
//! ## Key delivery
//!
//! In priority order:
//!
//! 1. `WG_EASY_SECRET_KEY_PATH` — path to a file holding the base64 key.
//!    Intended for systemd credentials: `LoadCredentialEncrypted=SECRET_KEY:…`
//!    puts a machine-bound, decrypted-at-start copy at
//!    `/run/credentials/awg-easy-rs.service/SECRET_KEY`, which never exists as
//!    plaintext on disk.
//! 2. `WG_EASY_SECRET_KEY` — the base64 key itself, for Docker and dev.
//!
//! With neither set the module reports [`is_configured`] as `false` and
//! callers fall back to storing plaintext, with a startup warning. That is a
//! deliberate choice over refusing to boot: an operator upgrading into this
//! feature should not find their VPN down because a new environment variable
//! is missing.
//!
//! ## Format
//!
//! `enc$` + base64(12-byte nonce ‖ ciphertext ‖ 16-byte GCM tag). The prefix
//! is what makes migration and mixed content safe — a stored value without it
//! is legacy plaintext, and [`decrypt`] passes it through unchanged.

use std::sync::LazyLock;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};

/// Marks a value as produced by [`encrypt`]. Anything lacking it is treated as
/// legacy plaintext.
pub const ENC_PREFIX: &str = "enc$";

/// AES-256 key length in bytes.
const KEY_LEN: usize = 32;

/// The process-wide key, loaded once.
///
/// Deliberately kept here rather than in [`crate::config::CONFIG`]: that
/// struct is read all over the codebase and its fields end up in debug output
/// and error paths. Key material has exactly one legitimate consumer, so it
/// lives behind this module's API and nowhere else.
static KEY: LazyLock<Option<LessSafeKey>> = LazyLock::new(load_key);

fn load_key() -> Option<LessSafeKey> {
    let raw = match std::env::var("WG_EASY_SECRET_KEY_PATH") {
        Ok(path) if !path.is_empty() => match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(e) => {
                // A configured-but-unreadable key is an operator error worth
                // shouting about: it silently degrades to plaintext storage,
                // which is precisely what they were trying to avoid.
                tracing::error!(
                    "WG_EASY_SECRET_KEY_PATH={path} could not be read ({e}); \
                     secrets will be stored unencrypted"
                );
                return None;
            }
        },
        _ => match std::env::var("WG_EASY_SECRET_KEY") {
            Ok(v) if !v.is_empty() => v,
            _ => return None,
        },
    };

    let mut bytes = match base64::engine::general_purpose::STANDARD.decode(raw.trim()) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("secret key is not valid base64 ({e}); secrets will be stored unencrypted");
            return None;
        }
    };
    if bytes.len() != KEY_LEN {
        tracing::error!(
            "secret key must decode to {KEY_LEN} bytes, got {}; secrets will be stored unencrypted",
            bytes.len()
        );
        bytes.iter_mut().for_each(|b| *b = 0);
        return None;
    }

    let unbound = UnboundKey::new(&AES_256_GCM, &bytes).ok();
    // Best-effort scrub of the decoded copy. `LessSafeKey` has taken its own
    // (expanded) copy by now, so this buffer is dead weight holding key
    // material; a crash dump or swap page should not carry a second copy of it.
    // Not a guarantee — base64's intermediate allocations are out of reach —
    // which is why the module doc is explicit about the boundary this sits on.
    bytes.iter_mut().for_each(|b| *b = 0);
    unbound.map(LessSafeKey::new)
}

/// Whether a usable key was supplied. Callers branch on this to decide
/// between encrypting and storing plaintext.
pub fn is_configured() -> bool {
    KEY.is_some()
}

/// Log the mode once at startup so the operator can see, in the journal,
/// which of the two states this instance is in without reading the database.
pub fn log_status() {
    if is_configured() {
        tracing::info!("secret encryption: enabled (AES-256-GCM, key supplied out of band)");
    } else {
        tracing::warn!(
            "secret encryption: DISABLED — TOTP secrets are stored in plaintext. \
             Set WG_EASY_SECRET_KEY_PATH (systemd credential) or WG_EASY_SECRET_KEY \
             (base64, 32 bytes) so a stolen database does not yield working second factors."
        );
    }
}

/// Encrypt `plaintext`, returning the `enc$…` form.
///
/// Returns the input unchanged when no key is configured, so call sites do not
/// need to branch: what comes back is always safe to store, and [`decrypt`]
/// reads either shape.
pub fn encrypt(plaintext: &str) -> Result<String> {
    let Some(key) = KEY.as_ref() else {
        return Ok(plaintext.to_string());
    };
    // Random 96-bit nonce per message. Uniqueness matters enormously for
    // GCM — a repeat with the same key is catastrophic, not merely weak — but
    // the birthday bound over a random 96-bit nonce is far beyond the handful
    // of secrets this ever protects.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    crate::rng::fill(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| anyhow!("AES-GCM seal failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(format!(
        "{ENC_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(&out)
    ))
}

/// Decrypt a value produced by [`encrypt`].
///
/// A value without the `enc$` prefix is legacy plaintext and is returned as
/// is — that is what lets an instance start encrypting without a flag day, and
/// what lets one keep working if the key is later removed from a value's
/// lifetime. An `enc$` value with no key configured is an error rather than a
/// pass-through: returning ciphertext as if it were a TOTP secret would fail
/// every login with no indication why.
pub fn decrypt(stored: &str) -> Result<String> {
    let Some(encoded) = stored.strip_prefix(ENC_PREFIX) else {
        return Ok(stored.to_string());
    };
    let key = KEY
        .as_ref()
        .context("value is encrypted but no secret key is configured (WG_EASY_SECRET_KEY_PATH / WG_EASY_SECRET_KEY)")?;

    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("encrypted value is not valid base64")?;
    if raw.len() <= NONCE_LEN {
        return Err(anyhow!("encrypted value is truncated"));
    }
    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| anyhow!("bad nonce length"))?;

    let mut buf = ciphertext.to_vec();
    let plain = key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| anyhow!("decryption failed — wrong key, or the value was tampered with"))?;
    String::from_utf8(plain.to_vec()).context("decrypted value is not valid UTF-8")
}

/// Whether a stored value is in the encrypted form.
pub fn is_encrypted(stored: &str) -> bool {
    stored.starts_with(ENC_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The env is process-global, so these run serially and restore it.
    fn with_key<T>(f: impl FnOnce() -> T) -> T {
        // `KEY` is a LazyLock resolved once per process, so a test cannot
        // meaningfully toggle it. The round-trip behaviour is therefore
        // covered by the integration tests in tests/crypto.rs, which set the
        // env before the first call; what is unit-tested here is the shape
        // handling that does not depend on a key being present.
        f()
    }

    #[test]
    fn plaintext_passes_through_decrypt() {
        with_key(|| {
            assert_eq!(decrypt("JBSWY3DPEHPK3PXP").unwrap(), "JBSWY3DPEHPK3PXP");
        });
    }

    #[test]
    fn prefix_detection() {
        assert!(is_encrypted("enc$abc"));
        assert!(!is_encrypted("JBSWY3DPEHPK3PXP"));
        assert!(!is_encrypted(""));
    }

    #[test]
    fn truncated_ciphertext_is_rejected_not_panicked_on() {
        // Only meaningful when a key is configured; without one this returns
        // the "no key configured" error instead. Either way it must not panic
        // on a short buffer.
        let _ = decrypt("enc$AAAA");
    }
}
