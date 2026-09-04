use anyhow::Result;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sha2::{Digest, Sha256};

/// Hash a plaintext password using Argon2id with default parameters.
pub fn hash_password(pw: &str) -> Result<String> {
    // 16-byte random salt straight from the OS CSPRNG, encoded in the B64 form
    // password-hash expects. This replaces `SaltString::generate(&mut OsRng)`:
    // that `OsRng` lived behind rand_core 0.6's `getrandom` feature, which only
    // got enabled as a side effect of depending on `rand`. Sourcing the salt
    // ourselves keeps argon2 self-contained now that `rand` is gone.
    let mut salt_bytes = [0u8; 16];
    crate::rng::fill(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| anyhow::anyhow!("argon2 salt encode failed: {e}"))?;
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against an Argon2id hash.
pub fn verify_password(pw: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| anyhow::anyhow!("invalid password hash: {e}"))?;
    Ok(Argon2::default()
        .verify_password(pw.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Generate a session token: 256 random bytes encoded as 512 hex characters.
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 256];
    crate::rng::fill(&mut bytes);
    crate::encoding::hex_encode(bytes)
}

/// Compute the SHA-256 hex digest of a string.
pub fn sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    crate::encoding::hex_encode(hasher.finalize())
}
