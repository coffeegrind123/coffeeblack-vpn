//! Track 1: Unit tests for auth.rs — password hashing, verification, token
//! generation, and SHA-256 hashing.

use coffeeblack_vpn::auth;

// ---------------------------------------------------------------------------
// hash_password
// ---------------------------------------------------------------------------

#[test]
fn hash_password_produces_valid_argon2_hash() {
    let hash = auth::hash_password("my-secret-password").unwrap();
    // argon2 hash format: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
    assert!(hash.starts_with("$argon2id$"), "expected argon2id hash, got: {hash}");
    assert!(hash.contains("$v=19$"), "hash missing version: {hash}");
}

#[test]
fn hash_password_empty_string() {
    let hash = auth::hash_password("").unwrap();
    assert!(hash.starts_with("$argon2id$"));
}

#[test]
fn hash_password_long_string() {
    let long = "a".repeat(10_000);
    let hash = auth::hash_password(&long).unwrap();
    assert!(hash.starts_with("$argon2id$"));
}

#[test]
fn hash_password_deterministic_structure() {
    // Same input twice should produce different salts → different hashes.
    let h1 = auth::hash_password("hello").unwrap();
    let h2 = auth::hash_password("hello").unwrap();
    assert_ne!(h1, h2, "same password should produce different hashes (random salt)");
}

// ---------------------------------------------------------------------------
// verify_password
// ---------------------------------------------------------------------------

#[test]
fn verify_password_matching() {
    let hash = auth::hash_password("correct-horse-battery-staple").unwrap();
    assert!(auth::verify_password("correct-horse-battery-staple", &hash).unwrap());
}

#[test]
fn verify_password_wrong() {
    let hash = auth::hash_password("correct-password").unwrap();
    assert!(!auth::verify_password("wrong-password", &hash).unwrap());
}

#[test]
fn verify_password_empty_match() {
    let hash = auth::hash_password("").unwrap();
    assert!(auth::verify_password("", &hash).unwrap());
}

#[test]
fn verify_password_empty_mismatch() {
    let hash = auth::hash_password("something").unwrap();
    assert!(!auth::verify_password("", &hash).unwrap());
}

#[test]
fn verify_password_unicode() {
    let pw = "パスワード🔒安全";
    let hash = auth::hash_password(pw).unwrap();
    assert!(auth::verify_password(pw, &hash).unwrap());
    assert!(!auth::verify_password(pw, &auth::hash_password("other").unwrap()).unwrap());
}

#[test]
fn verify_password_similar_but_different() {
    let hash = auth::hash_password("Password1").unwrap();
    assert!(!auth::verify_password("password1", &hash).unwrap()); // case sensitive
    assert!(!auth::verify_password("Password1 ", &hash).unwrap()); // trailing space
    assert!(!auth::verify_password(" Password1", &hash).unwrap()); // leading space
}

#[test]
fn verify_password_invalid_hash() {
    // Malformed hash string should return an error, not panic.
    let result = auth::verify_password("anything", "not-a-valid-hash");
    assert!(result.is_err());
}

#[test]
fn verify_password_empty_hash() {
    let result = auth::verify_password("pw", "");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// generate_session_token
// ---------------------------------------------------------------------------

#[test]
fn generate_session_token_length() {
    let token = auth::generate_session_token();
    // 256 random bytes → 512 hex characters
    assert_eq!(token.len(), 512);
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn generate_session_token_unique() {
    let t1 = auth::generate_session_token();
    let t2 = auth::generate_session_token();
    assert_ne!(t1, t2);
}

#[test]
fn generate_session_token_many_unique() {
    let tokens: Vec<String> = (0..100).map(|_| auth::generate_session_token()).collect();
    for i in 0..tokens.len() {
        for j in (i + 1)..tokens.len() {
            assert_ne!(tokens[i], tokens[j], "collision at indices {i}, {j}");
        }
    }
}

// ---------------------------------------------------------------------------
// sha256
// ---------------------------------------------------------------------------

#[test]
fn sha256_known_vector() {
    // SHA-256 of empty string
    let hash = auth::sha256("");
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_known_vector_hello() {
    let hash = auth::sha256("hello");
    assert_eq!(
        hash,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[test]
fn sha256_deterministic() {
    let h1 = auth::sha256("test-input");
    let h2 = auth::sha256("test-input");
    assert_eq!(h1, h2);
}

#[test]
fn sha256_length() {
    let hash = auth::sha256("any input");
    assert_eq!(hash.len(), 64);
}
