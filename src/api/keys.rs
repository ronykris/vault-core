//! Key generation and derivation functions

use crate::crypto::{bip39, kdf};
use crate::types::{CacheKey, IndexKey, PasswordKey, RecoveryKey, VaultMasterKey, FileKey};

/// Generate a random vault master key (32 bytes)
pub fn generate_vault_master_key() -> Result<VaultMasterKey, String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| format!("getrandom failed: {}", e))?;
    Ok(VaultMasterKey::new(bytes))
}

/// Derive a password key from a master password using Argon2id
///
/// # Parameters
/// - `password`: UTF-8 master password (minimum 12 chars recommended)
/// - `salt`: 16-byte random salt
/// - `m_cost`: Memory cost in KiB (minimum 19456 = 19 MiB)
/// - `t_cost`: Time cost (minimum 2)
/// - `p_cost`: Parallelism (typically 1)
///
/// # Errors
/// - Invalid parameters (below minimums from DESIGN.md)
/// - Argon2 derivation failure
///
/// # Example
/// ```ignore
/// let salt = [0u8; 16]; // In production, use getrandom
/// let pk = derive_password_key("my-secure-password", &salt, 65536, 3, 1)?;
/// ```
pub fn derive_password_key(
    password: &str,
    salt: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<PasswordKey, String> {
    let params = kdf::Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    };
    params.validate()?;

    kdf::derive_password_key(password, salt, params)
}

/// Generate a 24-word BIP-39 recovery phrase
///
/// Returns a space-separated string of 24 words from the BIP-39 English wordlist.
///
/// # Example
/// ```ignore
/// let phrase = generate_recovery_phrase()?;
/// assert_eq!(phrase.split_whitespace().count(), 24);
/// ```
pub fn generate_recovery_phrase() -> Result<String, String> {
    bip39::generate_recovery_phrase()
}

/// Convert a 24-word BIP-39 recovery phrase to a recovery key
///
/// # Parameters
/// - `phrase`: Space-separated 24 BIP-39 words
///
/// # Errors
/// - Wrong word count (not 24)
/// - Invalid words (not in BIP-39 wordlist)
/// - Invalid checksum
///
/// # Example
/// ```ignore
/// let rk = phrase_to_recovery_key("word1 word2 ... word24")?;
/// ```
pub fn phrase_to_recovery_key(phrase: &str) -> Result<RecoveryKey, String> {
    bip39::phrase_to_recovery_key(phrase)
}

/// Validate a recovery phrase without deriving the key
///
/// Cheaper than full derivation when you just need to check validity.
///
/// # Errors
/// - Wrong word count
/// - Invalid words
/// - Invalid checksum
pub fn validate_recovery_phrase(phrase: &str) -> Result<(), String> {
    bip39::validate_recovery_phrase(phrase)
}

/// Derive index encryption key from VMK
///
/// Uses HKDF-SHA256 with info = "vault/index/v1"
pub fn derive_index_key(vmk: &VaultMasterKey) -> Result<IndexKey, String> {
    kdf::derive_index_key(vmk)
}

/// Derive local cache encryption key from VMK (for SQLCipher)
///
/// Uses HKDF-SHA256 with info = "vault/local-cache/v1"
pub fn derive_cache_key(vmk: &VaultMasterKey) -> Result<CacheKey, String> {
    let bytes = kdf::derive_cache_key(vmk)?;
    Ok(CacheKey::new(bytes))
}

/// Generate a random file key for blob encryption
///
/// Each blob gets its own random 32-byte key.
pub fn generate_file_key() -> FileKey {
    FileKey::generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_vault_master_key() {
        let vmk1 = generate_vault_master_key().unwrap();
        let vmk2 = generate_vault_master_key().unwrap();

        // Keys should be different (random)
        assert_ne!(
            vmk1.expose_secret(),
            vmk2.expose_secret()
        );
    }

    #[test]
    fn test_derive_password_key() {
        let salt = [0x42; 16];
        let pk = derive_password_key("test-password", &salt, 19456, 2, 1).unwrap();

        // Same inputs should give same output (deterministic)
        let pk2 = derive_password_key("test-password", &salt, 19456, 2, 1).unwrap();
        assert_eq!(pk.expose_secret(), pk2.expose_secret());

        // Different password should give different key
        let pk3 = derive_password_key("different", &salt, 19456, 2, 1).unwrap();
        assert_ne!(pk.expose_secret(), pk3.expose_secret());
    }

    #[test]
    fn test_derive_password_key_rejects_weak_params() {
        let salt = [0x42; 16];

        // m_cost too low
        assert!(derive_password_key("test", &salt, 10000, 2, 1).is_err());

        // t_cost too low
        assert!(derive_password_key("test", &salt, 19456, 1, 1).is_err());
    }

    #[test]
    fn test_generate_recovery_phrase() {
        let phrase = generate_recovery_phrase().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);

        // Should be different each time
        let phrase2 = generate_recovery_phrase().unwrap();
        assert_ne!(phrase, phrase2);
    }

    #[test]
    fn test_phrase_to_recovery_key() {
        let phrase = generate_recovery_phrase().unwrap();
        let rk = phrase_to_recovery_key(&phrase).unwrap();

        // Same phrase should give same key
        let rk2 = phrase_to_recovery_key(&phrase).unwrap();
        assert_eq!(rk.expose_secret(), rk2.expose_secret());
    }

    #[test]
    fn test_validate_recovery_phrase() {
        let phrase = generate_recovery_phrase().unwrap();
        assert!(validate_recovery_phrase(&phrase).is_ok());

        assert!(validate_recovery_phrase("invalid phrase here").is_err());
    }

    #[test]
    fn test_derive_index_key() {
        let vmk = generate_vault_master_key().unwrap();
        let k_index = derive_index_key(&vmk).unwrap();

        // Deterministic
        let k_index2 = derive_index_key(&vmk).unwrap();
        assert_eq!(k_index.expose_secret(), k_index2.expose_secret());
    }

    #[test]
    fn test_derive_cache_key() {
        let vmk = generate_vault_master_key().unwrap();
        let k_cache = derive_cache_key(&vmk).unwrap();

        // Different from index key
        let k_index = derive_index_key(&vmk).unwrap();
        assert_ne!(k_cache.expose_secret(), k_index.expose_secret());
    }

    #[test]
    fn test_generate_file_key() {
        let fk1 = generate_file_key();
        let fk2 = generate_file_key();

        assert_ne!(fk1.expose_secret(), fk2.expose_secret());
    }
}
