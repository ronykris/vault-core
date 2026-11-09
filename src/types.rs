//! Secret types with zeroize-on-drop and redacting Debug.
//!
//! All key material uses these wrappers to prevent accidental logging
//! and ensure memory is cleared.

use secrecy::{ExposeSecret, Secret};

/// Vault Master Key (VMK) - 32 bytes, random
#[derive(Clone)]
pub struct VaultMasterKey(Secret<[u8; 32]>);

impl VaultMasterKey {
    /// Create from 32 bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Expose the secret (use sparingly)
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for VaultMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultMasterKey([REDACTED])")
    }
}

/// Password Key (PK) - derived from master password via Argon2id
#[derive(Clone)]
pub struct PasswordKey(Secret<[u8; 32]>);

impl PasswordKey {
    /// Create a new PasswordKey from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Expose the secret key bytes (use with caution)
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for PasswordKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordKey([REDACTED])")
    }
}

/// Recovery Key (RK) - derived from 24-word BIP-39 phrase
#[derive(Clone)]
pub struct RecoveryKey(Secret<[u8; 32]>);

impl RecoveryKey {
    /// Create a new RecoveryKey from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Expose the secret key bytes (use with caution)
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

/// File Key (FK) - random 32 bytes per encrypted blob
#[derive(Clone)]
pub struct FileKey(Secret<[u8; 32]>);

impl FileKey {
    /// Create a new FileKey from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Expose the secret key bytes (use with caution)
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    /// Generate a random file key
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        Self::new(bytes)
    }
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKey([REDACTED])")
    }
}

/// Index encryption key (K_index) - derived from VMK
#[derive(Clone)]
pub struct IndexKey(Secret<[u8; 32]>);

impl IndexKey {
    /// Create a new IndexKey from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Expose the secret key bytes (use with caution)
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for IndexKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IndexKey([REDACTED])")
    }
}

/// Cache encryption key (K_cache) - derived from VMK for SQLCipher
#[derive(Clone)]
pub struct CacheKey(Secret<[u8; 32]>);

impl CacheKey {
    /// Create a new CacheKey from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Expose the secret key bytes (use with caution)
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CacheKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_redaction() {
        let vmk = VaultMasterKey::new([0x42; 32]);
        let debug_output = format!("{:?}", vmk);
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains("42"));

        let pk = PasswordKey::new([0x99; 32]);
        let debug_output = format!("{:?}", pk);
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains("99"));
    }

    #[test]
    fn test_file_key_generation() {
        let fk1 = FileKey::generate();
        let fk2 = FileKey::generate();
        // Keys should be different (astronomically unlikely to be equal)
        assert_ne!(fk1.expose_secret(), fk2.expose_secret());
    }
}
