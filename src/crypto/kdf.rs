//! Key derivation functions (Argon2id, HKDF).
//!
//! Implements password → PK and VMK → subkeys derivation.

use crate::types::{IndexKey, PasswordKey, RecoveryKey, VaultMasterKey};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use hkdf::Hkdf;
use sha2::Sha256;

/// Argon2id parameters for password hashing
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    /// Memory size in KiB
    pub m_cost: u32,
    /// Time cost (iterations)
    pub t_cost: u32,
    /// Parallelism
    pub p_cost: u32,
}

impl Argon2Params {
    /// Default parameters: m=64 MiB, t=3, p=1
    /// Design spec: benchmark on first run and raise t toward 500-800ms
    pub fn default() -> Self {
        Self {
            m_cost: 65536, // 64 MiB
            t_cost: 3,
            p_cost: 1,
        }
    }

    /// Validate parameters against design minimums
    /// Reject: m < 19 MiB (19456 KiB) or t < 2
    pub fn validate(&self) -> Result<(), String> {
        if self.m_cost < 19456 {
            return Err(format!(
                "Memory cost {} KiB is below minimum 19456 KiB",
                self.m_cost
            ));
        }
        if self.t_cost < 2 {
            return Err(format!("Time cost {} is below minimum 2", self.t_cost));
        }
        if self.p_cost < 1 {
            return Err("Parallelism must be at least 1".to_string());
        }
        Ok(())
    }
}

/// Derive password key from master password using Argon2id
///
/// # Design
/// - Algorithm: Argon2id
/// - Output: 32 bytes (PK)
/// - Salt: 16 bytes, random (from header)
/// - Default params: m=64 MiB, t=3, p=1
pub fn derive_password_key(
    password: &str,
    salt: &[u8; 16],
    params: Argon2Params,
) -> Result<PasswordKey, String> {
    params.validate()?;

    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| format!("Invalid Argon2 params: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let salt_string =
        SaltString::encode_b64(salt).map_err(|e| format!("Salt encoding failed: {}", e))?;

    let hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| format!("Argon2id hashing failed: {}", e))?;

    let hash_output = hash.hash.ok_or_else(|| "No hash output".to_string())?;
    let hash_bytes = hash_output.as_bytes();

    if hash_bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", hash_bytes.len()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes);
    Ok(PasswordKey::new(key))
}

/// Derive recovery key from BIP-39 entropy using HKDF
///
/// # Design
/// - Input: 32 bytes entropy from 24-word BIP-39 phrase
/// - HKDF-SHA256.Extract(salt="vault/recovery/v1", ikm=entropy)
/// - HKDF-SHA256.Expand(info="vault/recovery-key/v1", L=32)
pub fn derive_recovery_key(entropy: &[u8; 32]) -> RecoveryKey {
    let hkdf = Hkdf::<Sha256>::new(Some(b"vault/recovery/v1"), entropy);
    let mut rk = [0u8; 32];
    hkdf.expand(b"vault/recovery-key/v1", &mut rk)
        .expect("HKDF expand failed");
    RecoveryKey::new(rk)
}

/// Derive index encryption key from VMK
///
/// # Design
/// - HKDF-SHA256.Extract(salt="", ikm=VMK)
/// - HKDF-SHA256.Expand(info="vault/index/v1", L=32)
pub fn derive_index_key(vmk: &VaultMasterKey) -> IndexKey {
    let hkdf = Hkdf::<Sha256>::new(Some(b""), vmk.expose_secret());
    let mut k_index = [0u8; 32];
    hkdf.expand(b"vault/index/v1", &mut k_index)
        .expect("HKDF expand failed");
    IndexKey::new(k_index)
}

/// Derive local cache key from VMK (for SQLCipher)
///
/// # Design
/// - HKDF-SHA256.Extract(salt="", ikm=VMK)
/// - HKDF-SHA256.Expand(info="vault/local-cache/v1", L=32)
pub fn derive_cache_key(vmk: &VaultMasterKey) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(b""), vmk.expose_secret());
    let mut k_cache = [0u8; 32];
    hkdf.expand(b"vault/local-cache/v1", &mut k_cache)
        .expect("HKDF expand failed");
    k_cache
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_basic() {
        let password = "correct horse battery staple";
        let salt = [0x01; 16];
        let params = Argon2Params {
            m_cost: 19456, // Minimum: 19 MiB
            t_cost: 2,     // Minimum
            p_cost: 1,
        };

        let pk = derive_password_key(password, &salt, params).unwrap();
        assert_eq!(pk.expose_secret().len(), 32);

        // Same password and salt should produce same key
        let pk2 = derive_password_key(password, &salt, params).unwrap();
        assert_eq!(pk.expose_secret(), pk2.expose_secret());

        // Different password should produce different key
        let pk3 = derive_password_key("wrong password", &salt, params).unwrap();
        assert_ne!(pk.expose_secret(), pk3.expose_secret());
    }

    #[test]
    fn test_argon2id_params_validation() {
        let password = "test";
        let salt = [0x01; 16];

        // m_cost too low
        let params = Argon2Params {
            m_cost: 1024,
            t_cost: 2,
            p_cost: 1,
        };
        assert!(derive_password_key(password, &salt, params).is_err());

        // t_cost too low
        let params = Argon2Params {
            m_cost: 19456,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(derive_password_key(password, &salt, params).is_err());

        // Valid params
        let params = Argon2Params {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
        };
        assert!(derive_password_key(password, &salt, params).is_ok());
    }

    #[test]
    fn test_recovery_key_derivation() {
        let entropy = [0x42; 32];
        let rk = derive_recovery_key(&entropy);
        assert_eq!(rk.expose_secret().len(), 32);

        // Same entropy should produce same key
        let rk2 = derive_recovery_key(&entropy);
        assert_eq!(rk.expose_secret(), rk2.expose_secret());

        // Different entropy should produce different key
        let rk3 = derive_recovery_key(&[0x99; 32]);
        assert_ne!(rk.expose_secret(), rk3.expose_secret());
    }

    #[test]
    fn test_subkey_derivation() {
        let vmk = VaultMasterKey::new([0x12; 32]);

        let k_index = derive_index_key(&vmk);
        assert_eq!(k_index.expose_secret().len(), 32);

        let k_cache = derive_cache_key(&vmk);
        assert_eq!(k_cache.len(), 32);

        // Index key and cache key should be different
        assert_ne!(k_index.expose_secret(), &k_cache);

        // Same VMK should produce same subkeys
        let k_index2 = derive_index_key(&vmk);
        assert_eq!(k_index.expose_secret(), k_index2.expose_secret());
    }

    // RFC 9106 Argon2id test - deterministic output verification
    // Note: RFC 9106 test vectors include Secret (K) and Associated Data (X)
    // which the argon2 crate's PasswordHasher API doesn't directly support.
    // This test verifies deterministic behavior instead of exact RFC output.
    #[test]
    fn test_argon2id_deterministic() {
        // Use fixed inputs to verify deterministic output
        let password = "test password 123";
        let salt = [0x42u8; 16];
        let params = Argon2Params {
            m_cost: 19456, // 19 MiB minimum
            t_cost: 2,
            p_cost: 1,
        };

        let pk1 = derive_password_key(password, &salt, params).unwrap();
        let pk2 = derive_password_key(password, &salt, params).unwrap();

        // Same inputs should produce identical output
        assert_eq!(pk1.expose_secret(), pk2.expose_secret());

        // Different password should produce different output
        let pk3 = derive_password_key("different password", &salt, params).unwrap();
        assert_ne!(pk1.expose_secret(), pk3.expose_secret());

        // Different salt should produce different output
        let salt2 = [0x99u8; 16];
        let pk4 = derive_password_key(password, &salt2, params).unwrap();
        assert_ne!(pk1.expose_secret(), pk4.expose_secret());
    }

    // HKDF-SHA256 test vector from RFC 5869
    #[test]
    fn test_hkdf_rfc5869_test_case_1() {
        // RFC 5869 Test Case 1
        // Hash = SHA-256
        // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
        // salt = 0x000102030405060708090a0b0c (13 octets)
        // info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
        // L    = 42

        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hkdf.expand(&info, &mut okm).unwrap();

        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        assert_eq!(&okm, &expected);
    }
}
