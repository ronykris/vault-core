//! Vault header CBOR serialization.
//!
//! The header contains KDF parameters, wrapped VMK (under both password and recovery keys),
//! HPKE ingest keypair, vault ID, and key epoch. It is uploaded to Drive as `h_<seq>`.
//!
//! Schema version 1 from DESIGN.md section 6.

use ciborium::{de::from_reader, ser::into_writer};
use serde::{Deserialize, Serialize};

/// Argon2id parameters for KDF
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB (minimum 19456 = 19 MiB)
    pub m_cost: u32,
    /// Time cost (minimum 2)
    pub t_cost: u32,
    /// Parallelism
    pub p_cost: u32,
    /// 16-byte salt
    pub salt: [u8; 16],
}

impl Argon2Params {
    /// Validate parameters against DESIGN.md minimums
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
            return Err(format!("Parallelism {} is below minimum 1", self.p_cost));
        }
        if self.salt.len() != 16 {
            return Err(format!("Salt must be 16 bytes, got {}", self.salt.len()));
        }
        Ok(())
    }
}

/// Vault header (CBOR map)
///
/// # Design (from DESIGN.md section 6)
/// This structure is stored on Drive as `h_<seq>`. It contains all the key material
/// needed to unlock the vault, plus metadata for key rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    /// Schema version (must be 1)
    pub v: u8,

    /// Vault identifier (16 bytes, random, immutable)
    pub vault_id: [u8; 16],

    /// Key epoch (for future VMK rotation, currently always 1)
    pub key_epoch: u32,

    /// Argon2id parameters for password → PK derivation
    pub argon2: Argon2Params,

    /// VMK wrapped under password key (PK)
    /// Format: 24-byte nonce || ciphertext || 16-byte tag
    pub wrap_pw: Vec<u8>,

    /// VMK wrapped under recovery key (RK)
    /// Format: 24-byte nonce || ciphertext || 16-byte tag
    pub wrap_rec: Vec<u8>,

    /// HPKE ingest public key (32 bytes, X25519)
    pub ingest_pub: [u8; 32],

    /// HPKE ingest private key, wrapped under VMK
    /// Format: 24-byte nonce || ciphertext || 16-byte tag
    pub ingest_priv_enc: Vec<u8>,
}

impl VaultHeader {
    /// Serialize to CBOR bytes
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        // Validate schema version
        if self.v != 1 {
            return Err(format!("Unsupported schema version: {}", self.v));
        }

        // Validate key epoch
        if self.key_epoch < 1 {
            return Err(format!("key_epoch must be >= 1, got {}", self.key_epoch));
        }

        // Validate Argon2 parameters
        self.argon2.validate()?;

        // Validate wrapped key sizes
        // XChaCha20-Poly1305: 24-byte nonce + 32-byte key + 16-byte tag = 72 bytes
        if self.wrap_pw.len() != 72 {
            return Err(format!(
                "wrap_pw must be 72 bytes (24 nonce + 32 ct + 16 tag), got {}",
                self.wrap_pw.len()
            ));
        }

        if self.wrap_rec.len() != 72 {
            return Err(format!(
                "wrap_rec must be 72 bytes (24 nonce + 32 ct + 16 tag), got {}",
                self.wrap_rec.len()
            ));
        }

        if self.ingest_priv_enc.len() != 72 {
            return Err(format!(
                "ingest_priv_enc must be 72 bytes (24 nonce + 32 ct + 16 tag), got {}",
                self.ingest_priv_enc.len()
            ));
        }

        let mut bytes = Vec::new();
        into_writer(self, &mut bytes).map_err(|e| format!("CBOR serialization failed: {}", e))?;
        Ok(bytes)
    }

    /// Deserialize from CBOR bytes
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        let header: VaultHeader =
            from_reader(bytes).map_err(|e| format!("CBOR deserialization failed: {}", e))?;

        // Validate schema version
        if header.v != 1 {
            return Err(format!("Unsupported schema version: {}", header.v));
        }

        // Validate key epoch
        if header.key_epoch < 1 {
            return Err(format!("key_epoch must be >= 1, got {}", header.key_epoch));
        }

        // Validate Argon2 parameters
        header.argon2.validate()?;

        // Validate wrapped key sizes
        if header.wrap_pw.len() != 72 {
            return Err(format!(
                "wrap_pw must be 72 bytes (24 nonce + 32 ct + 16 tag), got {}",
                header.wrap_pw.len()
            ));
        }

        if header.wrap_rec.len() != 72 {
            return Err(format!(
                "wrap_rec must be 72 bytes (24 nonce + 32 ct + 16 tag), got {}",
                header.wrap_rec.len()
            ));
        }

        if header.ingest_priv_enc.len() != 72 {
            return Err(format!(
                "ingest_priv_enc must be 72 bytes (24 nonce + 32 ct + 16 tag), got {}",
                header.ingest_priv_enc.len()
            ));
        }

        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> VaultHeader {
        VaultHeader {
            v: 1,
            vault_id: [0x11; 16],
            key_epoch: 1,
            argon2: Argon2Params {
                m_cost: 65536, // 64 MiB
                t_cost: 3,
                p_cost: 1,
                salt: [0x22; 16],
            },
            wrap_pw: vec![0x33; 72], // 24 nonce + 32 ct + 16 tag
            wrap_rec: vec![0x44; 72],
            ingest_pub: [0x55; 32],
            ingest_priv_enc: vec![0x66; 72],
        }
    }

    #[test]
    fn test_header_round_trip() {
        let header = sample_header();

        let cbor = header.to_cbor().unwrap();
        let decoded = VaultHeader::from_cbor(&cbor).unwrap();

        assert_eq!(decoded, header);
    }

    #[test]
    fn test_header_fields() {
        let header = sample_header();
        let cbor = header.to_cbor().unwrap();
        let decoded = VaultHeader::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.v, 1);
        assert_eq!(decoded.vault_id, [0x11; 16]);
        assert_eq!(decoded.key_epoch, 1);
        assert_eq!(decoded.argon2.m_cost, 65536);
        assert_eq!(decoded.argon2.t_cost, 3);
        assert_eq!(decoded.argon2.p_cost, 1);
        assert_eq!(decoded.argon2.salt, [0x22; 16]);
        assert_eq!(decoded.wrap_pw, vec![0x33; 72]);
        assert_eq!(decoded.wrap_rec, vec![0x44; 72]);
        assert_eq!(decoded.ingest_pub, [0x55; 32]);
        assert_eq!(decoded.ingest_priv_enc, vec![0x66; 72]);
    }

    #[test]
    fn test_argon2_params_validation() {
        let mut params = Argon2Params {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
            salt: [0x22; 16],
        };

        // Valid params
        assert!(params.validate().is_ok());

        // m_cost too low
        params.m_cost = 10000;
        assert!(params.validate().is_err());
        params.m_cost = 65536;

        // t_cost too low
        params.t_cost = 1;
        assert!(params.validate().is_err());
        params.t_cost = 3;

        // p_cost too low
        params.p_cost = 0;
        assert!(params.validate().is_err());
        params.p_cost = 1;

        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_argon2_minimum_params() {
        let header = VaultHeader {
            v: 1,
            vault_id: [0x11; 16],
            key_epoch: 1,
            argon2: Argon2Params {
                m_cost: 19456, // Minimum 19 MiB
                t_cost: 2,     // Minimum
                p_cost: 1,
                salt: [0x22; 16],
            },
            wrap_pw: vec![0x33; 72],
            wrap_rec: vec![0x44; 72],
            ingest_pub: [0x55; 32],
            ingest_priv_enc: vec![0x66; 72],
        };

        let cbor = header.to_cbor().unwrap();
        let decoded = VaultHeader::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.argon2.m_cost, 19456);
        assert_eq!(decoded.argon2.t_cost, 2);
    }

    #[test]
    fn test_argon2_high_params() {
        let header = VaultHeader {
            v: 1,
            vault_id: [0x11; 16],
            key_epoch: 1,
            argon2: Argon2Params {
                m_cost: 524288, // 512 MiB
                t_cost: 10,
                p_cost: 4,
                salt: [0x22; 16],
            },
            wrap_pw: vec![0x33; 72],
            wrap_rec: vec![0x44; 72],
            ingest_pub: [0x55; 32],
            ingest_priv_enc: vec![0x66; 72],
        };

        let cbor = header.to_cbor().unwrap();
        let decoded = VaultHeader::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.argon2.m_cost, 524288);
        assert_eq!(decoded.argon2.t_cost, 10);
        assert_eq!(decoded.argon2.p_cost, 4);
    }

    #[test]
    fn test_invalid_schema_version_serialize() {
        let mut header = sample_header();
        header.v = 2;

        assert!(header.to_cbor().is_err());
    }

    #[test]
    fn test_invalid_schema_version_deserialize() {
        let mut header = sample_header();
        header.v = 99;

        // Bypass validation during serialization
        let mut bytes = Vec::new();
        into_writer(&header, &mut bytes).unwrap();

        // Should fail during deserialization
        assert!(VaultHeader::from_cbor(&bytes).is_err());
    }

    #[test]
    fn test_invalid_key_epoch() {
        let mut header = sample_header();
        header.key_epoch = 0;

        assert!(header.to_cbor().is_err());
    }

    #[test]
    fn test_future_key_epoch() {
        let mut header = sample_header();
        header.key_epoch = 5;

        let cbor = header.to_cbor().unwrap();
        let decoded = VaultHeader::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.key_epoch, 5);
    }

    #[test]
    fn test_invalid_wrap_pw_size() {
        let mut header = sample_header();
        header.wrap_pw = vec![0x33; 71]; // Too short

        assert!(header.to_cbor().is_err());

        header.wrap_pw = vec![0x33; 73]; // Too long
        assert!(header.to_cbor().is_err());
    }

    #[test]
    fn test_invalid_wrap_rec_size() {
        let mut header = sample_header();
        header.wrap_rec = vec![0x44; 50]; // Wrong size

        assert!(header.to_cbor().is_err());
    }

    #[test]
    fn test_invalid_ingest_priv_enc_size() {
        let mut header = sample_header();
        header.ingest_priv_enc = vec![0x66; 100]; // Wrong size

        assert!(header.to_cbor().is_err());
    }

    #[test]
    fn test_different_vault_ids() {
        let mut header1 = sample_header();
        header1.vault_id = [0xaa; 16];

        let mut header2 = sample_header();
        header2.vault_id = [0xbb; 16];

        let cbor1 = header1.to_cbor().unwrap();
        let cbor2 = header2.to_cbor().unwrap();

        let decoded1 = VaultHeader::from_cbor(&cbor1).unwrap();
        let decoded2 = VaultHeader::from_cbor(&cbor2).unwrap();

        assert_eq!(decoded1.vault_id, [0xaa; 16]);
        assert_eq!(decoded2.vault_id, [0xbb; 16]);
        assert_ne!(decoded1.vault_id, decoded2.vault_id);
    }

    #[test]
    fn test_cbor_determinism() {
        // Same header should serialize to same bytes (CBOR is deterministic with ciborium)
        let header = sample_header();

        let cbor1 = header.to_cbor().unwrap();
        let cbor2 = header.to_cbor().unwrap();

        assert_eq!(cbor1, cbor2);
    }
}
