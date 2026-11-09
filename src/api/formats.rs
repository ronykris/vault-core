//! Format serialization functions (for golden files and testing in M1)
//!
//! These will become private in M2 when wrapped in VaultSession APIs.

use crate::format::header;

/// Vault header structure (public for M1 golden files, will be opaque in M2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    /// Vault identifier (16 bytes)
    pub vault_id: [u8; 16],
    /// Key epoch number (for rotation)
    pub key_epoch: u32,
    /// Argon2 memory cost in KiB
    pub argon2_m_cost: u32,
    /// Argon2 time cost (iterations)
    pub argon2_t_cost: u32,
    /// Argon2 parallelism
    pub argon2_p_cost: u32,
    /// Argon2 salt (16 bytes)
    pub argon2_salt: [u8; 16],
    /// VMK wrapped with password key (72 bytes)
    pub wrap_pw: Vec<u8>,         // 72 bytes
    /// VMK wrapped with recovery key (72 bytes)
    pub wrap_rec: Vec<u8>,        // 72 bytes
    /// HPKE ingest public key (32 bytes)
    pub ingest_pub: [u8; 32],
    /// HPKE ingest private key, encrypted (72 bytes)
    pub ingest_priv_enc: Vec<u8>, // 72 bytes
}

impl From<header::VaultHeader> for VaultHeader {
    fn from(h: header::VaultHeader) -> Self {
        VaultHeader {
            vault_id: h.vault_id,
            key_epoch: h.key_epoch,
            argon2_m_cost: h.argon2.m_cost,
            argon2_t_cost: h.argon2.t_cost,
            argon2_p_cost: h.argon2.p_cost,
            argon2_salt: h.argon2.salt,
            wrap_pw: h.wrap_pw,
            wrap_rec: h.wrap_rec,
            ingest_pub: h.ingest_pub,
            ingest_priv_enc: h.ingest_priv_enc,
        }
    }
}

impl From<VaultHeader> for header::VaultHeader {
    fn from(h: VaultHeader) -> Self {
        header::VaultHeader {
            v: 1,
            vault_id: h.vault_id,
            key_epoch: h.key_epoch,
            argon2: header::Argon2Params {
                m_cost: h.argon2_m_cost,
                t_cost: h.argon2_t_cost,
                p_cost: h.argon2_p_cost,
                salt: h.argon2_salt,
            },
            wrap_pw: h.wrap_pw,
            wrap_rec: h.wrap_rec,
            ingest_pub: h.ingest_pub,
            ingest_priv_enc: h.ingest_priv_enc,
        }
    }
}

/// Serialize a vault header to CBOR
///
/// # Errors
/// - Invalid schema version (must be 1)
/// - Invalid key epoch (must be >= 1)
/// - Invalid Argon2 parameters (below minimums)
/// - Invalid wrapped key sizes (must be 72 bytes)
pub fn serialize_vault_header(header: &VaultHeader) -> Result<Vec<u8>, String> {
    let internal: header::VaultHeader = header.clone().into();
    internal.to_cbor()
}

/// Deserialize a vault header from CBOR
///
/// # Errors
/// - Invalid CBOR
/// - Unsupported schema version
/// - Invalid parameters
pub fn deserialize_vault_header(bytes: &[u8]) -> Result<VaultHeader, String> {
    let internal = header::VaultHeader::from_cbor(bytes)?;
    Ok(internal.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> VaultHeader {
        VaultHeader {
            vault_id: [0x11; 16],
            key_epoch: 1,
            argon2_m_cost: 65536,
            argon2_t_cost: 3,
            argon2_p_cost: 1,
            argon2_salt: [0x22; 16],
            wrap_pw: vec![0x33; 72],
            wrap_rec: vec![0x44; 72],
            ingest_pub: [0x55; 32],
            ingest_priv_enc: vec![0x66; 72],
        }
    }

    #[test]
    fn test_serialize_deserialize_vault_header() {
        let header = sample_header();

        let cbor = serialize_vault_header(&header).unwrap();
        let decoded = deserialize_vault_header(&cbor).unwrap();

        assert_eq!(decoded, header);
    }

    #[test]
    fn test_vault_header_fields() {
        let header = sample_header();
        let cbor = serialize_vault_header(&header).unwrap();
        let decoded = deserialize_vault_header(&cbor).unwrap();

        assert_eq!(decoded.vault_id, [0x11; 16]);
        assert_eq!(decoded.key_epoch, 1);
        assert_eq!(decoded.argon2_m_cost, 65536);
        assert_eq!(decoded.argon2_t_cost, 3);
        assert_eq!(decoded.argon2_p_cost, 1);
        assert_eq!(decoded.argon2_salt, [0x22; 16]);
        assert_eq!(decoded.wrap_pw, vec![0x33; 72]);
        assert_eq!(decoded.wrap_rec, vec![0x44; 72]);
        assert_eq!(decoded.ingest_pub, [0x55; 32]);
        assert_eq!(decoded.ingest_priv_enc, vec![0x66; 72]);
    }

    #[test]
    fn test_serialize_invalid_wrap_size() {
        let mut header = sample_header();
        header.wrap_pw = vec![0x33; 50]; // Wrong size

        assert!(serialize_vault_header(&header).is_err());
    }

    #[test]
    fn test_serialize_invalid_argon2_params() {
        let mut header = sample_header();
        header.argon2_m_cost = 1000; // Too low

        assert!(serialize_vault_header(&header).is_err());
    }

    #[test]
    fn test_serialize_invalid_key_epoch() {
        let mut header = sample_header();
        header.key_epoch = 0;

        assert!(serialize_vault_header(&header).is_err());
    }
}
