//! HPKE sealing for inbox records.
//!
//! Implements RFC 9180 HPKE base mode for sealing item records to the ingest public key.

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable,
    Kem as KemTrait, OpModeR, OpModeS, Serializable,
};

/// HPKE configuration
///
/// # Design (from DESIGN.md section 5)
/// - KEM: DHKEM(X25519, HKDF-SHA256)
/// - KDF: HKDF-SHA256
/// - AEAD: ChaCha20Poly1305
/// - Mode: Base (unauthenticated sender)
/// - Info: b"vault/inbox/v1" || vault_id
/// - AAD: device_id || seq
type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

/// Ingest keypair for sealing
pub struct IngestKeypair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// Generate a new ingest keypair (X25519)
pub fn generate_ingest_keypair() -> IngestKeypair {
    let mut csprng = rand::rngs::OsRng;
    let (secret_key, public_key) = Kem::gen_keypair(&mut csprng);

    IngestKeypair {
        public_key: public_key.to_bytes().to_vec(),
        private_key: secret_key.to_bytes().to_vec(),
    }
}

/// Seal data to the ingest public key using HPKE
///
/// # Design
/// - HPKE base mode (unauthenticated)
/// - Info: b"vault/inbox/v1" || vault_id
/// - AAD: device_id || seq
/// - Returns: (encapsulated_key, ciphertext)
///
/// # Parameters
/// - `ingest_public_key`: 32-byte X25519 public key
/// - `plaintext`: Data to seal (item record)
/// - `vault_id`: 16-byte vault identifier
/// - `device_id`: 16-byte device identifier
/// - `seq`: Sequence number (u64, big-endian in AAD)
pub fn seal(
    ingest_public_key: &[u8],
    plaintext: &[u8],
    vault_id: &[u8; 16],
    device_id: &[u8; 16],
    seq: u64,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Parse public key
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(ingest_public_key)
        .map_err(|e| format!("Invalid public key: {:?}", e))?;

    // Construct info: b"vault/inbox/v1" || vault_id
    let mut info = Vec::with_capacity(14 + 16);
    info.extend_from_slice(b"vault/inbox/v1");
    info.extend_from_slice(vault_id);

    // Construct AAD: device_id || seq (big-endian)
    let mut aad = Vec::with_capacity(16 + 8);
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(&seq.to_be_bytes());

    // Setup sender
    let mut csprng = rand::rngs::OsRng;
    let (encapsulated_key, mut sender_ctx) =
        hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &pk, &info, &mut csprng)
            .map_err(|e| format!("HPKE setup failed: {:?}", e))?;

    // Seal with AAD
    let ciphertext = sender_ctx
        .seal(plaintext, &aad)
        .map_err(|e| format!("HPKE seal failed: {:?}", e))?;

    Ok((encapsulated_key.to_bytes().to_vec(), ciphertext))
}

/// Open data sealed with HPKE
///
/// # Design
/// - Requires the ingest private key
/// - Info and AAD must match sealing
///
/// # Parameters
/// - `ingest_private_key`: 32-byte X25519 private key
/// - `encapsulated_key`: From sealing operation
/// - `ciphertext`: From sealing operation
/// - `vault_id`: 16-byte vault identifier (must match)
/// - `device_id`: 16-byte device identifier (must match)
/// - `seq`: Sequence number (must match)
pub fn open(
    ingest_private_key: &[u8],
    encapsulated_key: &[u8],
    ciphertext: &[u8],
    vault_id: &[u8; 16],
    device_id: &[u8; 16],
    seq: u64,
) -> Result<Vec<u8>, String> {
    // Parse private key
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(ingest_private_key)
        .map_err(|e| format!("Invalid private key: {:?}", e))?;

    // Parse encapsulated key
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(encapsulated_key)
        .map_err(|e| format!("Invalid encapsulated key: {:?}", e))?;

    // Construct info (must match sealing)
    let mut info = Vec::with_capacity(14 + 16);
    info.extend_from_slice(b"vault/inbox/v1");
    info.extend_from_slice(vault_id);

    // Construct AAD (must match sealing)
    let mut aad = Vec::with_capacity(16 + 8);
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(&seq.to_be_bytes());

    // Setup receiver
    let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, &info)
        .map_err(|e| format!("HPKE setup failed: {:?}", e))?;

    // Open with AAD
    let plaintext = receiver_ctx
        .open(ciphertext, &aad)
        .map_err(|_| "HPKE open failed (wrong key or tampered data)".to_string())?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ingest_keypair() {
        let keypair = generate_ingest_keypair();

        // X25519 keys are 32 bytes
        assert_eq!(keypair.public_key.len(), 32);
        assert_eq!(keypair.private_key.len(), 32);

        // Generate another - should be different
        let keypair2 = generate_ingest_keypair();
        assert_ne!(keypair.public_key, keypair2.public_key);
        assert_ne!(keypair.private_key, keypair2.private_key);
    }

    #[test]
    fn test_seal_open_round_trip() {
        let keypair = generate_ingest_keypair();
        let plaintext = b"test item record data";
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 42u64;

        // Seal
        let (enc, ct) = seal(&keypair.public_key, plaintext, &vault_id, &device_id, seq).unwrap();

        // Encapsulated key should be 32 bytes for X25519
        assert_eq!(enc.len(), 32);

        // Ciphertext should be plaintext + tag
        assert_eq!(ct.len(), plaintext.len() + 16);

        // Open
        let decrypted = open(&keypair.private_key, &enc, &ct, &vault_id, &device_id, seq).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let keypair = generate_ingest_keypair();
        let wrong_keypair = generate_ingest_keypair();
        let plaintext = b"test data";
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 42u64;

        let (enc, ct) = seal(&keypair.public_key, plaintext, &vault_id, &device_id, seq).unwrap();

        // Try to open with wrong private key
        assert!(open(
            &wrong_keypair.private_key,
            &enc,
            &ct,
            &vault_id,
            &device_id,
            seq
        )
        .is_err());
    }

    #[test]
    fn test_wrong_vault_id_fails() {
        let keypair = generate_ingest_keypair();
        let plaintext = b"test data";
        let vault_id = [0x11; 16];
        let wrong_vault_id = [0x99; 16];
        let device_id = [0x22; 16];
        let seq = 42u64;

        let (enc, ct) = seal(&keypair.public_key, plaintext, &vault_id, &device_id, seq).unwrap();

        // Open with wrong vault_id (wrong info)
        assert!(open(
            &keypair.private_key,
            &enc,
            &ct,
            &wrong_vault_id,
            &device_id,
            seq
        )
        .is_err());
    }

    #[test]
    fn test_wrong_device_id_fails() {
        let keypair = generate_ingest_keypair();
        let plaintext = b"test data";
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let wrong_device_id = [0x99; 16];
        let seq = 42u64;

        let (enc, ct) = seal(&keypair.public_key, plaintext, &vault_id, &device_id, seq).unwrap();

        // Open with wrong device_id (wrong AAD)
        assert!(open(
            &keypair.private_key,
            &enc,
            &ct,
            &vault_id,
            &wrong_device_id,
            seq
        )
        .is_err());
    }

    #[test]
    fn test_wrong_seq_fails() {
        let keypair = generate_ingest_keypair();
        let plaintext = b"test data";
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 42u64;

        let (enc, ct) = seal(&keypair.public_key, plaintext, &vault_id, &device_id, seq).unwrap();

        // Open with wrong seq (wrong AAD)
        assert!(open(&keypair.private_key, &enc, &ct, &vault_id, &device_id, 43).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let keypair = generate_ingest_keypair();
        let plaintext = b"test data";
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 42u64;

        let (enc, mut ct) =
            seal(&keypair.public_key, plaintext, &vault_id, &device_id, seq).unwrap();

        // Tamper with ciphertext
        ct[0] ^= 0x01;

        // Should fail authentication
        assert!(open(&keypair.private_key, &enc, &ct, &vault_id, &device_id, seq).is_err());
    }

    #[test]
    fn test_tampered_enc_fails() {
        let keypair = generate_ingest_keypair();
        let plaintext = b"test data";
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 42u64;

        let (mut enc, ct) =
            seal(&keypair.public_key, plaintext, &vault_id, &device_id, seq).unwrap();

        // Tamper with encapsulated key
        enc[0] ^= 0x01;

        // Should fail
        assert!(open(&keypair.private_key, &enc, &ct, &vault_id, &device_id, seq).is_err());
    }

    #[test]
    fn test_different_seals_have_different_enc() {
        let keypair = generate_ingest_keypair();
        let plaintext = b"test data";
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 42u64;

        // Seal twice
        let (enc1, _ct1) =
            seal(&keypair.public_key, plaintext, &vault_id, &device_id, seq).unwrap();

        let (enc2, _ct2) =
            seal(&keypair.public_key, plaintext, &vault_id, &device_id, seq).unwrap();

        // Encapsulated keys should be different (ephemeral sender key)
        assert_ne!(enc1, enc2);
    }
}
