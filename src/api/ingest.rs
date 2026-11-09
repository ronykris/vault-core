//! HPKE ingest functions for write-only sealing
//!
//! IngestContext provides a write-only handle for background workers to seal
//! item records without holding any decryption keys.

use crate::crypto::hpke_seal;

/// Generate an HPKE ingest keypair (X25519)
///
/// Returns: (public_key: 32 bytes, private_key: 32 bytes)
///
/// The public key goes in the vault header for write-only ingest.
/// The private key is wrapped under VMK and stored encrypted in the header.
///
/// # Example
/// ```ignore
/// let (ingest_pub, ingest_priv) = generate_ingest_keypair();
/// let ingest_priv_enc = wrap_ingest_private_key(&vmk, &ingest_priv, &vault_id)?;
/// // Store ingest_pub and ingest_priv_enc in vault header
/// ```
pub fn generate_ingest_keypair() -> ([u8; 32], [u8; 32]) {
    let keypair = hpke_seal::generate_ingest_keypair();
    let pub_key: [u8; 32] = keypair.public_key.try_into().expect("32 bytes");
    let priv_key: [u8; 32] = keypair.private_key.try_into().expect("32 bytes");
    (pub_key, priv_key)
}

/// Seal an item record for write-only ingest (HPKE base mode)
///
/// Uses RFC 9180 HPKE with X25519 + HKDF-SHA256 + ChaCha20-Poly1305.
///
/// # Parameters
/// - `ingest_pub`: HPKE public key from vault header (32 bytes)
/// - `plaintext`: CBOR-serialized ItemRecord
/// - `vault_id`: 16-byte vault identifier
/// - `device_id`: 16-byte device identifier
/// - `seq`: Monotonic sequence number per device
///
/// # Returns
/// (encapsulated_key: 32 bytes, ciphertext)
///
/// The caller must sign this with the device Ed25519 key:
/// ```ignore
/// let sig = sign_inbox_record(device_signing_key, device_id, seq, &enc, &ct)?;
/// ```
///
/// # HPKE Construction
/// - info = b"vault/inbox/v1" || vault_id
/// - aad = device_id || seq (big-endian)
///
/// # Example
/// ```ignore
/// let (enc, ct) = seal_item_record(&ingest_pub, &cbor_record, &vault_id, &device_id, seq)?;
/// let sig = sign_inbox_record(&device_key, &device_id, seq, &enc, &ct)?;
/// // Upload {device_id, seq, enc, ct, sig} to inbox batch
/// ```
pub fn seal_item_record(
    ingest_pub: &[u8; 32],
    plaintext: &[u8],
    vault_id: &[u8; 16],
    device_id: &[u8; 16],
    seq: u64,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    hpke_seal::seal(ingest_pub, plaintext, vault_id, device_id, seq)
}

/// Open a sealed item record (requires VMK for unwrapped ingest private key)
///
/// # Parameters
/// - `ingest_priv`: HPKE private key (32 bytes, unwrapped from vault header with VMK)
/// - `enc`: Encapsulated key from seal_item_record (32 bytes)
/// - `ct`: Ciphertext from seal_item_record
/// - `vault_id`: 16-byte vault identifier (must match sealing)
/// - `device_id`: 16-byte device identifier (must match sealing)
/// - `seq`: Sequence number (must match sealing)
///
/// # Returns
/// CBOR-serialized ItemRecord
///
/// # Errors
/// - Wrong private key
/// - Wrong vault_id, device_id, or seq (AAD mismatch)
/// - Tampered ciphertext
///
/// # Example
/// ```ignore
/// // After unlocking vault with VMK:
/// let ingest_priv = unwrap_ingest_private_key(&vmk, &header.ingest_priv_enc, &vault_id)?;
///
/// // Open inbox record (after signature verification):
/// let cbor_record = open_item_record(&ingest_priv, &enc, &ct, &vault_id, &device_id, seq)?;
/// ```
pub fn open_item_record(
    ingest_priv: &[u8; 32],
    enc: &[u8],
    ct: &[u8],
    vault_id: &[u8; 16],
    device_id: &[u8; 16],
    seq: u64,
) -> Result<Vec<u8>, String> {
    hpke_seal::open(ingest_priv, enc, ct, vault_id, device_id, seq)
}

/// Write-only ingest context for background workers
///
/// This type holds only the ingest public key and vault_id. Background workers
/// use it to seal item records without having any decryption capability.
///
/// # Security
/// - Holds NO decryption keys
/// - Cannot decrypt anything it seals
/// - Kotlin background workers hold this as an opaque handle
/// - Human-reviewable that this type has no path to VMK or any private key
#[derive(Debug, Clone)]
pub struct IngestContext {
    ingest_pub: [u8; 32],
    vault_id: [u8; 16],
}

impl IngestContext {
    /// Create a new IngestContext from an ingest public key
    ///
    /// # Parameters
    /// - `ingest_pub`: HPKE public key from vault header (32 bytes)
    /// - `vault_id`: Vault identifier (16 bytes)
    ///
    /// # Example
    /// ```ignore
    /// // After vault creation, background worker gets:
    /// let ctx = IngestContext::new(header.ingest_pub, header.vault_id);
    /// ```
    pub fn new(ingest_pub: [u8; 32], vault_id: [u8; 16]) -> Self {
        Self {
            ingest_pub,
            vault_id,
        }
    }

    /// Seal an item record for write-only ingest
    ///
    /// # Parameters
    /// - `item_record`: CBOR-serialized ItemRecord
    /// - `device_id`: 16-byte device identifier
    /// - `seq`: Monotonic sequence number per device
    ///
    /// # Returns
    /// (encapsulated_key, ciphertext)
    ///
    /// The caller must sign the result with the device signing key.
    pub fn seal_item_record(
        &self,
        item_record: &[u8],
        device_id: &[u8; 16],
        seq: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        seal_item_record(&self.ingest_pub, item_record, &self.vault_id, device_id, seq)
    }

    /// Sign a sealed inbox record with the device signing key
    ///
    /// # Parameters
    /// - `signing_key`: Ed25519 signing key (32 bytes, from device enrollment)
    /// - `device_id`: 16-byte device identifier (must match enrollment)
    /// - `seq`: Sequence number (must match seal)
    /// - `enc`: Encapsulated key from seal_item_record
    /// - `ct`: Ciphertext from seal_item_record
    ///
    /// # Returns
    /// Ed25519 signature (64 bytes)
    ///
    /// # Example
    /// ```ignore
    /// let (enc, ct) = ctx.seal_item_record(&cbor_record, &device_id, seq)?;
    /// let sig = ctx.sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct)?;
    /// // Upload {device_id, seq, enc, ct, sig} to inbox batch
    /// ```
    pub fn sign_inbox_record(
        &self,
        signing_key: &[u8; 32],
        device_id: &[u8; 16],
        seq: u64,
        enc: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, String> {
        crate::api::signatures::sign_inbox_record(signing_key, device_id, seq, enc, ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::signatures::{generate_device_signing_key, verify_inbox_record};

    #[test]
    fn test_generate_ingest_keypair() {
        let (pub1, priv1) = generate_ingest_keypair();
        let (pub2, priv2) = generate_ingest_keypair();

        // Keys should be 32 bytes
        assert_eq!(pub1.len(), 32);
        assert_eq!(priv1.len(), 32);

        // Different each time
        assert_ne!(pub1, pub2);
        assert_ne!(priv1, priv2);
    }

    #[test]
    fn test_seal_open_round_trip() {
        let (ingest_pub, ingest_priv) = generate_ingest_keypair();
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 42;
        let plaintext = b"test item record";

        let (enc, ct) = seal_item_record(&ingest_pub, plaintext, &vault_id, &device_id, seq)
            .unwrap();

        // Encapsulated key should be 32 bytes (X25519 public key)
        assert_eq!(enc.len(), 32);

        // Ciphertext should be plaintext + 16-byte tag
        assert_eq!(ct.len(), plaintext.len() + 16);

        let decrypted =
            open_item_record(&ingest_priv, &enc, &ct, &vault_id, &device_id, seq).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_open_with_wrong_private_key() {
        let (ingest_pub, _) = generate_ingest_keypair();
        let (_, wrong_priv) = generate_ingest_keypair();
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 42;
        let plaintext = b"secret";

        let (enc, ct) = seal_item_record(&ingest_pub, plaintext, &vault_id, &device_id, seq)
            .unwrap();

        assert!(open_item_record(&wrong_priv, &enc, &ct, &vault_id, &device_id, seq).is_err());
    }

    #[test]
    fn test_open_with_wrong_vault_id() {
        let (ingest_pub, ingest_priv) = generate_ingest_keypair();
        let vault_id = [0x11; 16];
        let wrong_vault_id = [0x99; 16];
        let device_id = [0x22; 16];
        let seq = 42;
        let plaintext = b"data";

        let (enc, ct) = seal_item_record(&ingest_pub, plaintext, &vault_id, &device_id, seq)
            .unwrap();

        assert!(
            open_item_record(&ingest_priv, &enc, &ct, &wrong_vault_id, &device_id, seq).is_err()
        );
    }

    #[test]
    fn test_open_with_wrong_device_id() {
        let (ingest_pub, ingest_priv) = generate_ingest_keypair();
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let wrong_device_id = [0x99; 16];
        let seq = 42;
        let plaintext = b"data";

        let (enc, ct) = seal_item_record(&ingest_pub, plaintext, &vault_id, &device_id, seq)
            .unwrap();

        assert!(
            open_item_record(&ingest_priv, &enc, &ct, &vault_id, &wrong_device_id, seq).is_err()
        );
    }

    #[test]
    fn test_open_with_wrong_seq() {
        let (ingest_pub, ingest_priv) = generate_ingest_keypair();
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 42;
        let plaintext = b"data";

        let (enc, ct) = seal_item_record(&ingest_pub, plaintext, &vault_id, &device_id, seq)
            .unwrap();

        assert!(open_item_record(&ingest_priv, &enc, &ct, &vault_id, &device_id, 43).is_err());
    }

    #[test]
    fn test_seal_is_non_deterministic() {
        // HPKE base mode uses ephemeral sender keys
        let (ingest_pub, _) = generate_ingest_keypair();
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 42;
        let plaintext = b"data";

        let (enc1, _ct1) = seal_item_record(&ingest_pub, plaintext, &vault_id, &device_id, seq)
            .unwrap();
        let (enc2, _ct2) = seal_item_record(&ingest_pub, plaintext, &vault_id, &device_id, seq)
            .unwrap();

        // Encapsulated keys should differ (different ephemeral keys)
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_ingest_context_seal_and_sign() {
        let (ingest_pub, ingest_priv) = generate_ingest_keypair();
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 1;
        let item_record = b"CBOR item record";

        // Create IngestContext (background worker API)
        let ctx = IngestContext::new(ingest_pub, vault_id);

        // Seal with context
        let (enc, ct) = ctx.seal_item_record(item_record, &device_id, seq).unwrap();

        // Sign with context
        let (signing_key, verifying_key) = generate_device_signing_key().unwrap();
        let sig = ctx.sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct).unwrap();

        // Verify signature
        let sig_array: [u8; 64] = sig.try_into().unwrap();
        verify_inbox_record(&verifying_key, &device_id, seq, &enc, &ct, &sig_array).unwrap();

        // Open with private key (unlocked client)
        let plaintext = open_item_record(&ingest_priv, &enc, &ct, &vault_id, &device_id, seq).unwrap();
        assert_eq!(&plaintext[..], item_record);
    }

    #[test]
    fn test_ingest_context_has_no_decrypt_capability() {
        // This test documents that IngestContext holds NO decryption keys
        let (ingest_pub, _ingest_priv) = generate_ingest_keypair();
        let vault_id = [0x11; 16];
        let device_id = [0x22; 16];
        let seq = 1;
        let item_record = b"secret data";

        let ctx = IngestContext::new(ingest_pub, vault_id);

        // Seal data
        let (enc, ct) = ctx.seal_item_record(item_record, &device_id, seq).unwrap();

        // IngestContext cannot decrypt - it only has the public key
        // There is no decrypt method on IngestContext
        // This is verified by:
        // 1. No `ingest_priv` field in IngestContext
        // 2. No method that calls open_item_record
        // 3. Human code review of this struct

        // To prove: try to access ingest_priv (compile error)
        // ctx.ingest_priv; // This would not compile

        // Only holder of ingest_priv can decrypt
        // (which requires an unlocked VaultSession)
        assert!(enc.len() == 32);
        assert!(ct.len() > 0);
    }
}
