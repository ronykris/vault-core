//! Ed25519 signature functions for inbox authentication

use crate::crypto::signatures;

/// Generate an Ed25519 device signing keypair
///
/// Returns: (signing_key: 32 bytes, verifying_key: 32 bytes)
///
/// Each device generates its own Ed25519 keypair. The signing key stays on device,
/// the verifying key is enrolled in the vault index for inbox authentication.
///
/// # Example
/// ```ignore
/// let (signing_key, verifying_key) = generate_device_signing_key();
/// // Store signing_key securely on device
/// // Enroll verifying_key in vault (written to index segment)
/// ```
pub fn generate_device_signing_key() -> Result<([u8; 32], [u8; 32]), String> {
    let keypair = signatures::generate_device_signing_key()?;
    Ok((
        keypair.signing_key.try_into().expect("32 bytes"),
        keypair.verifying_key.try_into().expect("32 bytes"),
    ))
}

/// Sign an inbox record with device Ed25519 key
///
/// # Message Construction
/// ```text
/// b"vault/inbox-sig/v1" || device_id || seq || enc || ct
/// ```
///
/// # Parameters
/// - `signing_key`: 32-byte Ed25519 private key
/// - `device_id`: 16-byte device identifier (must match sealed record)
/// - `seq`: Sequence number (must match sealed record)
/// - `enc`: HPKE encapsulated key from seal_item_record
/// - `ct`: HPKE ciphertext from seal_item_record
///
/// # Returns
/// 64-byte Ed25519 signature
///
/// # Example
/// ```ignore
/// let (enc, ct) = seal_item_record(&ingest_pub, &cbor, &vault_id, &device_id, seq)?;
/// let sig = sign_inbox_record(&device_signing_key, &device_id, seq, &enc, &ct)?;
/// // Upload {device_id, seq, enc, ct, sig} to inbox batch
/// ```
pub fn sign_inbox_record(
    signing_key: &[u8; 32],
    device_id: &[u8; 16],
    seq: u64,
    enc: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, String> {
    signatures::sign_inbox_record(signing_key, device_id, seq, enc, ct)
}

/// Verify an inbox record signature
///
/// # Parameters
/// - `verifying_key`: 32-byte Ed25519 public key (from device enrolment)
/// - `device_id`: 16-byte device identifier (must match signing)
/// - `seq`: Sequence number (must match signing)
/// - `enc`: HPKE encapsulated key (must match signing)
/// - `ct`: HPKE ciphertext (must match signing)
/// - `signature`: 64-byte Ed25519 signature from sign_inbox_record
///
/// # Errors
/// - Signature verification failed (wrong key, tampered data, or mismatched parameters)
///
/// # Example
/// ```ignore
/// // Before opening an inbox record, verify its signature:
/// verify_inbox_record(&enrolled_device_key, &device_id, seq, &enc, &ct, &sig)?;
///
/// // Only then open it:
/// let cbor = open_item_record(&ingest_priv, &enc, &ct, &vault_id, &device_id, seq)?;
/// ```
pub fn verify_inbox_record(
    verifying_key: &[u8; 32],
    device_id: &[u8; 16],
    seq: u64,
    enc: &[u8],
    ct: &[u8],
    signature: &[u8; 64],
) -> Result<(), String> {
    signatures::verify_inbox_record(verifying_key, device_id, seq, enc, ct, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_device_signing_key() {
        let (sk1, vk1) = generate_device_signing_key().unwrap();
        let (sk2, vk2) = generate_device_signing_key().unwrap();

        // Keys should be 32 bytes
        assert_eq!(sk1.len(), 32);
        assert_eq!(vk1.len(), 32);

        // Different each time
        assert_ne!(sk1, sk2);
        assert_ne!(vk1, vk2);
    }

    #[test]
    fn test_sign_verify_round_trip() {
        let (signing_key, verifying_key) = generate_device_signing_key().unwrap();
        let device_id = [0x42; 16];
        let seq = 123;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];

        let sig = sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct).unwrap();

        // Signature should be 64 bytes
        assert_eq!(sig.len(), 64);

        // Convert Vec to [u8; 64]
        let sig_array: [u8; 64] = sig.try_into().unwrap();

        // Verify should succeed
        verify_inbox_record(&verifying_key, &device_id, seq, &enc, &ct, &sig_array).unwrap();
    }

    #[test]
    fn test_verify_with_wrong_key() {
        let (signing_key, _) = generate_device_signing_key().unwrap();
        let (_, wrong_verifying_key) = generate_device_signing_key().unwrap();
        let device_id = [0x42; 16];
        let seq = 123;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];

        let sig = sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct).unwrap();
        let sig_array: [u8; 64] = sig.try_into().unwrap();

        assert!(verify_inbox_record(&wrong_verifying_key, &device_id, seq, &enc, &ct, &sig_array)
            .is_err());
    }

    #[test]
    fn test_verify_with_wrong_device_id() {
        let (signing_key, verifying_key) = generate_device_signing_key().unwrap();
        let device_id = [0x42; 16];
        let wrong_device_id = [0x99; 16];
        let seq = 123;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];

        let sig = sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct).unwrap();
        let sig_array: [u8; 64] = sig.try_into().unwrap();

        assert!(
            verify_inbox_record(&verifying_key, &wrong_device_id, seq, &enc, &ct, &sig_array)
                .is_err()
        );
    }

    #[test]
    fn test_verify_with_wrong_seq() {
        let (signing_key, verifying_key) = generate_device_signing_key().unwrap();
        let device_id = [0x42; 16];
        let seq = 123;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];

        let sig = sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct).unwrap();
        let sig_array: [u8; 64] = sig.try_into().unwrap();

        assert!(verify_inbox_record(&verifying_key, &device_id, 124, &enc, &ct, &sig_array)
            .is_err());
    }

    #[test]
    fn test_verify_with_tampered_enc() {
        let (signing_key, verifying_key) = generate_device_signing_key().unwrap();
        let device_id = [0x42; 16];
        let seq = 123;
        let enc = vec![0xaa; 32];
        let mut tampered_enc = enc.clone();
        tampered_enc[0] ^= 0x01;
        let ct = vec![0xbb; 100];

        let sig = sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct).unwrap();
        let sig_array: [u8; 64] = sig.try_into().unwrap();

        assert!(
            verify_inbox_record(&verifying_key, &device_id, seq, &tampered_enc, &ct, &sig_array)
                .is_err()
        );
    }

    #[test]
    fn test_verify_with_tampered_ct() {
        let (signing_key, verifying_key) = generate_device_signing_key().unwrap();
        let device_id = [0x42; 16];
        let seq = 123;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];
        let mut tampered_ct = ct.clone();
        tampered_ct[0] ^= 0x01;

        let sig = sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct).unwrap();
        let sig_array: [u8; 64] = sig.try_into().unwrap();

        assert!(
            verify_inbox_record(&verifying_key, &device_id, seq, &enc, &tampered_ct, &sig_array)
                .is_err()
        );
    }

    #[test]
    fn test_signature_is_deterministic() {
        // Ed25519 signatures are deterministic for the same message
        let (signing_key, _) = generate_device_signing_key().unwrap();
        let device_id = [0x42; 16];
        let seq = 123;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];

        let sig1 = sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct).unwrap();
        let sig2 = sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct).unwrap();

        assert_eq!(sig1, sig2);
    }
}
