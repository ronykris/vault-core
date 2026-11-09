//! Ed25519 signatures for inbox record authentication.
//!
//! Each device signs its sealed inbox records with its Ed25519 key.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Device signing keypair
pub struct DeviceSigningKey {
    pub signing_key: Vec<u8>,
    pub verifying_key: Vec<u8>,
}

/// Generate a new Ed25519 signing keypair for a device
pub fn generate_device_signing_key() -> DeviceSigningKey {
    // Generate 32 random bytes for the secret key
    let mut secret_bytes = [0u8; 32];
    getrandom::getrandom(&mut secret_bytes).expect("getrandom failed");

    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    DeviceSigningKey {
        signing_key: signing_key.to_bytes().to_vec(),
        verifying_key: verifying_key.to_bytes().to_vec(),
    }
}

/// Sign data with Ed25519
///
/// # Design (from DESIGN.md section 6)
/// - Message: b"vault/inbox-sig/v1" || device_id || seq || enc || ct
/// - Returns: 64-byte signature
///
/// # Parameters
/// - `signing_key`: 32-byte Ed25519 private key
/// - `device_id`: 16-byte device identifier
/// - `seq`: Sequence number
/// - `enc`: HPKE encapsulated key
/// - `ct`: HPKE ciphertext
pub fn sign_inbox_record(
    signing_key: &[u8],
    device_id: &[u8; 16],
    seq: u64,
    enc: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, String> {
    // Parse signing key
    if signing_key.len() != 32 {
        return Err(format!(
            "Invalid signing key length: {} (expected 32)",
            signing_key.len()
        ));
    }

    let key_bytes: [u8; 32] = signing_key.try_into().unwrap();
    let sk = SigningKey::from_bytes(&key_bytes);

    // Construct message: b"vault/inbox-sig/v1" || device_id || seq || enc || ct
    let mut message = Vec::with_capacity(18 + 16 + 8 + enc.len() + ct.len());
    message.extend_from_slice(b"vault/inbox-sig/v1");
    message.extend_from_slice(device_id);
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(enc);
    message.extend_from_slice(ct);

    // Sign
    let signature = sk.sign(&message);

    Ok(signature.to_bytes().to_vec())
}

/// Verify an inbox record signature
///
/// # Parameters
/// - `verifying_key`: 32-byte Ed25519 public key
/// - `device_id`: 16-byte device identifier (must match signing)
/// - `seq`: Sequence number (must match signing)
/// - `enc`: HPKE encapsulated key (must match signing)
/// - `ct`: HPKE ciphertext (must match signing)
/// - `signature`: 64-byte Ed25519 signature
pub fn verify_inbox_record(
    verifying_key: &[u8],
    device_id: &[u8; 16],
    seq: u64,
    enc: &[u8],
    ct: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    // Parse verifying key
    if verifying_key.len() != 32 {
        return Err(format!(
            "Invalid verifying key length: {} (expected 32)",
            verifying_key.len()
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(verifying_key);
    let vk = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| format!("Invalid verifying key: {:?}", e))?;

    // Parse signature
    if signature.len() != 64 {
        return Err(format!(
            "Invalid signature length: {} (expected 64)",
            signature.len()
        ));
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_bytes);

    // Reconstruct message (must match signing)
    let mut message = Vec::with_capacity(18 + 16 + 8 + enc.len() + ct.len());
    message.extend_from_slice(b"vault/inbox-sig/v1");
    message.extend_from_slice(device_id);
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(enc);
    message.extend_from_slice(ct);

    // Verify
    vk.verify(&message, &sig)
        .map_err(|_| "Signature verification failed".to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_device_signing_key() {
        let keypair = generate_device_signing_key();

        // Ed25519 keys are 32 bytes
        assert_eq!(keypair.signing_key.len(), 32);
        assert_eq!(keypair.verifying_key.len(), 32);

        // Generate another - should be different
        let keypair2 = generate_device_signing_key();
        assert_ne!(keypair.signing_key, keypair2.signing_key);
        assert_ne!(keypair.verifying_key, keypair2.verifying_key);
    }

    #[test]
    fn test_sign_verify_round_trip() {
        let keypair = generate_device_signing_key();
        let device_id = [0x42; 16];
        let seq = 123u64;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];

        // Sign
        let sig = sign_inbox_record(&keypair.signing_key, &device_id, seq, &enc, &ct).unwrap();

        // Signature should be 64 bytes
        assert_eq!(sig.len(), 64);

        // Verify
        verify_inbox_record(&keypair.verifying_key, &device_id, seq, &enc, &ct, &sig).unwrap();
    }

    #[test]
    fn test_wrong_verifying_key_fails() {
        let keypair = generate_device_signing_key();
        let wrong_keypair = generate_device_signing_key();
        let device_id = [0x42; 16];
        let seq = 123u64;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];

        let sig = sign_inbox_record(&keypair.signing_key, &device_id, seq, &enc, &ct).unwrap();

        // Verify with wrong key should fail
        assert!(verify_inbox_record(
            &wrong_keypair.verifying_key,
            &device_id,
            seq,
            &enc,
            &ct,
            &sig
        )
        .is_err());
    }

    #[test]
    fn test_wrong_device_id_fails() {
        let keypair = generate_device_signing_key();
        let device_id = [0x42; 16];
        let wrong_device_id = [0x99; 16];
        let seq = 123u64;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];

        let sig = sign_inbox_record(&keypair.signing_key, &device_id, seq, &enc, &ct).unwrap();

        // Verify with wrong device_id (wrong message) should fail
        assert!(verify_inbox_record(
            &keypair.verifying_key,
            &wrong_device_id,
            seq,
            &enc,
            &ct,
            &sig
        )
        .is_err());
    }

    #[test]
    fn test_wrong_seq_fails() {
        let keypair = generate_device_signing_key();
        let device_id = [0x42; 16];
        let seq = 123u64;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];

        let sig = sign_inbox_record(&keypair.signing_key, &device_id, seq, &enc, &ct).unwrap();

        // Verify with wrong seq (wrong message) should fail
        assert!(
            verify_inbox_record(&keypair.verifying_key, &device_id, 124, &enc, &ct, &sig).is_err()
        );
    }

    #[test]
    fn test_tampered_enc_fails() {
        let keypair = generate_device_signing_key();
        let device_id = [0x42; 16];
        let seq = 123u64;
        let enc = vec![0xaa; 32];
        let mut tampered_enc = enc.clone();
        tampered_enc[0] ^= 0x01;
        let ct = vec![0xbb; 100];

        let sig = sign_inbox_record(&keypair.signing_key, &device_id, seq, &enc, &ct).unwrap();

        // Verify with tampered enc should fail
        assert!(verify_inbox_record(
            &keypair.verifying_key,
            &device_id,
            seq,
            &tampered_enc,
            &ct,
            &sig
        )
        .is_err());
    }

    #[test]
    fn test_tampered_ct_fails() {
        let keypair = generate_device_signing_key();
        let device_id = [0x42; 16];
        let seq = 123u64;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];
        let mut tampered_ct = ct.clone();
        tampered_ct[0] ^= 0x01;

        let sig = sign_inbox_record(&keypair.signing_key, &device_id, seq, &enc, &ct).unwrap();

        // Verify with tampered ct should fail
        assert!(verify_inbox_record(
            &keypair.verifying_key,
            &device_id,
            seq,
            &enc,
            &tampered_ct,
            &sig
        )
        .is_err());
    }

    #[test]
    fn test_tampered_signature_fails() {
        let keypair = generate_device_signing_key();
        let device_id = [0x42; 16];
        let seq = 123u64;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];

        let mut sig = sign_inbox_record(&keypair.signing_key, &device_id, seq, &enc, &ct).unwrap();

        // Tamper with signature
        sig[0] ^= 0x01;

        // Should fail verification
        assert!(
            verify_inbox_record(&keypair.verifying_key, &device_id, seq, &enc, &ct, &sig).is_err()
        );
    }

    #[test]
    fn test_deterministic_signature() {
        // Ed25519 signatures are deterministic for the same message and key
        let keypair = generate_device_signing_key();
        let device_id = [0x42; 16];
        let seq = 123u64;
        let enc = vec![0xaa; 32];
        let ct = vec![0xbb; 100];

        let sig1 = sign_inbox_record(&keypair.signing_key, &device_id, seq, &enc, &ct).unwrap();
        let sig2 = sign_inbox_record(&keypair.signing_key, &device_id, seq, &enc, &ct).unwrap();

        // Signatures should be identical
        assert_eq!(sig1, sig2);
    }

    // RFC 8032 test vector - Ed25519
    // https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1
    #[test]
    fn test_ed25519_rfc8032_test_vector_1() {
        // Test vector 1 from RFC 8032
        // SECRET KEY (32 bytes):
        let secret_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let secret_key = hex::decode(secret_key_hex).unwrap();

        // PUBLIC KEY (32 bytes):
        let public_key_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let expected_public_key = hex::decode(public_key_hex).unwrap();

        // MESSAGE (empty):
        let message = b"";

        // SIGNATURE (64 bytes):
        let expected_sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        let expected_sig = hex::decode(expected_sig_hex).unwrap();

        // Verify the public key derivation
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&secret_key);
        let sk = SigningKey::from_bytes(&sk_bytes);
        let vk = sk.verifying_key();
        assert_eq!(vk.to_bytes(), expected_public_key.as_slice());

        // Sign and verify
        let signature = sk.sign(message);
        assert_eq!(signature.to_bytes().to_vec(), expected_sig);

        // Verify signature
        vk.verify(message, &signature).unwrap();
    }
}
