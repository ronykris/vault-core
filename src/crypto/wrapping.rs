//! Key wrapping using XChaCha20-Poly1305.
//!
//! Implements wrapping/unwrapping of the VMK under PK or RK with AAD.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

/// Wrap a key using XChaCha20-Poly1305
///
/// # Design
/// - Cipher: XChaCha20-Poly1305
/// - Nonce: 24 bytes, random
/// - AAD: `vault/wrap/v1 || vault_id || key_label`
/// - Output: nonce (24 B) || ciphertext || tag (16 B)
///
/// # Parameters
/// - `wrapping_key`: The key to wrap with (PK or RK), 32 bytes
/// - `key_to_wrap`: The key being wrapped (typically VMK), 32 bytes
/// - `vault_id`: 16-byte vault identifier
/// - `key_label`: Label like "password", "recovery", "ingest_priv"
pub fn wrap_key(
    wrapping_key: &[u8; 32],
    key_to_wrap: &[u8; 32],
    vault_id: &[u8; 16],
    key_label: &str,
) -> Result<Vec<u8>, String> {
    // Generate random 24-byte nonce
    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("RNG failed: {}", e))?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Construct AAD: b"vault/wrap/v1" || vault_id || key_label
    let mut aad = Vec::with_capacity(13 + 16 + key_label.len());
    aad.extend_from_slice(b"vault/wrap/v1");
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(key_label.as_bytes());

    // Create cipher
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());

    // Encrypt with AAD
    let payload = Payload {
        msg: key_to_wrap,
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Output: nonce || ciphertext
    let mut output = Vec::with_capacity(24 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Unwrap a key using XChaCha20-Poly1305
///
/// # Design
/// - Input: nonce (24 B) || ciphertext || tag (16 B)
/// - Returns the unwrapped 32-byte key
///
/// # Parameters
/// - `wrapping_key`: The key used to wrap (PK or RK), 32 bytes
/// - `wrapped`: The wrapped key bytes (nonce || ct || tag)
/// - `vault_id`: 16-byte vault identifier (must match wrapping)
/// - `key_label`: Label (must match wrapping)
pub fn unwrap_key(
    wrapping_key: &[u8; 32],
    wrapped: &[u8],
    vault_id: &[u8; 16],
    key_label: &str,
) -> Result<[u8; 32], String> {
    // Wrapped format: 24-byte nonce + ciphertext + 16-byte tag
    // Minimum size: 24 + 32 + 16 = 72 bytes
    if wrapped.len() < 72 {
        return Err(format!(
            "Wrapped key too short: {} bytes (expected at least 72)",
            wrapped.len()
        ));
    }

    // Extract nonce (first 24 bytes)
    let nonce = XNonce::from_slice(&wrapped[0..24]);

    // Remaining bytes are ciphertext + tag
    let ciphertext = &wrapped[24..];

    // Construct AAD (must match wrapping)
    let mut aad = Vec::with_capacity(13 + 16 + key_label.len());
    aad.extend_from_slice(b"vault/wrap/v1");
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(key_label.as_bytes());

    // Create cipher
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());

    // Decrypt with AAD
    let payload = Payload {
        msg: ciphertext,
        aad: &aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| "Decryption failed (wrong key or tampered data)".to_string())?;

    // Should be exactly 32 bytes
    if plaintext.len() != 32 {
        return Err(format!(
            "Unwrapped key wrong size: {} bytes (expected 32)",
            plaintext.len()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap_round_trip() {
        let wrapping_key = [0x42; 32];
        let key_to_wrap = [0x99; 32];
        let vault_id = [0x11; 16];
        let label = "password";

        // Wrap
        let wrapped = wrap_key(&wrapping_key, &key_to_wrap, &vault_id, label).unwrap();

        // Should be nonce (24) + ct (32) + tag (16) = 72 bytes
        assert_eq!(wrapped.len(), 72);

        // Unwrap
        let unwrapped = unwrap_key(&wrapping_key, &wrapped, &vault_id, label).unwrap();

        // Should match original
        assert_eq!(unwrapped, key_to_wrap);
    }

    #[test]
    fn test_wrong_wrapping_key_fails() {
        let wrapping_key = [0x42; 32];
        let wrong_key = [0x43; 32];
        let key_to_wrap = [0x99; 32];
        let vault_id = [0x11; 16];
        let label = "password";

        let wrapped = wrap_key(&wrapping_key, &key_to_wrap, &vault_id, label).unwrap();

        // Unwrap with wrong key should fail
        assert!(unwrap_key(&wrong_key, &wrapped, &vault_id, label).is_err());
    }

    #[test]
    fn test_wrong_vault_id_fails() {
        let wrapping_key = [0x42; 32];
        let key_to_wrap = [0x99; 32];
        let vault_id = [0x11; 16];
        let wrong_vault_id = [0x22; 16];
        let label = "password";

        let wrapped = wrap_key(&wrapping_key, &key_to_wrap, &vault_id, label).unwrap();

        // Unwrap with wrong vault_id (wrong AAD) should fail
        assert!(unwrap_key(&wrapping_key, &wrapped, &wrong_vault_id, label).is_err());
    }

    #[test]
    fn test_wrong_label_fails() {
        let wrapping_key = [0x42; 32];
        let key_to_wrap = [0x99; 32];
        let vault_id = [0x11; 16];
        let label = "password";
        let wrong_label = "recovery";

        let wrapped = wrap_key(&wrapping_key, &key_to_wrap, &vault_id, label).unwrap();

        // Unwrap with wrong label (wrong AAD) should fail
        assert!(unwrap_key(&wrapping_key, &wrapped, &vault_id, wrong_label).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let wrapping_key = [0x42; 32];
        let key_to_wrap = [0x99; 32];
        let vault_id = [0x11; 16];
        let label = "password";

        let mut wrapped = wrap_key(&wrapping_key, &key_to_wrap, &vault_id, label).unwrap();

        // Tamper with a ciphertext byte
        wrapped[30] ^= 0x01;

        // Should fail authentication
        assert!(unwrap_key(&wrapping_key, &wrapped, &vault_id, label).is_err());
    }

    #[test]
    fn test_tampered_tag_fails() {
        let wrapping_key = [0x42; 32];
        let key_to_wrap = [0x99; 32];
        let vault_id = [0x11; 16];
        let label = "password";

        let mut wrapped = wrap_key(&wrapping_key, &key_to_wrap, &vault_id, label).unwrap();

        // Tamper with the tag (last 16 bytes)
        let last_idx = wrapped.len() - 1;
        wrapped[last_idx] ^= 0x01;

        // Should fail authentication
        assert!(unwrap_key(&wrapping_key, &wrapped, &vault_id, label).is_err());
    }

    #[test]
    fn test_truncated_wrapped_key_fails() {
        let wrapping_key = [0x42; 32];
        let key_to_wrap = [0x99; 32];
        let vault_id = [0x11; 16];
        let label = "password";

        let wrapped = wrap_key(&wrapping_key, &key_to_wrap, &vault_id, label).unwrap();

        // Truncate
        let truncated = &wrapped[0..50];

        // Should fail
        assert!(unwrap_key(&wrapping_key, truncated, &vault_id, label).is_err());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let wrapping_key = [0x42; 32];
        let key_to_wrap = [0x99; 32];
        let vault_id = [0x11; 16];
        let label = "password";

        // Wrap twice
        let wrapped1 = wrap_key(&wrapping_key, &key_to_wrap, &vault_id, label).unwrap();
        let wrapped2 = wrap_key(&wrapping_key, &key_to_wrap, &vault_id, label).unwrap();

        // Nonces should be different (first 24 bytes)
        assert_ne!(&wrapped1[0..24], &wrapped2[0..24]);

        // Both should unwrap correctly
        let unwrapped1 = unwrap_key(&wrapping_key, &wrapped1, &vault_id, label).unwrap();
        let unwrapped2 = unwrap_key(&wrapping_key, &wrapped2, &vault_id, label).unwrap();
        assert_eq!(unwrapped1, key_to_wrap);
        assert_eq!(unwrapped2, key_to_wrap);
    }
}
