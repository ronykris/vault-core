//! Key wrapping functions

use crate::crypto::wrapping;
use crate::types::{PasswordKey, RecoveryKey, VaultMasterKey};

/// Wrap the vault master key under a password key
///
/// Uses XChaCha20-Poly1305 with random nonce and AAD = "vault/wrap/v1" || vault_id || "vmk-pw"
///
/// # Returns
/// 72 bytes: 24-byte nonce || 32-byte ciphertext || 16-byte tag
///
/// # Example
/// ```ignore
/// let vmk = generate_vault_master_key();
/// let pk = derive_password_key("password", &salt, 65536, 3, 1)?;
/// let vault_id = [0x42; 16];
/// let wrapped = wrap_vmk_with_password(&vmk, &pk, &vault_id)?;
/// assert_eq!(wrapped.len(), 72);
/// ```
pub fn wrap_vmk_with_password(
    vmk: &VaultMasterKey,
    pk: &PasswordKey,
    vault_id: &[u8; 16],
) -> Result<Vec<u8>, String> {
    wrapping::wrap_key(
        pk.expose_secret(),
        vmk.expose_secret(),
        vault_id,
        "vmk-pw",
    )
}

/// Unwrap the vault master key with a password key
///
/// # Parameters
/// - `wrapped`: 72 bytes from wrap_vmk_with_password
/// - `pk`: Password key
/// - `vault_id`: Must match the vault_id used during wrapping
///
/// # Errors
/// - Wrong key
/// - Wrong vault_id
/// - Tampered ciphertext
/// - Invalid wrapped format
pub fn unwrap_vmk_with_password(
    wrapped: &[u8],
    pk: &PasswordKey,
    vault_id: &[u8; 16],
) -> Result<VaultMasterKey, String> {
    let vmk_bytes = wrapping::unwrap_key(pk.expose_secret(), wrapped, vault_id, "vmk-pw")?;
    Ok(VaultMasterKey::new(vmk_bytes))
}

/// Wrap the vault master key under a recovery key
///
/// Uses XChaCha20-Poly1305 with random nonce and AAD = "vault/wrap/v1" || vault_id || "vmk-rec"
///
/// # Returns
/// 72 bytes: 24-byte nonce || 32-byte ciphertext || 16-byte tag
pub fn wrap_vmk_with_recovery(
    vmk: &VaultMasterKey,
    rk: &RecoveryKey,
    vault_id: &[u8; 16],
) -> Result<Vec<u8>, String> {
    wrapping::wrap_key(
        rk.expose_secret(),
        vmk.expose_secret(),
        vault_id,
        "vmk-rec",
    )
}

/// Unwrap the vault master key with a recovery key
///
/// # Parameters
/// - `wrapped`: 72 bytes from wrap_vmk_with_recovery
/// - `rk`: Recovery key
/// - `vault_id`: Must match the vault_id used during wrapping
///
/// # Errors
/// - Wrong key
/// - Wrong vault_id
/// - Tampered ciphertext
pub fn unwrap_vmk_with_recovery(
    wrapped: &[u8],
    rk: &RecoveryKey,
    vault_id: &[u8; 16],
) -> Result<VaultMasterKey, String> {
    let vmk_bytes = wrapping::unwrap_key(rk.expose_secret(), wrapped, vault_id, "vmk-rec")?;
    Ok(VaultMasterKey::new(vmk_bytes))
}

/// Wrap an HPKE private key under VMK
///
/// Used to encrypt the ingest private key in the vault header.
///
/// # Returns
/// 72 bytes: 24-byte nonce || 32-byte ciphertext || 16-byte tag
pub fn wrap_ingest_private_key(
    vmk: &VaultMasterKey,
    ingest_priv: &[u8; 32],
    vault_id: &[u8; 16],
) -> Result<Vec<u8>, String> {
    wrapping::wrap_key(vmk.expose_secret(), ingest_priv, vault_id, "ingest-priv")
}

/// Unwrap an HPKE private key with VMK
///
/// # Errors
/// - Wrong VMK
/// - Wrong vault_id
/// - Tampered ciphertext
pub fn unwrap_ingest_private_key(
    vmk: &VaultMasterKey,
    wrapped: &[u8],
    vault_id: &[u8; 16],
) -> Result<[u8; 32], String> {
    wrapping::unwrap_key(vmk.expose_secret(), wrapped, vault_id, "ingest-priv")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::keys::{derive_password_key, generate_recovery_phrase, generate_vault_master_key, phrase_to_recovery_key};

    #[test]
    fn test_wrap_unwrap_vmk_with_password() {
        let vmk = generate_vault_master_key();
        let salt = [0x42; 16];
        let pk = derive_password_key("test-password", &salt, 19456, 2, 1).unwrap();
        let vault_id = [0x11; 16];

        let wrapped = wrap_vmk_with_password(&vmk, &pk, &vault_id).unwrap();
        assert_eq!(wrapped.len(), 72);

        let unwrapped = unwrap_vmk_with_password(&wrapped, &pk, &vault_id).unwrap();
        assert_eq!(vmk.expose_secret(), unwrapped.expose_secret());
    }

    #[test]
    fn test_unwrap_vmk_with_wrong_password() {
        let vmk = generate_vault_master_key();
        let salt = [0x42; 16];
        let pk = derive_password_key("correct", &salt, 19456, 2, 1).unwrap();
        let wrong_pk = derive_password_key("wrong", &salt, 19456, 2, 1).unwrap();
        let vault_id = [0x11; 16];

        let wrapped = wrap_vmk_with_password(&vmk, &pk, &vault_id).unwrap();

        assert!(unwrap_vmk_with_password(&wrapped, &wrong_pk, &vault_id).is_err());
    }

    #[test]
    fn test_unwrap_vmk_with_wrong_vault_id() {
        let vmk = generate_vault_master_key();
        let salt = [0x42; 16];
        let pk = derive_password_key("test", &salt, 19456, 2, 1).unwrap();
        let vault_id = [0x11; 16];
        let wrong_vault_id = [0x22; 16];

        let wrapped = wrap_vmk_with_password(&vmk, &pk, &vault_id).unwrap();

        assert!(unwrap_vmk_with_password(&wrapped, &pk, &wrong_vault_id).is_err());
    }

    #[test]
    fn test_wrap_unwrap_vmk_with_recovery() {
        let vmk = generate_vault_master_key();
        let phrase = generate_recovery_phrase().unwrap();
        let rk = phrase_to_recovery_key(&phrase).unwrap();
        let vault_id = [0x11; 16];

        let wrapped = wrap_vmk_with_recovery(&vmk, &rk, &vault_id).unwrap();
        assert_eq!(wrapped.len(), 72);

        let unwrapped = unwrap_vmk_with_recovery(&wrapped, &rk, &vault_id).unwrap();
        assert_eq!(vmk.expose_secret(), unwrapped.expose_secret());
    }

    #[test]
    fn test_unwrap_vmk_with_wrong_recovery_key() {
        let vmk = generate_vault_master_key();
        let phrase1 = generate_recovery_phrase().unwrap();
        let phrase2 = generate_recovery_phrase().unwrap();
        let rk1 = phrase_to_recovery_key(&phrase1).unwrap();
        let rk2 = phrase_to_recovery_key(&phrase2).unwrap();
        let vault_id = [0x11; 16];

        let wrapped = wrap_vmk_with_recovery(&vmk, &rk1, &vault_id).unwrap();

        assert!(unwrap_vmk_with_recovery(&wrapped, &rk2, &vault_id).is_err());
    }

    #[test]
    fn test_wrap_unwrap_ingest_private_key() {
        let vmk = generate_vault_master_key();
        let vault_id = [0x11; 16];
        let ingest_priv = [0x55; 32];

        let wrapped = wrap_ingest_private_key(&vmk, &ingest_priv, &vault_id).unwrap();
        assert_eq!(wrapped.len(), 72);

        let unwrapped = unwrap_ingest_private_key(&vmk, &wrapped, &vault_id).unwrap();
        assert_eq!(ingest_priv, unwrapped);
    }

    #[test]
    fn test_unwrap_ingest_with_wrong_vmk() {
        let vmk1 = generate_vault_master_key();
        let vmk2 = generate_vault_master_key();
        let vault_id = [0x11; 16];
        let ingest_priv = [0x55; 32];

        let wrapped = wrap_ingest_private_key(&vmk1, &ingest_priv, &vault_id).unwrap();

        assert!(unwrap_ingest_private_key(&vmk2, &wrapped, &vault_id).is_err());
    }
}
