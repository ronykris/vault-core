//! Vault session management and lifecycle operations
//!
//! This module provides the VaultSession type (unlocked vault handle holding VMK)
//! and vault lifecycle operations: create, unlock, and password change.

use crate::api::formats::VaultHeader;
use crate::api::wrapping::{unwrap_vmk_with_password, unwrap_vmk_with_recovery, wrap_vmk_with_password, wrap_vmk_with_recovery, wrap_ingest_private_key, unwrap_ingest_private_key};
use crate::crypto::{bip39, kdf};
use crate::types::{CacheKey, IndexKey, VaultMasterKey};

/// An unlocked vault session holding the VMK in memory
///
/// This type represents an unlocked vault. It holds the Vault Master Key (VMK)
/// and provides access to derived keys. The VMK is zeroized when dropped.
///
/// # Security
/// - VMK is held in a Secret<[u8; 32]> wrapper (zeroize-on-drop)
/// - No Clone or Debug that would expose the VMK
/// - Kotlin holds this as an Arc<VaultSession> (opaque handle)
/// - Dropping this handle locks the vault
pub struct VaultSession {
    vmk: VaultMasterKey,
    vault_id: [u8; 16],
}

impl VaultSession {
    /// Create a new session (internal use)
    pub(crate) fn new(vmk: VaultMasterKey, vault_id: [u8; 16]) -> Self {
        Self { vmk, vault_id }
    }

    /// Get the vault ID
    pub fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }

    /// Derive the index encryption key (K_index) from the VMK
    ///
    /// This key encrypts index segments on Drive.
    pub fn derive_index_key(&self) -> Result<IndexKey, String> {
        kdf::derive_index_key(&self.vmk)
    }

    /// Derive the cache encryption key (K_cache) from the VMK
    ///
    /// This key is used for SQLCipher to encrypt the local index cache.
    pub fn derive_cache_key(&self) -> Result<CacheKey, String> {
        let bytes = kdf::derive_cache_key(&self.vmk)?;
        Ok(CacheKey::new(bytes))
    }

    /// Unwrap the ingest private key from the vault header
    ///
    /// Returns the raw X25519 private key (32 bytes) for opening inbox records.
    /// This is used by the unlocked client to merge sealed inbox batches.
    pub fn unwrap_ingest_private_key(&self, header: &VaultHeader) -> Result<[u8; 32], String> {
        let vec = unwrap_ingest_private_key(&self.vmk, &header.ingest_priv_enc, &self.vault_id)?;
        let array: [u8; 32] = vec.try_into().map_err(|_| "Invalid key length")?;
        Ok(array)
    }

    /// Expose the VMK (internal use only for wrapping operations)
    pub(crate) fn vmk(&self) -> &VaultMasterKey {
        &self.vmk
    }
}

impl std::fmt::Debug for VaultSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSession")
            .field("vault_id", &format!("{:02x?}", &self.vault_id[..]))
            .field("vmk", &"[REDACTED]")
            .finish()
    }
}

/// Result of create_vault operation
pub struct CreateVaultResult {
    /// The vault header to be uploaded to Drive
    pub header: VaultHeader,
    /// The unlocked session holding the VMK
    pub session: VaultSession,
    /// The 24-word BIP-39 recovery phrase (show once, securely)
    pub recovery_phrase: String,
}

/// Create a new vault with a master password
///
/// This generates all vault secrets and creates the initial header.
///
/// # Parameters
/// - `password`: Master password (minimum 12 chars, zxcvbn score >= 3 recommended)
/// - `argon2_m_cost`: Argon2id memory cost in KiB (minimum 19456 = 19 MiB)
/// - `argon2_t_cost`: Argon2id time cost (minimum 2)
///
/// # Returns
/// - Vault header (to be uploaded as h_<seq>)
/// - Unlocked session
/// - 24-word recovery phrase (show once with FLAG_SECURE)
///
/// # Example
/// ```ignore
/// let result = create_vault("correct-horse-battery-staple", 65536, 3)?;
/// // Upload result.header to Drive
/// // Show result.recovery_phrase to user with retype check
/// // Use result.session for operations
/// ```
pub fn create_vault(
    password: &str,
    argon2_m_cost: u32,
    argon2_t_cost: u32,
) -> Result<CreateVaultResult, String> {
    // 1. Generate random VMK (32 bytes)
    let mut vmk_bytes = [0u8; 32];
    getrandom::getrandom(&mut vmk_bytes).map_err(|e| format!("getrandom failed: {}", e))?;
    let vmk = VaultMasterKey::new(vmk_bytes);

    // 2. Generate random vault_id (16 bytes)
    let mut vault_id = [0u8; 16];
    getrandom::getrandom(&mut vault_id).map_err(|e| format!("getrandom failed: {}", e))?;

    // 3. Generate 24-word BIP-39 recovery phrase
    let recovery_phrase = bip39::generate_recovery_phrase()?;

    // 4. Derive RK from phrase
    let rk = bip39::phrase_to_recovery_key(&recovery_phrase)?;

    // 5. Generate random salt (16 bytes)
    let mut argon2_salt = [0u8; 16];
    getrandom::getrandom(&mut argon2_salt).map_err(|e| format!("getrandom failed: {}", e))?;

    // 6. Validate Argon2 params
    let argon2_params = kdf::Argon2Params {
        m_cost: argon2_m_cost,
        t_cost: argon2_t_cost,
        p_cost: 1,
    };
    argon2_params.validate()?;

    // 7. Derive PK from password
    let pk = kdf::derive_password_key(password, &argon2_salt, argon2_params)?;

    // 8. Wrap VMK under PK
    let wrap_pw = wrap_vmk_with_password(&vmk, &pk, &vault_id)?;

    // 9. Wrap VMK under RK
    let wrap_rec = wrap_vmk_with_recovery(&vmk, &rk, &vault_id)?;

    // 10. Generate ingest keypair (X25519)
    let (ingest_pub, ingest_priv) = crate::api::ingest::generate_ingest_keypair();

    // 11. Wrap ingest private key under VMK
    let ingest_priv_enc = wrap_ingest_private_key(&vmk, &ingest_priv, &vault_id)?;

    // 12. Create VaultHeader
    let header = VaultHeader {
        vault_id,
        key_epoch: 1,
        argon2_m_cost,
        argon2_t_cost,
        argon2_p_cost: 1,
        argon2_salt,
        wrap_pw,
        wrap_rec,
        ingest_pub,
        ingest_priv_enc,
    };

    // 13. Create session
    let session = VaultSession::new(vmk, vault_id);

    Ok(CreateVaultResult {
        header,
        session,
        recovery_phrase,
    })
}

/// Unlock a vault with a master password
///
/// # Parameters
/// - `header`: The vault header from Drive (h_<seq>)
/// - `password`: Master password
///
/// # Returns
/// An unlocked VaultSession holding the VMK
///
/// # Errors
/// - Wrong password (unwrap fails)
/// - Invalid header
/// - VMK verification fails
///
/// # Example
/// ```ignore
/// let session = unlock_with_password(&header, "correct-horse-battery-staple")?;
/// let k_index = session.derive_index_key();
/// ```
pub fn unlock_with_password(
    header: &VaultHeader,
    password: &str,
) -> Result<VaultSession, String> {
    // 1. Derive PK from password + header params
    let argon2_params = kdf::Argon2Params {
        m_cost: header.argon2_m_cost,
        t_cost: header.argon2_t_cost,
        p_cost: header.argon2_p_cost,
    };
    let pk = kdf::derive_password_key(password, &header.argon2_salt, argon2_params)?;

    // 2. Unwrap VMK with PK
    let vmk = unwrap_vmk_with_password(&header.wrap_pw, &pk, &header.vault_id)?;

    // 3. Verify VMK is correct by unwrapping ingest_priv
    let _ingest_priv = unwrap_ingest_private_key(&vmk, &header.ingest_priv_enc, &header.vault_id)?;

    // 4. Return session
    Ok(VaultSession::new(vmk, header.vault_id))
}

/// Unlock a vault with a recovery phrase
///
/// # Parameters
/// - `header`: The vault header from Drive
/// - `recovery_phrase`: 24-word BIP-39 phrase
///
/// # Returns
/// An unlocked VaultSession holding the VMK
///
/// # Errors
/// - Invalid phrase (wrong word count, invalid words, bad checksum)
/// - Wrong phrase (unwrap fails)
/// - VMK verification fails
///
/// # Example
/// ```ignore
/// let session = unlock_with_recovery(&header, "word1 word2 ... word24")?;
/// ```
pub fn unlock_with_recovery(
    header: &VaultHeader,
    recovery_phrase: &str,
) -> Result<VaultSession, String> {
    // 1. Convert phrase to RK
    let rk = bip39::phrase_to_recovery_key(recovery_phrase)?;

    // 2. Unwrap VMK with RK
    let vmk = unwrap_vmk_with_recovery(&header.wrap_rec, &rk, &header.vault_id)?;

    // 3. Verify VMK is correct
    let _ingest_priv = unwrap_ingest_private_key(&vmk, &header.ingest_priv_enc, &header.vault_id)?;

    // 4. Return session
    Ok(VaultSession::new(vmk, header.vault_id))
}

/// Change the vault master password
///
/// This re-wraps the VMK under a new password key. The recovery phrase stays the same.
///
/// # Parameters
/// - `session`: Current unlocked session
/// - `old_password`: Current password (for verification)
/// - `new_password`: New password
/// - `header`: Current vault header
/// - `new_argon2_m_cost`: Argon2id memory cost for new password (can increase from old)
/// - `new_argon2_t_cost`: Argon2id time cost for new password
///
/// # Returns
/// A new VaultHeader with updated wrap_pw and Argon2 params
///
/// # Errors
/// - old_password doesn't match current header
/// - Invalid new Argon2 params
/// - Wrapping fails
///
/// # Security
/// - The VMK itself does NOT change
/// - wrap_rec (recovery key wrapping) stays the same
/// - Old encrypted items still decrypt with the same VMK
/// - Upload the new header as h_<seq+1>, then delete old header only after verifying new one
///
/// # Example
/// ```ignore
/// let new_header = change_password(
///     &session,
///     "old-password",
///     "new-stronger-password",
///     &current_header,
///     131072,  // 128 MiB
///     4,
/// )?;
/// // Upload new_header, verify, then delete old header
/// ```
pub fn change_password(
    session: &VaultSession,
    old_password: &str,
    new_password: &str,
    header: &VaultHeader,
    new_argon2_m_cost: u32,
    new_argon2_t_cost: u32,
) -> Result<VaultHeader, String> {
    // 1. Verify old_password unwraps current header
    let argon2_params = kdf::Argon2Params {
        m_cost: header.argon2_m_cost,
        t_cost: header.argon2_t_cost,
        p_cost: header.argon2_p_cost,
    };
    let old_pk = kdf::derive_password_key(old_password, &header.argon2_salt, argon2_params)?;
    let vmk_check = unwrap_vmk_with_password(&header.wrap_pw, &old_pk, &header.vault_id)?;

    // 2. Constant-time compare with session VMK
    use subtle::ConstantTimeEq;
    if vmk_check.expose_secret().ct_eq(session.vmk.expose_secret()).into() {
        // OK
    } else {
        return Err("Old password does not match current session".to_string());
    }

    // 3. Validate new Argon2 params
    let new_argon2_params = kdf::Argon2Params {
        m_cost: new_argon2_m_cost,
        t_cost: new_argon2_t_cost,
        p_cost: 1,
    };
    new_argon2_params.validate()?;

    // 4. Generate new salt
    let mut new_argon2_salt = [0u8; 16];
    getrandom::getrandom(&mut new_argon2_salt).map_err(|e| format!("getrandom failed: {}", e))?;

    // 5. Derive new PK
    let new_pk = kdf::derive_password_key(new_password, &new_argon2_salt, new_argon2_params)?;

    // 6. Re-wrap VMK under new PK
    let new_wrap_pw = wrap_vmk_with_password(&session.vmk, &new_pk, &session.vault_id)?;

    // 7. Create new header (keep same vault_id, key_epoch, wrap_rec, ingest keys)
    let new_header = VaultHeader {
        vault_id: header.vault_id,
        key_epoch: header.key_epoch,
        argon2_m_cost: new_argon2_m_cost,
        argon2_t_cost: new_argon2_t_cost,
        argon2_p_cost: 1,
        argon2_salt: new_argon2_salt,
        wrap_pw: new_wrap_pw,
        wrap_rec: header.wrap_rec.clone(), // SAME recovery phrase
        ingest_pub: header.ingest_pub,
        ingest_priv_enc: header.ingest_priv_enc.clone(),
    };

    Ok(new_header)
}

/// Device enrollment record
///
/// Tracks which devices are enrolled to write to the vault inbox.
/// Enrollment records are written to index segments (M6 scope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrollment {
    /// Unique device ID (16 bytes random)
    pub device_id: [u8; 16],
    /// Ed25519 verifying key for inbox signature verification
    pub verifying_key: [u8; 32],
    /// Enrollment timestamp (Unix seconds)
    pub enrolled_at: i64,
}

/// Create a device enrollment record
///
/// This records a device's Ed25519 verifying key for inbox authentication.
/// The enrollment will be written to an index segment (M6 implementation).
///
/// # Parameters
/// - `device_id`: Random 16-byte device identifier
/// - `verifying_key`: Ed25519 public key (32 bytes)
///
/// # Returns
/// A DeviceEnrollment ready to be serialized to CBOR and added to an index segment
pub fn create_device_enrollment(
    device_id: [u8; 16],
    verifying_key: [u8; 32],
) -> DeviceEnrollment {
    use std::time::{SystemTime, UNIX_EPOCH};
    let enrolled_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before UNIX epoch")
        .as_secs() as i64;

    DeviceEnrollment {
        device_id,
        verifying_key,
        enrolled_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_vault() {
        let result = create_vault("test-password-12345", 19456, 2).unwrap();

        // Verify header fields
        assert_eq!(result.header.key_epoch, 1);
        assert_eq!(result.header.argon2_m_cost, 19456);
        assert_eq!(result.header.argon2_t_cost, 2);
        assert_eq!(result.header.argon2_p_cost, 1);
        assert_eq!(result.header.wrap_pw.len(), 72);
        assert_eq!(result.header.wrap_rec.len(), 72);
        assert_eq!(result.header.ingest_priv_enc.len(), 72);

        // Verify recovery phrase
        assert_eq!(result.recovery_phrase.split_whitespace().count(), 24);

        // Verify session
        assert_eq!(result.session.vault_id(), result.header.vault_id);
    }

    #[test]
    fn test_unlock_with_password_success() {
        let result = create_vault("my-password", 19456, 2).unwrap();
        let header = result.header;

        // Unlock with correct password
        let session = unlock_with_password(&header, "my-password").unwrap();
        assert_eq!(session.vault_id(), header.vault_id);
    }

    #[test]
    fn test_unlock_with_password_wrong() {
        let result = create_vault("my-password", 19456, 2).unwrap();
        let header = result.header;

        // Wrong password should fail
        assert!(unlock_with_password(&header, "wrong-password").is_err());
    }

    #[test]
    fn test_unlock_with_recovery() {
        let result = create_vault("my-password", 19456, 2).unwrap();
        let header = result.header;
        let recovery_phrase = result.recovery_phrase;

        // Unlock with recovery phrase
        let session = unlock_with_recovery(&header, &recovery_phrase).unwrap();
        assert_eq!(session.vault_id(), header.vault_id);
    }

    #[test]
    fn test_unlock_with_wrong_recovery() {
        let result = create_vault("my-password", 19456, 2).unwrap();
        let header = result.header;

        // Generate a different phrase
        let wrong_phrase = bip39::generate_recovery_phrase().unwrap();

        // Should fail
        assert!(unlock_with_recovery(&header, &wrong_phrase).is_err());
    }

    #[test]
    fn test_change_password() {
        let result = create_vault("old-password", 19456, 2).unwrap();
        let old_header = result.header;
        let session = result.session;

        // Change password
        let new_header = change_password(
            &session,
            "old-password",
            "new-password",
            &old_header,
            32768,
            3,
        ).unwrap();

        // New header has updated Argon2 params
        assert_eq!(new_header.argon2_m_cost, 32768);
        assert_eq!(new_header.argon2_t_cost, 3);

        // wrap_rec stays the same (recovery phrase unchanged)
        assert_eq!(new_header.wrap_rec, old_header.wrap_rec);

        // vault_id stays the same
        assert_eq!(new_header.vault_id, old_header.vault_id);

        // Old password no longer works on new header
        assert!(unlock_with_password(&new_header, "old-password").is_err());

        // New password works on new header
        let new_session = unlock_with_password(&new_header, "new-password").unwrap();
        assert_eq!(new_session.vault_id(), new_header.vault_id);

        // Recovery phrase still works with new header
        let session_from_recovery = unlock_with_recovery(&new_header, &result.recovery_phrase).unwrap();
        assert_eq!(session_from_recovery.vault_id(), new_header.vault_id);
    }

    #[test]
    fn test_change_password_old_items_decrypt() {
        use crate::api::encryption::{encrypt_blob, decrypt_blob, BlobKind};
        use crate::api::keys::generate_file_key;

        // Create vault and encrypt a blob
        let result = create_vault("old-password", 19456, 2).unwrap();
        let old_header = result.header.clone();
        let session = result.session;

        let fk = generate_file_key();
        let plaintext = b"Secret data before password change";
        let blob_id = [0x42; 16];
        let ciphertext = encrypt_blob(&fk, plaintext, BlobKind::File, blob_id).unwrap();

        // Change password
        let new_header = change_password(
            &session,
            "old-password",
            "new-password",
            &old_header,
            19456,
            2,
        ).unwrap();

        // Decrypt blob with same FK (VMK unchanged, FK unchanged)
        let decrypted = decrypt_blob(&fk, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);

        // Unlock with new password and derive same index key
        let new_session = unlock_with_password(&new_header, "new-password").unwrap();
        let k_index_new = new_session.derive_index_key().unwrap();

        // Unlock with old password on old header and derive index key
        let old_session = unlock_with_password(&old_header, "old-password").unwrap();
        let k_index_old = old_session.derive_index_key().unwrap();

        // Index keys should be THE SAME (VMK didn't change)
        assert_eq!(k_index_new.expose_secret(), k_index_old.expose_secret());
    }

    #[test]
    fn test_derive_subkeys() {
        let result = create_vault("test-password", 19456, 2).unwrap();
        let session = result.session;

        let k_index = session.derive_index_key().unwrap();
        let k_cache = session.derive_cache_key().unwrap();

        // Should be different
        assert_ne!(k_index.expose_secret(), k_cache.expose_secret());

        // Should be deterministic
        let k_index2 = session.derive_index_key().unwrap();
        assert_eq!(k_index.expose_secret(), k_index2.expose_secret());
    }

    #[test]
    fn test_create_device_enrollment() {
        let device_id = [0x11; 16];
        let verifying_key = [0x22; 32];

        let enrollment = create_device_enrollment(device_id, verifying_key);

        assert_eq!(enrollment.device_id, device_id);
        assert_eq!(enrollment.verifying_key, verifying_key);
        assert!(enrollment.enrolled_at > 0);
    }

    #[test]
    fn test_vault_session_debug() {
        let result = create_vault("test-password", 19456, 2).unwrap();
        let session = result.session;

        let debug_output = format!("{:?}", session);
        assert!(debug_output.contains("REDACTED"));
        assert!(debug_output.contains("vault_id"));
    }
}
