//! # wovault
//!
//! **Write-Only Vault**: Encrypted backup library with HPKE-sealed write-only ingest support.
//!
//! ## Design
//!
//! wovault provides a split-key architecture where background workers can encrypt
//! and seal data without holding any decryption secret:
//!
//! - Workers generate random per-item keys and encrypt content
//! - Item records (containing the per-item keys) are sealed to an ingest public key using HPKE
//! - Only an unlocked client with the private key can decrypt and merge records
//!
//! ## Security
//!
//! Built with audited RustCrypto primitives and following modern cryptographic best practices.
//!
//! ## Examples
//!
//! ### Encrypting a file blob (write-only ingest)
//!
//! ```rust
//! use wovault::*;
//!
//! # fn main() -> Result<(), String> {
//! // Generate a random file key (done by background worker)
//! let file_key = generate_file_key();
//! let plaintext = b"Hello, Vault!";
//! let blob_id = [0x42; 16]; // Random blob ID
//!
//! // Encrypt to STREAM blob
//! let ciphertext = encrypt_blob(&file_key, plaintext, BlobKind::File, blob_id)?;
//!
//! // Later, decrypt with the same key
//! let decrypted = decrypt_blob(&file_key, &ciphertext)?;
//! assert_eq!(&decrypted[..], plaintext);
//! # Ok(())
//! # }
//! ```
//!
//! ### Write-only ingest with HPKE sealing
//!
//! ```rust
//! use wovault::*;
//!
//! # fn main() -> Result<(), String> {
//! // Setup: unlocked client generates ingest keypair
//! let (ingest_pub, ingest_priv) = generate_ingest_keypair();
//! let vault_id = [0x11; 16];
//!
//! // Background worker: seal item record (write-only, no decryption key)
//! let device_id = [0x22; 16];
//! let seq = 1;
//! let item_record = b"CBOR-encoded item record";
//! let (enc, ct) = seal_item_record(&ingest_pub, item_record, &vault_id, &device_id, seq)?;
//!
//! // Sign the sealed record
//! let (signing_key, verifying_key) = generate_device_signing_key();
//! let sig = sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct)?;
//!
//! // Upload {device_id, seq, enc, ct, sig} to inbox
//!
//! // Later: unlocked client opens and verifies
//! let sig_array: [u8; 64] = sig.try_into().unwrap();
//! verify_inbox_record(&verifying_key, &device_id, seq, &enc, &ct, &sig_array)?;
//! let decrypted = open_item_record(&ingest_priv, &enc, &ct, &vault_id, &device_id, seq)?;
//! assert_eq!(&decrypted[..], item_record);
//! # Ok(())
//! # }
//! ```
//!
//! ### Password-based vault unlocking
//!
//! ```rust
//! use wovault::*;
//!
//! # fn main() -> Result<(), String> {
//! // Create vault: generate VMK and wrap it
//! let vmk = generate_vault_master_key();
//! let vault_id = [0x11; 16];
//! let password = "correct-horse-battery-staple";
//! let salt = [0x42; 16]; // Random salt
//!
//! // Derive password key with Argon2id
//! let pk = derive_password_key(password, &salt, 65536, 3, 1)?;
//!
//! // Wrap VMK under password
//! let wrapped = wrap_vmk_with_password(&vmk, &pk, &vault_id)?;
//!
//! // Later: unlock vault with password
//! let pk_unlock = derive_password_key(password, &salt, 65536, 3, 1)?;
//! let vmk_unlocked = unwrap_vmk_with_password(&wrapped, &pk_unlock, &vault_id)?;
//!
//! // Derive subkeys
//! let index_key = derive_index_key(&vmk_unlocked);
//! let cache_key = derive_cache_key(&vmk_unlocked);
//! # Ok(())
//! # }
//! ```
//!
//! ### Recovery phrase generation and usage
//!
//! ```rust
//! use wovault::*;
//!
//! # fn main() -> Result<(), String> {
//! // Generate 24-word BIP-39 recovery phrase
//! let phrase = generate_recovery_phrase()?;
//! assert_eq!(phrase.split_whitespace().count(), 24);
//!
//! // Convert phrase to recovery key
//! let rk = phrase_to_recovery_key(&phrase)?;
//!
//! // Wrap VMK under recovery key
//! let vmk = generate_vault_master_key();
//! let vault_id = [0x11; 16];
//! let wrapped = wrap_vmk_with_recovery(&vmk, &rk, &vault_id)?;
//!
//! // Later: recover vault with phrase
//! let rk_recover = phrase_to_recovery_key(&phrase)?;
//! let vmk_recovered = unwrap_vmk_with_recovery(&wrapped, &rk_recover, &vault_id)?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// Private modules
mod crypto;
mod format;
mod types;

// Public API (M1, M2)
mod api;

// Re-export public API from ADR-002 (M1) and ADR-003 (M2)
pub use api::*;

// Also export types for convenience (these are already exposed via API)
pub use types::{CacheKey, FileKey, IndexKey, PasswordKey, RecoveryKey, VaultMasterKey};

// Export format types for M6 inbox processing
pub use format::record::{BlobRef, ItemKind, ItemRecord, Source, SourceType, ThumbRef};

/// Hello world function for UniFFI integration test
pub fn hello_vault() -> String {
    "Hello from wovault!".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_vault() {
        assert_eq!(hello_vault(), "Hello from wovault!");
    }
}
