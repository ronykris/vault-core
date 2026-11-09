//! Blob encryption functions

use crate::crypto::stream;
use crate::types::FileKey;

/// Blob kind (file or thumbnail)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    /// Full file blob
    File = 1,
    /// Thumbnail blob
    Thumbnail = 2,
}

impl From<BlobKind> for stream::BlobKind {
    fn from(kind: BlobKind) -> Self {
        match kind {
            BlobKind::File => stream::BlobKind::File,
            BlobKind::Thumbnail => stream::BlobKind::Thumbnail,
        }
    }
}

/// Encrypt a file or thumbnail to a blob
///
/// Uses XChaCha20-Poly1305 STREAM with 1 MiB chunks.
///
/// # Parameters
/// - `fk`: Random file key (generated per blob with generate_file_key())
/// - `plaintext`: File contents (any size, including empty)
/// - `kind`: BlobKind::File or BlobKind::Thumbnail
/// - `blob_id`: 16-byte random identifier
///
/// # Returns
/// STREAM ciphertext: 47-byte header + chunks (each ≤1 MiB plaintext + 16-byte tag)
///
/// The 47-byte header format:
/// - Magic "VLT1" (4 bytes)
/// - format_version = 1 (1 byte)
/// - kind (1 byte)
/// - flags (2 bytes, must be 0)
/// - chunk_log2 = 20 (1 byte)
/// - reserved (3 bytes, zero)
/// - blob_id (16 bytes)
/// - nonce_prefix (19 bytes, random)
///
/// # Example
/// ```ignore
/// let fk = generate_file_key();
/// let plaintext = b"Hello, world!";
/// let blob_id = [0x42; 16];
/// let ciphertext = encrypt_blob(&fk, plaintext, BlobKind::File, blob_id)?;
/// ```
pub fn encrypt_blob(
    fk: &FileKey,
    plaintext: &[u8],
    kind: BlobKind,
    blob_id: [u8; 16],
) -> Result<Vec<u8>, String> {
    stream::encrypt_blob(fk, plaintext, kind.into(), blob_id)
}

/// Decrypt a blob
///
/// # Parameters
/// - `fk`: File key (must match the key used for encryption)
/// - `ciphertext`: STREAM ciphertext from encrypt_blob()
///
/// # Returns
/// Original plaintext
///
/// # Errors
/// - Wrong key
/// - Tampered ciphertext (fails AEAD verification)
/// - Truncated blob (no final chunk with last-flag)
/// - Invalid header (wrong magic, version, or reserved bytes)
/// - Data after final chunk
///
/// # Example
/// ```ignore
/// let plaintext = decrypt_blob(&fk, &ciphertext)?;
/// ```
pub fn decrypt_blob(fk: &FileKey, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    stream::decrypt_blob(fk, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::keys::generate_file_key;

    #[test]
    fn test_encrypt_decrypt_file() {
        let fk = generate_file_key();
        let plaintext = b"Hello, vault!";
        let blob_id = [0x42; 16];

        let ciphertext = encrypt_blob(&fk, plaintext, BlobKind::File, blob_id).unwrap();

        // Header (47) + plaintext + tag (16)
        assert_eq!(ciphertext.len(), 47 + plaintext.len() + 16);

        let decrypted = decrypt_blob(&fk, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_thumbnail() {
        let fk = generate_file_key();
        let plaintext = vec![0xff; 1024]; // 1 KB thumbnail
        let blob_id = [0x99; 16];

        let ciphertext = encrypt_blob(&fk, &plaintext, BlobKind::Thumbnail, blob_id).unwrap();
        let decrypted = decrypt_blob(&fk, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_file() {
        let fk = generate_file_key();
        let plaintext = b"";
        let blob_id = [0x11; 16];

        let ciphertext = encrypt_blob(&fk, plaintext, BlobKind::File, blob_id).unwrap();

        // Header (47) + one empty final chunk (0 + 16 tag) = 63
        assert_eq!(ciphertext.len(), 47 + 16);

        let decrypted = decrypt_blob(&fk, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_file() {
        let fk = generate_file_key();
        let plaintext = vec![0xab; 2 * 1024 * 1024 + 500]; // 2 MiB + 500 bytes
        let blob_id = [0x33; 16];

        let ciphertext = encrypt_blob(&fk, &plaintext, BlobKind::File, blob_id).unwrap();
        let decrypted = decrypt_blob(&fk, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let fk1 = generate_file_key();
        let fk2 = generate_file_key();
        let plaintext = b"secret";
        let blob_id = [0x42; 16];

        let ciphertext = encrypt_blob(&fk1, plaintext, BlobKind::File, blob_id).unwrap();

        assert!(decrypt_blob(&fk2, &ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let fk = generate_file_key();
        let plaintext = b"data";
        let blob_id = [0x42; 16];

        let mut ciphertext = encrypt_blob(&fk, plaintext, BlobKind::File, blob_id).unwrap();

        // Tamper with ciphertext (after header)
        ciphertext[50] ^= 0x01;

        assert!(decrypt_blob(&fk, &ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_truncated_blob() {
        let fk = generate_file_key();
        let plaintext = vec![0xcc; 1000];
        let blob_id = [0x42; 16];

        let ciphertext = encrypt_blob(&fk, &plaintext, BlobKind::File, blob_id).unwrap();

        // Truncate (remove last 20 bytes)
        let truncated = &ciphertext[..ciphertext.len() - 20];

        assert!(decrypt_blob(&fk, truncated).is_err());
    }

    #[test]
    fn test_blob_kind_conversion() {
        assert_eq!(stream::BlobKind::File, BlobKind::File.into());
        assert_eq!(stream::BlobKind::Thumbnail, BlobKind::Thumbnail.into());
    }
}
