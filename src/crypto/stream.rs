//! XChaCha20-Poly1305 STREAM encryption for blobs.
//!
//! Implements the STREAM construction with 1 MiB chunks and a 47-byte header.

use crate::types::FileKey;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

/// Blob kind
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    File = 1,
    Thumbnail = 2,
}

impl BlobKind {
    fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(BlobKind::File),
            2 => Ok(BlobKind::Thumbnail),
            _ => Err(format!("Invalid blob kind: {}", value)),
        }
    }
}

/// Blob header (47 bytes)
///
/// # Design (from DESIGN.md section 6)
/// ```text
/// offset  size  field
/// 0       4     magic "VLT1"
/// 4       1     format_version = 1
/// 5       1     kind (1 = file, 2 = thumbnail)
/// 6       2     flags (bit 0 = padded, reserved, must be 0 in v1)
/// 8       1     chunk_log2 = 20 (1 MiB)
/// 9       3     reserved, zero
/// 12      16    blob_id
/// 28      19    nonce_prefix
/// 47      -     chunks
/// ```
#[derive(Debug, Clone)]
pub struct BlobHeader {
    pub format_version: u8,
    pub kind: BlobKind,
    pub flags: u16,
    pub chunk_log2: u8,
    pub blob_id: [u8; 16],
    pub nonce_prefix: [u8; 19],
}

impl BlobHeader {
    /// Create a new blob header
    pub fn new(kind: BlobKind, blob_id: [u8; 16]) -> Result<Self, String> {
        // Generate random nonce prefix
        let mut nonce_prefix = [0u8; 19];
        getrandom::getrandom(&mut nonce_prefix).map_err(|e| format!("RNG failed: {}", e))?;

        Ok(BlobHeader {
            format_version: 1,
            kind,
            flags: 0,
            chunk_log2: 20, // 1 MiB
            blob_id,
            nonce_prefix,
        })
    }

    /// Serialize header to 47 bytes
    pub fn to_bytes(&self) -> [u8; 47] {
        let mut bytes = [0u8; 47];
        bytes[0..4].copy_from_slice(b"VLT1");
        bytes[4] = self.format_version;
        bytes[5] = self.kind as u8;
        bytes[6..8].copy_from_slice(&self.flags.to_be_bytes());
        bytes[8] = self.chunk_log2;
        // bytes[9..12] reserved (already zero)
        bytes[12..28].copy_from_slice(&self.blob_id);
        bytes[28..47].copy_from_slice(&self.nonce_prefix);
        bytes
    }

    /// Parse header from 47 bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 47 {
            return Err(format!(
                "Header too short: {} bytes (expected 47)",
                bytes.len()
            ));
        }

        // Validate magic
        if &bytes[0..4] != b"VLT1" {
            return Err("Invalid magic (expected VLT1)".to_string());
        }

        // Parse fields
        let format_version = bytes[4];
        if format_version != 1 {
            return Err(format!("Unsupported format version: {}", format_version));
        }

        let kind = BlobKind::from_u8(bytes[5])?;
        let flags = u16::from_be_bytes([bytes[6], bytes[7]]);

        // Validate reserved flags
        if flags != 0 {
            return Err(format!("Reserved flags must be zero, got: {}", flags));
        }

        let chunk_log2 = bytes[8];
        if chunk_log2 != 20 {
            return Err(format!(
                "Unsupported chunk_log2: {} (expected 20)",
                chunk_log2
            ));
        }

        // Validate reserved bytes
        if bytes[9..12] != [0, 0, 0] {
            return Err("Reserved bytes must be zero".to_string());
        }

        let mut blob_id = [0u8; 16];
        blob_id.copy_from_slice(&bytes[12..28]);

        let mut nonce_prefix = [0u8; 19];
        nonce_prefix.copy_from_slice(&bytes[28..47]);

        Ok(BlobHeader {
            format_version,
            kind,
            flags,
            chunk_log2,
            blob_id,
            nonce_prefix,
        })
    }
}

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

/// Encrypt plaintext to a blob
///
/// # Design
/// - XChaCha20-Poly1305 STREAM
/// - Nonce: nonce_prefix (19 B) || counter (4 B, BE) || last_flag (1 B)
/// - AAD: 47-byte blob header
/// - Chunks: 1 MiB plaintext → ciphertext + 16 B tag
///
/// Returns: header (47 B) || encrypted chunks
pub fn encrypt_blob(
    fk: &FileKey,
    plaintext: &[u8],
    kind: BlobKind,
    blob_id: [u8; 16],
) -> Result<Vec<u8>, String> {
    let header = BlobHeader::new(kind, blob_id)?;
    let header_bytes = header.to_bytes();

    let cipher = XChaCha20Poly1305::new(fk.expose_secret().into());

    // Output: header + chunks
    let mut output =
        Vec::with_capacity(47 + plaintext.len() + (plaintext.len() / CHUNK_SIZE + 1) * 16);
    output.extend_from_slice(&header_bytes);

    // Encrypt in chunks
    let chunks = plaintext.chunks(CHUNK_SIZE);
    let total_chunks = (plaintext.len() + CHUNK_SIZE - 1) / CHUNK_SIZE.max(1);

    for (i, chunk) in chunks.enumerate() {
        let is_last = i == total_chunks - 1 || (plaintext.is_empty() && i == 0);

        // Construct nonce: prefix (19) || counter (4) || last_flag (1)
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes[0..19].copy_from_slice(&header.nonce_prefix);
        nonce_bytes[19..23].copy_from_slice(&(i as u32).to_be_bytes());
        nonce_bytes[23] = if is_last { 1 } else { 0 };
        let nonce = XNonce::from_slice(&nonce_bytes);

        // AAD is the 47-byte header
        let payload = Payload {
            msg: chunk,
            aad: &header_bytes,
        };

        let ct = cipher
            .encrypt(nonce, payload)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        output.extend_from_slice(&ct);
    }

    // Handle empty file: one empty final chunk
    if plaintext.is_empty() {
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes[0..19].copy_from_slice(&header.nonce_prefix);
        nonce_bytes[19..23].copy_from_slice(&0u32.to_be_bytes());
        nonce_bytes[23] = 1; // last flag
        let nonce = XNonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: &[],
            aad: &header_bytes,
        };

        let ct = cipher
            .encrypt(nonce, payload)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        output.extend_from_slice(&ct);
    }

    Ok(output)
}

/// Decrypt a blob
///
/// Returns: plaintext
pub fn decrypt_blob(fk: &FileKey, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 47 {
        return Err("Blob too short".to_string());
    }

    // Parse header
    let header = BlobHeader::from_bytes(&ciphertext[0..47])?;
    let header_bytes = &ciphertext[0..47];

    let cipher = XChaCha20Poly1305::new(fk.expose_secret().into());

    let mut plaintext = Vec::new();
    let mut chunk_data = &ciphertext[47..];
    let mut counter = 0u32;
    let mut found_last = false;

    while !chunk_data.is_empty() {
        // Each chunk: ciphertext + 16-byte tag
        // Try both possible chunk sizes for the last chunk
        let chunk_size = chunk_data.len().min(CHUNK_SIZE + 16);
        let chunk_ct = &chunk_data[..chunk_size];

        // Try last=0 first
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes[0..19].copy_from_slice(&header.nonce_prefix);
        nonce_bytes[19..23].copy_from_slice(&counter.to_be_bytes());
        nonce_bytes[23] = 0;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: chunk_ct,
            aad: header_bytes,
        };

        let pt = match cipher.decrypt(nonce, payload) {
            Ok(pt) => pt,
            Err(_) => {
                // Try with last=1
                nonce_bytes[23] = 1;
                let nonce = XNonce::from_slice(&nonce_bytes);
                let payload = Payload {
                    msg: chunk_ct,
                    aad: header_bytes,
                };

                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| "Decryption failed".to_string())?
            }
        };

        plaintext.extend_from_slice(&pt);

        // Check if this was the last chunk
        if nonce_bytes[23] == 1 {
            found_last = true;
            chunk_data = &chunk_data[chunk_size..];
            break;
        }

        chunk_data = &chunk_data[chunk_size..];
        counter += 1;
    }

    // Must have found a last chunk
    if !found_last {
        return Err("No final chunk found (truncated blob)".to_string());
    }

    // Must not have data after last chunk
    if !chunk_data.is_empty() {
        return Err("Data after final chunk".to_string());
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_header_round_trip() {
        let blob_id = [0x42; 16];
        let header = BlobHeader::new(BlobKind::File, blob_id).unwrap();

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 47);
        assert_eq!(&bytes[0..4], b"VLT1");
        assert_eq!(bytes[4], 1); // version
        assert_eq!(bytes[5], 1); // kind
        assert_eq!(bytes[8], 20); // chunk_log2

        let parsed = BlobHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.format_version, header.format_version);
        assert_eq!(parsed.kind, header.kind);
        assert_eq!(parsed.blob_id, header.blob_id);
        assert_eq!(parsed.nonce_prefix, header.nonce_prefix);
    }

    #[test]
    fn test_encrypt_decrypt_empty_file() {
        let fk = FileKey::generate();
        let blob_id = [0x11; 16];
        let plaintext = b"";

        let encrypted = encrypt_blob(&fk, plaintext, BlobKind::File, blob_id).unwrap();

        // Header (47) + one empty chunk (0 + 16 tag) = 63 bytes
        assert_eq!(encrypted.len(), 47 + 16);

        let decrypted = decrypt_blob(&fk, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_small_file() {
        let fk = FileKey::generate();
        let blob_id = [0x22; 16];
        let plaintext = b"Hello, Vault!";

        let encrypted = encrypt_blob(&fk, plaintext, BlobKind::File, blob_id).unwrap();

        // Header (47) + one chunk (13 + 16 tag) = 76 bytes
        assert_eq!(encrypted.len(), 47 + 13 + 16);

        let decrypted = decrypt_blob(&fk, &encrypted).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_exactly_one_chunk() {
        let fk = FileKey::generate();
        let blob_id = [0x33; 16];
        let plaintext = vec![0x42u8; CHUNK_SIZE];

        let encrypted = encrypt_blob(&fk, &plaintext, BlobKind::File, blob_id).unwrap();

        // Header + one chunk (1 MiB + 16 tag)
        assert_eq!(encrypted.len(), 47 + CHUNK_SIZE + 16);

        let decrypted = decrypt_blob(&fk, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_one_byte_less_than_chunk() {
        let fk = FileKey::generate();
        let blob_id = [0x44; 16];
        let plaintext = vec![0x99u8; CHUNK_SIZE - 1];

        let encrypted = encrypt_blob(&fk, &plaintext, BlobKind::File, blob_id).unwrap();
        let decrypted = decrypt_blob(&fk, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_one_byte_more_than_chunk() {
        let fk = FileKey::generate();
        let blob_id = [0x55; 16];
        let plaintext = vec![0xaau8; CHUNK_SIZE + 1];

        let encrypted = encrypt_blob(&fk, &plaintext, BlobKind::File, blob_id).unwrap();

        // Header + chunk 1 (1 MiB + 16) + chunk 2 (1 byte + 16)
        assert_eq!(encrypted.len(), 47 + (CHUNK_SIZE + 16) + (1 + 16));

        let decrypted = decrypt_blob(&fk, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_multi_chunk() {
        let fk = FileKey::generate();
        let blob_id = [0x66; 16];
        let plaintext = vec![0xbbu8; 3 * CHUNK_SIZE + 500];

        let encrypted = encrypt_blob(&fk, &plaintext, BlobKind::File, blob_id).unwrap();
        let decrypted = decrypt_blob(&fk, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let fk = FileKey::generate();
        let wrong_fk = FileKey::generate();
        let blob_id = [0x77; 16];
        let plaintext = b"secret data";

        let encrypted = encrypt_blob(&fk, plaintext, BlobKind::File, blob_id).unwrap();
        assert!(decrypt_blob(&wrong_fk, &encrypted).is_err());
    }

    #[test]
    fn test_tampered_header_fails() {
        let fk = FileKey::generate();
        let blob_id = [0x88; 16];
        let plaintext = b"data";

        let mut encrypted = encrypt_blob(&fk, plaintext, BlobKind::File, blob_id).unwrap();

        // Tamper with header (within first 47 bytes)
        encrypted[10] ^= 0x01;

        // Should fail because AAD doesn't match
        assert!(decrypt_blob(&fk, &encrypted).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let fk = FileKey::generate();
        let blob_id = [0x99; 16];
        let plaintext = b"data";

        let mut encrypted = encrypt_blob(&fk, plaintext, BlobKind::File, blob_id).unwrap();

        // Tamper with ciphertext (after header)
        encrypted[50] ^= 0x01;

        assert!(decrypt_blob(&fk, &encrypted).is_err());
    }

    #[test]
    fn test_truncated_blob_fails() {
        let fk = FileKey::generate();
        let blob_id = [0xaa; 16];
        let plaintext = vec![0xcc; 1000];

        let encrypted = encrypt_blob(&fk, &plaintext, BlobKind::File, blob_id).unwrap();

        // Truncate (remove last chunk)
        let truncated = &encrypted[..encrypted.len() - 20];

        // Should fail (no final chunk)
        assert!(decrypt_blob(&fk, truncated).is_err());
    }
}
