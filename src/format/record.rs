//! Item record CBOR serialization.
//!
//! An item record represents one version of a file (photo, video, file, or note).
//! It contains plaintext metadata (name, size, timestamps), encrypted blob references,
//! and tracking info (device_id, seq).
//!
//! Schema version 1 from DESIGN.md section 6.

use ciborium::{de::from_reader, ser::into_writer};
use serde::{Deserialize, Serialize};

/// Item kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    /// Photo item (JPEG, PNG, etc.)
    Photo,
    /// Video item (MP4, etc.)
    Video,
    /// Generic file item
    File,
    /// Text note item (Logseq markdown)
    Note,
}

/// Source type for tracking where the item came from
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceType {
    /// Item from Android MediaStore
    Mediastore,
    /// Item from file tree sync
    Tree,
    /// Item received via share intent
    Share,
}

/// Source tracking information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// Type of source (mediastore, tree, or share)
    #[serde(rename = "type")]
    pub source_type: SourceType,
    /// SHA-256 of (source URI + relative path)
    pub key: [u8; 32],
}

/// Blob reference (encrypted file contents)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    /// Blob ID (16 bytes)
    pub id: [u8; 16],
    /// File key (32 bytes) for XChaCha20-Poly1305 STREAM
    pub fk: [u8; 32],
    /// Chunk size as log2 (e.g., 20 = 1 MiB chunks)
    pub chunk_log2: u8,
    /// Ciphertext size in bytes
    pub ct_size: u64,
    /// SHA-256 of complete ciphertext
    pub ct_sha256: [u8; 32],
}

/// Thumbnail reference (optional, encrypted)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThumbRef {
    /// Thumbnail blob ID (16 bytes)
    pub id: [u8; 16],
    /// File key (32 bytes) for thumbnail encryption
    pub fk: [u8; 32],
    /// SHA-256 of thumbnail ciphertext
    pub ct_sha256: [u8; 32],
}

/// Item record (unsealed CBOR map)
///
/// # Design (from DESIGN.md section 6)
/// This structure is serialized to CBOR, then sealed with HPKE before being
/// placed in an inbox batch. All fields are confidential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRecord {
    /// Schema version (must be 1)
    pub v: u8,

    /// Stable identifier across versions of the same source file
    pub item_id: [u8; 16],

    /// Version counter (increments when file changes)
    pub version: u32,

    /// Previous blob ID (null for first version)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_blob_id: Option<[u8; 16]>,

    /// Item kind (photo, video, file, note)
    pub kind: ItemKind,

    /// Source tracking (type + key)
    pub source: Source,

    /// File name (confidential)
    pub name: String,

    /// MIME type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,

    /// File size in bytes (plaintext)
    pub size: u64,

    /// Modification time (Unix timestamp, seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,

    /// Photo/video taken timestamp (Unix timestamp, seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taken_at: Option<i64>,

    /// SHA-256 of plaintext
    pub sha256: [u8; 32],

    /// Blob reference (encrypted file)
    pub blob: BlobRef,

    /// Thumbnail reference (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb: Option<ThumbRef>,

    /// Device that created this record
    pub device_id: [u8; 16],

    /// Monotonic sequence number per device
    pub seq: u64,

    /// Tombstone flag (user-initiated delete)
    #[serde(default)]
    pub tombstone: bool,
}

impl ItemRecord {
    /// Serialize to CBOR bytes
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        // Validate schema version
        if self.v != 1 {
            return Err(format!("Unsupported schema version: {}", self.v));
        }

        // Validate chunk_log2
        if self.blob.chunk_log2 != 20 {
            return Err(format!(
                "Invalid chunk_log2: {} (expected 20)",
                self.blob.chunk_log2
            ));
        }

        let mut bytes = Vec::new();
        into_writer(self, &mut bytes).map_err(|e| format!("CBOR serialization failed: {}", e))?;
        Ok(bytes)
    }

    /// Deserialize from CBOR bytes
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        let record: ItemRecord =
            from_reader(bytes).map_err(|e| format!("CBOR deserialization failed: {}", e))?;

        // Validate schema version
        if record.v != 1 {
            return Err(format!("Unsupported schema version: {}", record.v));
        }

        // Validate chunk_log2
        if record.blob.chunk_log2 != 20 {
            return Err(format!(
                "Invalid chunk_log2: {} (expected 20)",
                record.blob.chunk_log2
            ));
        }

        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> ItemRecord {
        ItemRecord {
            v: 1,
            item_id: [0x11; 16],
            version: 1,
            prev_blob_id: None,
            kind: ItemKind::Photo,
            source: Source {
                source_type: SourceType::Mediastore,
                key: [0x22; 32],
            },
            name: "IMG_1234.jpg".to_string(),
            mime: Some("image/jpeg".to_string()),
            size: 1024 * 1024,
            mtime: Some(1700000000),
            taken_at: Some(1699999000),
            sha256: [0x33; 32],
            blob: BlobRef {
                id: [0x44; 16],
                fk: [0x55; 32],
                chunk_log2: 20,
                ct_size: 1024 * 1024 + 47 + 16,
                ct_sha256: [0x66; 32],
            },
            thumb: Some(ThumbRef {
                id: [0x77; 16],
                fk: [0x88; 32],
                ct_sha256: [0x99; 32],
            }),
            device_id: [0xaa; 16],
            seq: 42,
            tombstone: false,
        }
    }

    #[test]
    fn test_record_round_trip() {
        let record = sample_record();

        let cbor = record.to_cbor().unwrap();
        let decoded = ItemRecord::from_cbor(&cbor).unwrap();

        assert_eq!(decoded, record);
    }

    #[test]
    fn test_record_fields() {
        let record = sample_record();
        let cbor = record.to_cbor().unwrap();
        let decoded = ItemRecord::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.v, 1);
        assert_eq!(decoded.item_id, [0x11; 16]);
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.prev_blob_id, None);
        assert_eq!(decoded.kind, ItemKind::Photo);
        assert_eq!(decoded.source.source_type, SourceType::Mediastore);
        assert_eq!(decoded.source.key, [0x22; 32]);
        assert_eq!(decoded.name, "IMG_1234.jpg");
        assert_eq!(decoded.mime, Some("image/jpeg".to_string()));
        assert_eq!(decoded.size, 1024 * 1024);
        assert_eq!(decoded.mtime, Some(1700000000));
        assert_eq!(decoded.taken_at, Some(1699999000));
        assert_eq!(decoded.sha256, [0x33; 32]);
        assert_eq!(decoded.blob.id, [0x44; 16]);
        assert_eq!(decoded.blob.fk, [0x55; 32]);
        assert_eq!(decoded.blob.chunk_log2, 20);
        assert_eq!(decoded.blob.ct_size, 1024 * 1024 + 47 + 16);
        assert_eq!(decoded.blob.ct_sha256, [0x66; 32]);
        assert!(decoded.thumb.is_some());
        assert_eq!(decoded.device_id, [0xaa; 16]);
        assert_eq!(decoded.seq, 42);
        assert!(!decoded.tombstone);
    }

    #[test]
    fn test_record_with_version_chain() {
        let mut record = sample_record();
        record.version = 3;
        record.prev_blob_id = Some([0xbb; 16]);

        let cbor = record.to_cbor().unwrap();
        let decoded = ItemRecord::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.version, 3);
        assert_eq!(decoded.prev_blob_id, Some([0xbb; 16]));
    }

    #[test]
    fn test_record_without_optional_fields() {
        let mut record = sample_record();
        record.prev_blob_id = None;
        record.mime = None;
        record.mtime = None;
        record.taken_at = None;
        record.thumb = None;

        let cbor = record.to_cbor().unwrap();
        let decoded = ItemRecord::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.prev_blob_id, None);
        assert_eq!(decoded.mime, None);
        assert_eq!(decoded.mtime, None);
        assert_eq!(decoded.taken_at, None);
        assert_eq!(decoded.thumb, None);
    }

    #[test]
    fn test_all_item_kinds() {
        let kinds = vec![
            ItemKind::Photo,
            ItemKind::Video,
            ItemKind::File,
            ItemKind::Note,
        ];

        for kind in kinds {
            let mut record = sample_record();
            record.kind = kind;

            let cbor = record.to_cbor().unwrap();
            let decoded = ItemRecord::from_cbor(&cbor).unwrap();

            assert_eq!(decoded.kind, kind);
        }
    }

    #[test]
    fn test_all_source_types() {
        let types = vec![SourceType::Mediastore, SourceType::Tree, SourceType::Share];

        for source_type in types {
            let mut record = sample_record();
            record.source.source_type = source_type.clone();

            let cbor = record.to_cbor().unwrap();
            let decoded = ItemRecord::from_cbor(&cbor).unwrap();

            assert_eq!(decoded.source.source_type, source_type);
        }
    }

    #[test]
    fn test_tombstone_flag() {
        let mut record = sample_record();
        record.tombstone = true;

        let cbor = record.to_cbor().unwrap();
        let decoded = ItemRecord::from_cbor(&cbor).unwrap();

        assert!(decoded.tombstone);
    }

    #[test]
    fn test_invalid_schema_version_serialize() {
        let mut record = sample_record();
        record.v = 2;

        assert!(record.to_cbor().is_err());
    }

    #[test]
    fn test_invalid_schema_version_deserialize() {
        let mut record = sample_record();
        record.v = 99;

        // Bypass validation during serialization for this test
        let mut bytes = Vec::new();
        into_writer(&record, &mut bytes).unwrap();

        // Should fail during deserialization
        assert!(ItemRecord::from_cbor(&bytes).is_err());
    }

    #[test]
    fn test_invalid_chunk_log2_serialize() {
        let mut record = sample_record();
        record.blob.chunk_log2 = 21;

        assert!(record.to_cbor().is_err());
    }

    #[test]
    fn test_invalid_chunk_log2_deserialize() {
        let mut record = sample_record();
        record.blob.chunk_log2 = 21;

        // Bypass validation during serialization
        let mut bytes = Vec::new();
        into_writer(&record, &mut bytes).unwrap();

        // Should fail during deserialization
        assert!(ItemRecord::from_cbor(&bytes).is_err());
    }

    #[test]
    fn test_unicode_filename() {
        let mut record = sample_record();
        record.name = "照片_2024_🎉.jpg".to_string();

        let cbor = record.to_cbor().unwrap();
        let decoded = ItemRecord::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.name, "照片_2024_🎉.jpg");
    }

    #[test]
    fn test_large_file() {
        let mut record = sample_record();
        record.size = 5 * 1024 * 1024 * 1024; // 5 GiB
        record.blob.ct_size = record.size + 47 + (record.size / (1024 * 1024) + 1) * 16;

        let cbor = record.to_cbor().unwrap();
        let decoded = ItemRecord::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.size, 5 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_empty_file() {
        let mut record = sample_record();
        record.size = 0;
        record.blob.ct_size = 47 + 16; // header + one empty final chunk

        let cbor = record.to_cbor().unwrap();
        let decoded = ItemRecord::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.size, 0);
        assert_eq!(decoded.blob.ct_size, 47 + 16);
    }

    #[test]
    fn test_video_record() {
        let mut record = sample_record();
        record.kind = ItemKind::Video;
        record.name = "VID_2024.mp4".to_string();
        record.mime = Some("video/mp4".to_string());

        let cbor = record.to_cbor().unwrap();
        let decoded = ItemRecord::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.kind, ItemKind::Video);
        assert_eq!(decoded.name, "VID_2024.mp4");
        assert_eq!(decoded.mime, Some("video/mp4".to_string()));
    }

    #[test]
    fn test_note_record() {
        let mut record = sample_record();
        record.kind = ItemKind::Note;
        record.name = "daily-note.md".to_string();
        record.mime = Some("text/markdown".to_string());
        record.taken_at = None; // Notes don't have taken_at
        record.thumb = None; // Notes don't have thumbnails

        let cbor = record.to_cbor().unwrap();
        let decoded = ItemRecord::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.kind, ItemKind::Note);
        assert_eq!(decoded.name, "daily-note.md");
        assert_eq!(decoded.taken_at, None);
        assert_eq!(decoded.thumb, None);
    }
}
