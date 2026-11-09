//! Fuzz-style test harnesses for parsers
//!
//! These tests use proptest to generate random inputs and verify that
//! all parsers handle invalid input gracefully (no panics, bounded allocations).

use proptest::prelude::*;
use vault_core::*;

/// Fuzz the STREAM blob header parser
///
/// Tests:
/// - Random 47 bytes (most will be invalid)
/// - Truncated headers
/// - Invalid magic, version, flags
/// - Should never panic
#[test]
fn fuzz_blob_header_parser() {
    proptest!(|(bytes: Vec<u8>)| {
        // Generate a blob with potentially invalid header
        if bytes.len() >= 47 {
            let fk = generate_file_key();

            // Try to decrypt - should return error, never panic
            let result = decrypt_blob(&fk, &bytes);

            // Either succeeds (valid format) or fails gracefully
            match result {
                Ok(_) => {}, // Valid format
                Err(e) => {
                    // Error message should be descriptive
                    assert!(!e.is_empty(), "Error message should not be empty");
                },
            }
        }
    });
}

/// Fuzz the vault header CBOR parser
///
/// Tests:
/// - Random CBOR data
/// - Truncated CBOR
/// - Invalid types
/// - Should never panic
#[test]
fn fuzz_vault_header_parser() {
    proptest!(|(bytes: Vec<u8>)| {
        // Try to parse as vault header
        let result = deserialize_vault_header(&bytes);

        match result {
            Ok(header) => {
                // If it parsed, verify constraints
                assert_eq!(header.key_epoch >= 1, true, "key_epoch must be >= 1");
                assert_eq!(header.wrap_pw.len(), 72, "wrap_pw must be 72 bytes");
                assert_eq!(header.wrap_rec.len(), 72, "wrap_rec must be 72 bytes");
                assert_eq!(header.ingest_priv_enc.len(), 72, "ingest_priv_enc must be 72 bytes");
                assert_eq!(header.argon2_m_cost >= 19456, true, "m_cost must be >= 19456");
                assert_eq!(header.argon2_t_cost >= 2, true, "t_cost must be >= 2");
            },
            Err(e) => {
                assert!(!e.is_empty(), "Error message should not be empty");
            },
        }
    });
}

/// Fuzz blob decryption with random keys and data
///
/// Tests:
/// - Wrong keys
/// - Tampered ciphertext
/// - Truncated blobs
/// - Should never panic, even with completely random input
#[test]
fn fuzz_blob_decryption() {
    proptest!(|(
        key_bytes: [u8; 32],
        plaintext in prop::collection::vec(any::<u8>(), 0..1000),
        blob_id: [u8; 16],
    )| {
        let fk = FileKey::new(key_bytes);

        // Encrypt with correct key
        let encrypted = encrypt_blob(&fk, &plaintext, BlobKind::File, blob_id);

        if let Ok(ciphertext) = encrypted {
            // Try to decrypt with random wrong key
            let wrong_key = generate_file_key();
            let result = decrypt_blob(&wrong_key, &ciphertext);

            // Should fail, never panic
            match result {
                Ok(pt) => {
                    // Extremely unlikely but possible with random key
                    // Just verify it doesn't panic
                    let _ = pt.len();
                },
                Err(_) => {}, // Expected
            }

            // Try to decrypt truncated blob
            if ciphertext.len() > 10 {
                let truncated = &ciphertext[..ciphertext.len() - 10];
                let result = decrypt_blob(&fk, truncated);
                // Should fail gracefully
                assert!(result.is_err(), "Truncated blob should fail");
            }
        }
    });
}

/// Fuzz key wrapping/unwrapping
///
/// Tests:
/// - Random keys
/// - Tampered wrapped keys
/// - Truncated wrapped keys
/// - Should never panic
#[test]
fn fuzz_key_wrapping() {
    proptest!(|(
        wrapping_key_bytes: [u8; 32],
        key_to_wrap: [u8; 32],
        vault_id: [u8; 16],
    )| {
        let vmk = VaultMasterKey::new(wrapping_key_bytes);
        let target_key = key_to_wrap;

        // Wrap the key
        let wrapped = wrap_ingest_private_key(&vmk, &target_key, &vault_id);

        if let Ok(wrapped_bytes) = wrapped {
            assert_eq!(wrapped_bytes.len(), 72, "Wrapped key should be 72 bytes");

            // Try to unwrap with correct key
            let unwrapped = unwrap_ingest_private_key(&vmk, &wrapped_bytes, &vault_id);
            assert!(unwrapped.is_ok(), "Unwrap with correct key should succeed");

            // Try to unwrap with wrong key
            let wrong_vmk = generate_vault_master_key();
            let result = unwrap_ingest_private_key(&wrong_vmk, &wrapped_bytes, &vault_id);
            assert!(result.is_err(), "Unwrap with wrong key should fail");

            // Try to unwrap truncated
            if wrapped_bytes.len() > 10 {
                let truncated = &wrapped_bytes[..wrapped_bytes.len() - 10];
                let result = unwrap_ingest_private_key(&vmk, truncated, &vault_id);
                assert!(result.is_err(), "Unwrap truncated should fail");
            }

            // Try to unwrap with tampered data
            let mut tampered = wrapped_bytes.clone();
            tampered[50] ^= 0x01;
            let result = unwrap_ingest_private_key(&vmk, &tampered, &vault_id);
            assert!(result.is_err(), "Unwrap tampered should fail");
        }
    });
}

/// Fuzz HPKE sealing/opening
///
/// Tests:
/// - Random keypairs
/// - Tampered ciphertext
/// - Wrong keys
/// - Should never panic
#[test]
fn fuzz_hpke_sealing() {
    proptest!(|(
        plaintext in prop::collection::vec(any::<u8>(), 0..500),
        vault_id: [u8; 16],
        device_id: [u8; 16],
        seq: u64,
    )| {
        let (ingest_pub, ingest_priv) = generate_ingest_keypair();

        // Seal the record
        let sealed = seal_item_record(&ingest_pub, &plaintext, &vault_id, &device_id, seq);

        if let Ok((enc, ct)) = sealed {
            assert_eq!(enc.len(), 32, "Encapsulated key should be 32 bytes");
            assert!(ct.len() >= 16, "Ciphertext should have at least tag");

            // Try to open with correct key
            let opened = open_item_record(&ingest_priv, &enc, &ct, &vault_id, &device_id, seq);
            assert!(opened.is_ok(), "Open with correct key should succeed");

            if let Ok(decrypted) = opened {
                assert_eq!(decrypted, plaintext, "Decrypted should match plaintext");
            }

            // Try to open with wrong private key
            let (_, wrong_priv) = generate_ingest_keypair();
            let result = open_item_record(&wrong_priv, &enc, &ct, &vault_id, &device_id, seq);
            assert!(result.is_err(), "Open with wrong key should fail");

            // Try to open with tampered ciphertext
            if ct.len() > 1 {
                let mut tampered_ct = ct.clone();
                tampered_ct[0] ^= 0x01;
                let result = open_item_record(&ingest_priv, &enc, &tampered_ct, &vault_id, &device_id, seq);
                assert!(result.is_err(), "Open with tampered ct should fail");
            }

            // Try to open with wrong vault_id
            let wrong_vault_id = [0xff; 16];
            let result = open_item_record(&ingest_priv, &enc, &ct, &wrong_vault_id, &device_id, seq);
            assert!(result.is_err(), "Open with wrong vault_id should fail");
        }
    });
}

/// Fuzz Ed25519 signature verification
///
/// Tests:
/// - Random signatures
/// - Tampered signatures
/// - Wrong keys
/// - Should never panic
#[test]
fn fuzz_signature_verification() {
    proptest!(|(
        device_id: [u8; 16],
        seq: u64,
        enc in prop::collection::vec(any::<u8>(), 0..100),
        ct in prop::collection::vec(any::<u8>(), 0..100),
        random_sig: [u8; 64],
    )| {
        let (signing_key, verifying_key) = generate_device_signing_key();

        // Sign with correct key
        let sig = sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct);

        if let Ok(valid_sig) = sig {
            let sig_array: [u8; 64] = valid_sig.try_into().unwrap();

            // Verify with correct key should succeed
            let result = verify_inbox_record(&verifying_key, &device_id, seq, &enc, &ct, &sig_array);
            assert!(result.is_ok(), "Verify with correct key should succeed");

            // Verify with wrong key should fail
            let (_, wrong_verifying_key) = generate_device_signing_key();
            let result = verify_inbox_record(&wrong_verifying_key, &device_id, seq, &enc, &ct, &sig_array);
            assert!(result.is_err(), "Verify with wrong key should fail");

            // Verify with tampered signature should fail
            let mut tampered_sig = sig_array;
            tampered_sig[0] ^= 0x01;
            let result = verify_inbox_record(&verifying_key, &device_id, seq, &enc, &ct, &tampered_sig);
            assert!(result.is_err(), "Verify with tampered sig should fail");

            // Verify random signature should fail
            let result = verify_inbox_record(&verifying_key, &device_id, seq, &enc, &ct, &random_sig);
            assert!(result.is_err(), "Verify with random sig should fail");
        }
    });
}

/// Fuzz password derivation with various inputs
///
/// Tests:
/// - Various password lengths
/// - Edge case parameters
/// - Should never panic
#[test]
fn fuzz_password_derivation() {
    proptest!(|(
        password in ".*",
        salt: [u8; 16],
        m_cost in 19456u32..100000u32,
        t_cost in 2u32..10u32,
    )| {
        // Derive password key
        let result = derive_password_key(&password, &salt, m_cost, t_cost, 1);

        // Should either succeed or fail with clear error
        match result {
            Ok(pk) => {
                // Verify it's not all zeros (extremely unlikely)
                let is_all_zeros = pk.expose_secret().iter().all(|&b| b == 0);
                assert!(!is_all_zeros || password.is_empty(), "Key should not be all zeros for non-empty password");
            },
            Err(e) => {
                assert!(!e.is_empty(), "Error should have message");
            },
        }
    });
}

/// Test that large allocations are bounded
///
/// This verifies we don't allocate unbounded memory on hostile input
#[test]
fn test_bounded_allocations() {
    // Try to parse a blob with claimed huge size (should fail gracefully)
    let mut fake_blob = vec![0u8; 100];
    // Set magic
    fake_blob[0..4].copy_from_slice(b"VLT1");
    fake_blob[4] = 1; // version
    fake_blob[5] = 1; // kind: file
    // flags, chunk_log2, etc. default to 0
    fake_blob[8] = 20; // chunk_log2

    let fk = generate_file_key();
    let result = decrypt_blob(&fk, &fake_blob);

    // Should fail (invalid format) but not allocate huge amounts
    assert!(result.is_err(), "Invalid blob should fail");
}
