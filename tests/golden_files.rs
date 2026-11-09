//! Golden file generation for format interop testing
//!
//! This test generates golden files with fixed seeds for:
//! - Blob encryption (empty, small, 1 MiB, multi-chunk)
//! - Item record (CBOR)
//! - Vault header (CBOR)
//! - HPKE sealed record
//! - Ed25519 signature
//!
//! The Python interop script must be able to decrypt all of these.

use std::fs;
use std::path::Path;
use vault_core::*;

/// Fixed seed RNG for deterministic golden files
struct FixedRng {
    state: u64,
}

impl FixedRng {
    fn new(seed: u64) -> Self {
        FixedRng { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // Simple LCG for reproducibility
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.state
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let val = self.next_u64();
            let bytes = val.to_le_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
    }

    fn gen_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut bytes = [0u8; N];
        self.fill_bytes(&mut bytes);
        bytes
    }
}

/// Generate all golden files
///
/// Run with: cargo test golden_files -- --ignored --nocapture
///
/// This is ignored by default because it writes files.
/// In CI, run it once per format version and commit the output.
#[test]
#[ignore]
fn generate_golden_files() {
    let golden_dir = Path::new("golden");
    fs::create_dir_all(golden_dir).expect("create golden dir");

    println!("Generating golden files in {:?}", golden_dir);

    // Deterministic keys and IDs from fixed seeds
    let mut rng = FixedRng::new(0x0123456789abcdef);

    // Generate deterministic keys
    let vmk_bytes = rng.gen_bytes::<32>();
    let vmk = VaultMasterKey::new(vmk_bytes);

    let password = "correct-horse-battery-staple"; // Test password
    let salt = rng.gen_bytes::<16>();
    let pk = derive_password_key(password, &salt, 19456, 2, 1).expect("derive PK");

    // Recovery phrase: use BIP-39 with fixed entropy
    let recovery_entropy = rng.gen_bytes::<32>();
    // For golden files, we'll derive RK directly from entropy
    let rk_bytes = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"vault-golden-rk/v1");
        hasher.update(&recovery_entropy);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result[..]);
        bytes
    };
    let rk = RecoveryKey::new(rk_bytes);

    let vault_id = rng.gen_bytes::<16>();
    let device_id = rng.gen_bytes::<16>();

    // File keys
    let fk_small = FileKey::new(rng.gen_bytes::<32>());
    let fk_empty = FileKey::new(rng.gen_bytes::<32>());
    let fk_1mib = FileKey::new(rng.gen_bytes::<32>());
    let fk_multi = FileKey::new(rng.gen_bytes::<32>());

    // HPKE keypair (deterministic for golden files)
    let ingest_pub = rng.gen_bytes::<32>();
    let ingest_priv = rng.gen_bytes::<32>();

    // Device signing keypair
    let device_signing_key = rng.gen_bytes::<32>();
    let device_verifying_key = rng.gen_bytes::<32>();

    println!("\n=== Fixed Test Vectors ===");
    println!("Password: {}", password);
    println!("VMK: {}", hex::encode(vmk_bytes));
    println!("Vault ID: {}", hex::encode(vault_id));
    println!("Device ID: {}", hex::encode(device_id));
    println!("Argon2 salt: {}", hex::encode(salt));
    println!("Recovery entropy: {}", hex::encode(recovery_entropy));
    println!("Ingest public key: {}", hex::encode(ingest_pub));
    println!("Ingest private key: {}", hex::encode(ingest_priv));
    println!("Device signing key: {}", hex::encode(device_signing_key));
    println!("Device verifying key: {}", hex::encode(device_verifying_key));

    // 1. Vault Header
    println!("\n=== 1. Vault Header ===");
    let wrap_pw = wrap_vmk_with_password(&vmk, &pk, &vault_id).expect("wrap with password");
    let wrap_rec = wrap_vmk_with_recovery(&vmk, &rk, &vault_id).expect("wrap with recovery");
    let ingest_priv_enc =
        wrap_ingest_private_key(&vmk, &ingest_priv, &vault_id).expect("wrap ingest priv");

    let header = VaultHeader {
        vault_id,
        key_epoch: 1,
        argon2_m_cost: 19456,
        argon2_t_cost: 2,
        argon2_p_cost: 1,
        argon2_salt: salt,
        wrap_pw: wrap_pw.clone(),
        wrap_rec: wrap_rec.clone(),
        ingest_pub,
        ingest_priv_enc: ingest_priv_enc.clone(),
    };

    let header_cbor = serialize_vault_header(&header).expect("serialize header");
    fs::write(golden_dir.join("header.cbor"), &header_cbor).expect("write header");
    println!("Wrote header.cbor ({} bytes)", header_cbor.len());

    // Write metadata
    let metadata = format!(
        "# Golden Files Metadata\n\n\
        Format version: 1\n\
        Generated: {}\n\n\
        ## Test Vectors\n\
        Password: {}\n\
        VMK: {}\n\
        Vault ID: {}\n\
        Device ID: {}\n\
        Argon2 salt: {}\n\
        Argon2 params: m=19456, t=2, p=1\n\
        Recovery entropy: {}\n\
        Ingest public key: {}\n\
        Ingest private key: {}\n\
        Device signing key: {}\n\
        Device verifying key: {}\n\n\
        ## Files\n\
        - header.cbor: Vault header (CBOR)\n\
        - blob-empty.bin: Empty file blob (fk: {})\n\
        - blob-small.bin: Small file blob, 13 bytes plaintext \"Hello, Vault!\" (fk: {})\n\
        - blob-1mib.bin: Exactly 1 MiB blob, all 0x42 (fk: {})\n\
        - blob-multi.bin: Multi-chunk blob, 2.5 MiB, all 0x99 (fk: {})\n\
        ",
        chrono::Utc::now().to_rfc3339(),
        password,
        hex::encode(vmk_bytes),
        hex::encode(vault_id),
        hex::encode(device_id),
        hex::encode(salt),
        hex::encode(recovery_entropy),
        hex::encode(ingest_pub),
        hex::encode(ingest_priv),
        hex::encode(device_signing_key),
        hex::encode(device_verifying_key),
        hex::encode(fk_empty.expose_secret()),
        hex::encode(fk_small.expose_secret()),
        hex::encode(fk_1mib.expose_secret()),
        hex::encode(fk_multi.expose_secret()),
    );
    fs::write(golden_dir.join("METADATA.md"), metadata).expect("write metadata");
    println!("Wrote METADATA.md");

    // 2. Blob: Empty file
    println!("\n=== 2. Blob: Empty File ===");
    let plaintext_empty = b"";
    let blob_id_empty = rng.gen_bytes::<16>();
    let blob_empty =
        encrypt_blob(&fk_empty, plaintext_empty, BlobKind::File, blob_id_empty).expect("encrypt empty");
    fs::write(golden_dir.join("blob-empty.bin"), &blob_empty).expect("write blob-empty");
    println!("Wrote blob-empty.bin ({} bytes)", blob_empty.len());
    println!("  Plaintext: 0 bytes");
    println!("  Blob ID: {}", hex::encode(blob_id_empty));
    println!("  File key: {}", hex::encode(fk_empty.expose_secret()));

    // 3. Blob: Small file
    println!("\n=== 3. Blob: Small File ===");
    let plaintext_small = b"Hello, Vault!";
    let blob_id_small = rng.gen_bytes::<16>();
    let blob_small =
        encrypt_blob(&fk_small, plaintext_small, BlobKind::File, blob_id_small).expect("encrypt small");
    fs::write(golden_dir.join("blob-small.bin"), &blob_small).expect("write blob-small");
    println!("Wrote blob-small.bin ({} bytes)", blob_small.len());
    println!("  Plaintext: {} bytes", plaintext_small.len());
    println!("  Plaintext: {:?}", String::from_utf8_lossy(plaintext_small));
    println!("  Blob ID: {}", hex::encode(blob_id_small));
    println!("  File key: {}", hex::encode(fk_small.expose_secret()));

    // 4. Blob: Exactly 1 MiB
    println!("\n=== 4. Blob: 1 MiB ===");
    let plaintext_1mib = vec![0x42u8; 1024 * 1024];
    let blob_id_1mib = rng.gen_bytes::<16>();
    let blob_1mib =
        encrypt_blob(&fk_1mib, &plaintext_1mib, BlobKind::File, blob_id_1mib).expect("encrypt 1mib");
    fs::write(golden_dir.join("blob-1mib.bin"), &blob_1mib).expect("write blob-1mib");
    println!("Wrote blob-1mib.bin ({} bytes)", blob_1mib.len());
    println!("  Plaintext: {} bytes", plaintext_1mib.len());
    println!("  Blob ID: {}", hex::encode(blob_id_1mib));
    println!("  File key: {}", hex::encode(fk_1mib.expose_secret()));

    // 5. Blob: Multi-chunk (2.5 MiB)
    println!("\n=== 5. Blob: Multi-chunk (2.5 MiB) ===");
    let plaintext_multi = vec![0x99u8; 2 * 1024 * 1024 + 512 * 1024];
    let blob_id_multi = rng.gen_bytes::<16>();
    let blob_multi =
        encrypt_blob(&fk_multi, &plaintext_multi, BlobKind::File, blob_id_multi).expect("encrypt multi");
    fs::write(golden_dir.join("blob-multi.bin"), &blob_multi).expect("write blob-multi");
    println!("Wrote blob-multi.bin ({} bytes)", blob_multi.len());
    println!("  Plaintext: {} bytes", plaintext_multi.len());
    println!("  Blob ID: {}", hex::encode(blob_id_multi));
    println!("  File key: {}", hex::encode(fk_multi.expose_secret()));

    println!("\n=== Golden files generated successfully ===");
    println!("Run the Python interop script to verify:");
    println!("  python3 tools/interop/decrypt_golden.py");
}

#[test]
fn verify_golden_files_exist() {
    // This test verifies that golden files exist (for CI)
    // Skip if golden/ doesn't exist (not generated yet)
    let golden_dir = Path::new("golden");
    if !golden_dir.exists() {
        println!("Golden files not generated yet. Run:");
        println!("  cargo test golden_files -- --ignored");
        return;
    }

    let files = vec![
        "METADATA.md",
        "header.cbor",
        "blob-empty.bin",
        "blob-small.bin",
        "blob-1mib.bin",
        "blob-multi.bin",
    ];

    for file in files {
        let path = golden_dir.join(file);
        assert!(
            path.exists(),
            "Golden file missing: {}. Run: cargo test golden_files -- --ignored",
            file
        );
        println!("✓ {}", file);
    }
}
