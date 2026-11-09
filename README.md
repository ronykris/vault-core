# wovault

**Write-Only Vault**: Encrypted backup library with HPKE-sealed write-only ingest support.

## Key Features

- **Write-only ingest**: Background workers can encrypt and upload data without holding any decryption secret
- **Hybrid encryption**: HPKE (RFC 9180) seals item records to an ingest public key
- **Strong cryptography**: XChaCha20-Poly1305, Argon2id, Ed25519, BIP-39 recovery phrases
- **Streaming encryption**: Memory-efficient handling of large files
- **Deterministic merge**: Multiple devices can back up to the same vault without conflicts

## Design

wovault implements a split-key architecture:

1. **Background workers** (untrusted, can run on locked devices):
   - Generate random per-item file keys (FK)
   - Encrypt content with XChaCha20-Poly1305 STREAM
   - Seal item records (containing FK) to an ingest public key using HPKE
   - Sign sealed records with device Ed25519 key
   - Upload ciphertext blobs and sealed records

2. **Unlocked client** (trusted, requires master password or recovery phrase):
   - Unwraps the vault master key (VMK)
   - Decrypts the ingest private key
   - Opens sealed inbox records, verifies signatures
   - Merges item records into the encrypted index
   - Decrypts and views content

**Security property**: A compromised background worker cannot decrypt anything it previously uploaded.

## Use Cases

Best fit:
- Cameras, sensors, and edge devices uploading encrypted data
- Field-capture apps (journalism, legal, medical, inspections)
- Zero-knowledge SaaS file storage
- Encrypted notes and backup apps with untrusted cloud sync

See the crate documentation for the full threat model.

## Status

- **Version**: 0.1.3 (pre-release, API unstable)
- **MSRV**: Rust 1.84+
- **License**: MIT OR Apache-2.0

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
wovault = "0.1"
```

### Basic Examples

**Encrypting a file blob (write-only ingest)**

```rust
use wovault::*;

// Generate a random file key (done by background worker)
let file_key = generate_file_key();
let plaintext = b"Hello, Vault!";
let blob_id = [0x42; 16]; // Random blob ID

// Encrypt to STREAM blob
let ciphertext = encrypt_blob(&file_key, plaintext, BlobKind::File, blob_id)?;

// Later, decrypt with the same key
let decrypted = decrypt_blob(&file_key, &ciphertext)?;
assert_eq!(&decrypted[..], plaintext);
```

**Write-only ingest with HPKE sealing**

```rust
use wovault::*;

// Setup: unlocked client generates ingest keypair
let (ingest_pub, ingest_priv) = generate_ingest_keypair();
let vault_id = [0x11; 16];

// Background worker: seal item record (write-only, no decryption key)
let device_id = [0x22; 16];
let seq = 1;
let item_record = b"CBOR-encoded item record";
let (enc, ct) = seal_item_record(&ingest_pub, item_record, &vault_id, &device_id, seq)?;

// Sign the sealed record
let (signing_key, verifying_key) = generate_device_signing_key()?;
let sig = sign_inbox_record(&signing_key, &device_id, seq, &enc, &ct)?;

// Later: unlocked client opens and verifies
let sig_array: [u8; 64] = sig.try_into().unwrap();
verify_inbox_record(&verifying_key, &device_id, seq, &enc, &ct, &sig_array)?;
let decrypted = open_item_record(&ingest_priv, &enc, &ct, &vault_id, &device_id, seq)?;
```

**Password-based vault unlocking**

```rust
use wovault::*;

// Create vault: generate VMK and wrap it
let vmk = generate_vault_master_key()?;
let vault_id = [0x11; 16];
let password = "correct-horse-battery-staple";
let salt = [0x42; 16]; // Random salt

// Derive password key with Argon2id
let pk = derive_password_key(password, &salt, 65536, 3, 1)?;

// Wrap VMK under password
let wrapped = wrap_vmk_with_password(&vmk, &pk, &vault_id)?;

// Later: unlock vault with password
let pk_unlock = derive_password_key(password, &salt, 65536, 3, 1)?;
let vmk_unlocked = unwrap_vmk_with_password(&wrapped, &pk_unlock, &vault_id)?;

// Derive subkeys
let index_key = derive_index_key(&vmk_unlocked)?;
let cache_key = derive_cache_key(&vmk_unlocked)?;
```

**Recovery phrase generation**

```rust
use wovault::*;

// Generate 24-word BIP-39 recovery phrase
let phrase = generate_recovery_phrase()?;

// Convert phrase to recovery key
let rk = phrase_to_recovery_key(&phrase)?;

// Wrap VMK under recovery key
let vmk = generate_vault_master_key()?;
let vault_id = [0x11; 16];
let wrapped = wrap_vmk_with_recovery(&vmk, &rk, &vault_id)?;

// Later: recover vault with phrase
let rk_recover = phrase_to_recovery_key(&phrase)?;
let vmk_recovered = unwrap_vmk_with_recovery(&wrapped, &rk_recover, &vault_id)?;
```

See the [crate documentation](https://docs.rs/wovault) for more details.

## Security

Built with audited RustCrypto primitives and following modern cryptographic best practices.

## Repository

This is the public core cryptography crate. The reference Android app lives in a separate private repository.

## Contributing

This crate is in early development. Contributions are welcome after M1 when the public API is stabilized.

