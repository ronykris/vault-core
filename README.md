# wovault

**Write-Only Vault**: Encrypted backup library with HPKE-sealed write-only ingest support.

**⚠️ UNAUDITED: This crate is in active development and has not undergone a security audit. Do not use in production.**

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

- **Version**: 0.1.0 (pre-release, API unstable)
- **Audit**: None yet (planned before 1.0)
- **MSRV**: Rust 1.75+
- **License**: MIT OR Apache-2.0

## Usage

(Documentation and examples will be added in milestone M1)

## Security

**Threat model**: See [THREAT_MODEL.md](THREAT_MODEL.md)
**Audit status**: See [SECURITY.md](SECURITY.md)
**Format specification**: See [FORMAT.md](FORMAT.md)

## Repository

This is the public core cryptography crate. The reference Android app lives in a separate private repository.

## Contributing

This crate is in early development. Contributions are welcome after M1 when the public API is stabilized.

## Acknowledgments

Built with audited RustCrypto primitives and following modern cryptographic best practices.
