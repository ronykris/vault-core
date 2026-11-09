# Interop Testing

This directory contains Python scripts for format interoperability testing.

## decrypt_golden.py

Decrypts golden files using an independent Python implementation to verify:
- Format specification is complete and correct
- Rust implementation matches the spec
- Another implementation can decrypt Rust-encrypted data
- No Rust-specific quirks or undocumented behaviors

### Dependencies

```bash
pip install pycryptodome cbor2
```

### Usage

```bash
# Generate golden files first
cd /home/roger/dev/code/vault/vault-core
cargo test golden_files -- --ignored

# Run Python interop test
python3 tools/interop/decrypt_golden.py
```

### What It Tests

1. **Vault Header (CBOR)**
   - CBOR parsing
   - Schema version validation
   - Field extraction

2. **STREAM Blob Encryption**
   - 47-byte header parsing
   - Magic, version, flags validation
   - XChaCha20-Poly1305 decryption
   - Nonce construction (prefix || counter || last_flag)
   - AAD validation (header as AAD)
   - Last-chunk detection
   - Multi-chunk handling

3. **Test Cases**
   - Empty file (0 bytes)
   - Small file (13 bytes: "Hello, Vault!")
   - Exactly 1 MiB (boundary test)
   - Multi-chunk (2.5 MiB, 3 chunks)

### Expected Output

```
============================================================
Vault Golden File Decryption Test
============================================================
...
✓ ALL TESTS PASSED
============================================================
Python successfully decrypted all golden files.
Format interoperability verified!
```

### Adding to CI

```yaml
# .github/workflows/interop.yml
name: Interop Tests
on: [push, pull_request]
jobs:
  interop:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: nightly-2024-12-01
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install Python dependencies
        run: pip install pycryptodome cbor2
      - name: Generate golden files
        run: cargo test golden_files -- --ignored
      - name: Run Python interop tests
        run: python3 tools/interop/decrypt_golden.py
```

## Format Changes

When changing the wire format:
1. Bump format version in DESIGN.md
2. Update `FORMAT.md`
3. Regenerate golden files: `cargo test golden_files -- --ignored`
4. Update this Python script to handle the new version
5. Commit golden files and script together
6. Document the change in an ADR

This forces you to think through the format change from an implementer's perspective and ensures backward compatibility is handled correctly.
