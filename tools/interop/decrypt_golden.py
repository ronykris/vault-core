#!/usr/bin/env python3
"""
Decrypt golden files to verify format interoperability.

This script provides an independent implementation of vault-core's crypto
and format handling using Python libraries. It must decrypt all golden files
correctly, proving that the format specification is complete and correct.

Usage:
    python3 tools/interop/decrypt_golden.py

Dependencies:
    pip install pycryptodome cbor2

Libraries used:
- pycryptodome: XChaCha20-Poly1305, Argon2
- cbor2: CBOR decoding
- hashlib: SHA-256 (stdlib)
"""

import os
import sys
import struct
from pathlib import Path

try:
    from Crypto.Cipher import ChaCha20_Poly1305
    from Crypto.Protocol.KDF import argon2
    import cbor2
except ImportError as e:
    print(f"Error: Missing dependency: {e}")
    print("Install with: pip install pycryptodome cbor2")
    sys.exit(1)


class VaultDecryptor:
    """Independent implementation of vault decryption"""

    @staticmethod
    def decrypt_xchacha20poly1305(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """
        Decrypt with XChaCha20-Poly1305

        Args:
            key: 32-byte key
            nonce: 24-byte nonce
            ciphertext: Ciphertext + 16-byte tag
            aad: Additional authenticated data

        Returns:
            Plaintext
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        if len(nonce) != 24:
            raise ValueError(f"Nonce must be 24 bytes, got {len(nonce)}")
        if len(ciphertext) < 16:
            raise ValueError(f"Ciphertext too short: {len(ciphertext)}")

        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(aad)
        plaintext = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
        return plaintext

    @staticmethod
    def decrypt_blob(file_key: bytes, blob_data: bytes) -> bytes:
        """
        Decrypt a STREAM blob

        Format (from DESIGN.md section 6):
        - Header (47 bytes):
          - Magic "VLT1" (4)
          - format_version = 1 (1)
          - kind (1 = file, 2 = thumbnail) (1)
          - flags (must be 0) (2)
          - chunk_log2 = 20 (1)
          - reserved (3, must be 0)
          - blob_id (16)
          - nonce_prefix (19)
        - Chunks: each 1 MiB plaintext + 16-byte tag
        - Nonce: nonce_prefix (19) || counter (4, BE) || last_flag (1)
        - AAD: 47-byte header
        """
        if len(blob_data) < 47:
            raise ValueError(f"Blob too short: {len(blob_data)}")

        # Parse header
        header = blob_data[:47]
        magic = header[0:4]
        format_version = header[4]
        kind = header[5]
        flags = struct.unpack('>H', header[6:8])[0]
        chunk_log2 = header[8]
        reserved = header[9:12]
        blob_id = header[12:28]
        nonce_prefix = header[28:47]

        # Validate header
        if magic != b'VLT1':
            raise ValueError(f"Invalid magic: {magic}")
        if format_version != 1:
            raise ValueError(f"Unsupported version: {format_version}")
        if kind not in (1, 2):
            raise ValueError(f"Invalid kind: {kind}")
        if flags != 0:
            raise ValueError(f"Reserved flags must be 0, got: {flags}")
        if chunk_log2 != 20:
            raise ValueError(f"Unsupported chunk_log2: {chunk_log2}")
        if reserved != b'\x00\x00\x00':
            raise ValueError("Reserved bytes must be zero")

        print(f"  Header: magic={magic}, version={format_version}, kind={kind}, blob_id={blob_id.hex()}")
        print(f"  Nonce prefix: {nonce_prefix.hex()}")

        # Decrypt chunks
        CHUNK_SIZE = 1024 * 1024  # 1 MiB
        plaintext = bytearray()
        chunk_data = blob_data[47:]
        counter = 0
        found_last = False

        while chunk_data:
            # Try both possible chunk sizes
            chunk_size = min(len(chunk_data), CHUNK_SIZE + 16)
            chunk_ct = chunk_data[:chunk_size]

            # Try last=0 first
            nonce = nonce_prefix + struct.pack('>I', counter) + b'\x00'
            try:
                pt = VaultDecryptor.decrypt_xchacha20poly1305(file_key, nonce, chunk_ct, header)
                is_last = False
            except Exception:
                # Try with last=1
                nonce = nonce_prefix + struct.pack('>I', counter) + b'\x01'
                try:
                    pt = VaultDecryptor.decrypt_xchacha20poly1305(file_key, nonce, chunk_ct, header)
                    is_last = True
                    found_last = True
                except Exception as e:
                    raise ValueError(f"Decryption failed at chunk {counter}: {e}")

            plaintext.extend(pt)
            print(f"  Chunk {counter}: {len(pt)} bytes (last={is_last})")

            if is_last:
                chunk_data = chunk_data[chunk_size:]
                break

            chunk_data = chunk_data[chunk_size:]
            counter += 1

        if not found_last:
            raise ValueError("No final chunk found (truncated blob)")

        if chunk_data:
            raise ValueError(f"Data after final chunk: {len(chunk_data)} bytes")

        return bytes(plaintext)

    @staticmethod
    def parse_vault_header(cbor_data: bytes) -> dict:
        """
        Parse vault header from CBOR

        Returns dict with keys: vault_id, key_epoch, argon2, wrap_pw, wrap_rec, ingest_pub, ingest_priv_enc
        """
        header = cbor2.loads(cbor_data)

        if not isinstance(header, dict):
            raise ValueError(f"Header must be a CBOR map, got {type(header)}")

        # Validate version
        if header.get('v') != 1:
            raise ValueError(f"Unsupported version: {header.get('v')}")

        return header


def main():
    """Run golden file decryption tests"""
    golden_dir = Path(__file__).parent.parent.parent / 'golden'

    if not golden_dir.exists():
        print(f"Error: Golden files directory not found: {golden_dir}")
        print("Generate with: cargo test golden_files -- --ignored")
        sys.exit(1)

    print("=" * 60)
    print("Vault Golden File Decryption Test")
    print("=" * 60)
    print(f"Golden files: {golden_dir}")
    print()

    # Load metadata
    metadata_file = golden_dir / 'METADATA.md'
    if not metadata_file.exists():
        print(f"Error: METADATA.md not found")
        sys.exit(1)

    # Parse test vectors from metadata
    print("Loading test vectors from METADATA.md...")
    test_vectors = {}
    with open(metadata_file, 'r') as f:
        for line in f:
            line = line.strip()
            if ': ' in line and not line.startswith('#'):
                key, value = line.split(': ', 1)
                test_vectors[key] = value

    # Extract keys (remove any parenthetical notes)
    fk_empty = bytes.fromhex(test_vectors['- blob-empty.bin'].split('(fk: ')[1].rstrip(')'))
    fk_small = bytes.fromhex(test_vectors['- blob-small.bin'].split('(fk: ')[1].rstrip(')'))
    fk_1mib = bytes.fromhex(test_vectors['- blob-1mib.bin'].split('(fk: ')[1].rstrip(')'))
    fk_multi = bytes.fromhex(test_vectors['- blob-multi.bin'].split('(fk: ')[1].rstrip(')'))

    print(f"✓ Loaded {len(test_vectors)} test vectors")
    print()

    # Test 1: Vault header
    print("1. Vault Header (CBOR)")
    print("-" * 40)
    header_file = golden_dir / 'header.cbor'
    with open(header_file, 'rb') as f:
        header_data = f.read()

    header = VaultDecryptor.parse_vault_header(header_data)
    print(f"  ✓ Parsed CBOR header ({len(header_data)} bytes)")
    print(f"  Vault ID: {header['vault_id'].hex()}")
    print(f"  Key epoch: {header['key_epoch']}")
    print(f"  Argon2: m={header['argon2']['m_cost']}, t={header['argon2']['t_cost']}, p={header['argon2']['p_cost']}")
    print()

    # Test 2: Empty blob
    print("2. Empty Blob")
    print("-" * 40)
    blob_file = golden_dir / 'blob-empty.bin'
    with open(blob_file, 'rb') as f:
        blob_data = f.read()

    plaintext = VaultDecryptor.decrypt_blob(fk_empty, blob_data)
    print(f"  ✓ Decrypted: {len(plaintext)} bytes")
    assert len(plaintext) == 0, f"Expected 0 bytes, got {len(plaintext)}"
    print("  ✓ Verified: empty file")
    print()

    # Test 3: Small blob
    print("3. Small Blob")
    print("-" * 40)
    blob_file = golden_dir / 'blob-small.bin'
    with open(blob_file, 'rb') as f:
        blob_data = f.read()

    plaintext = VaultDecryptor.decrypt_blob(fk_small, blob_data)
    print(f"  ✓ Decrypted: {len(plaintext)} bytes")
    expected = b"Hello, Vault!"
    assert plaintext == expected, f"Expected {expected}, got {plaintext}"
    print(f"  ✓ Verified: {plaintext.decode('utf-8')}")
    print()

    # Test 4: 1 MiB blob
    print("4. 1 MiB Blob")
    print("-" * 40)
    blob_file = golden_dir / 'blob-1mib.bin'
    with open(blob_file, 'rb') as f:
        blob_data = f.read()

    plaintext = VaultDecryptor.decrypt_blob(fk_1mib, blob_data)
    print(f"  ✓ Decrypted: {len(plaintext)} bytes")
    assert len(plaintext) == 1024 * 1024, f"Expected 1 MiB, got {len(plaintext)}"
    assert all(b == 0x42 for b in plaintext), "Expected all bytes to be 0x42"
    print("  ✓ Verified: 1 MiB of 0x42")
    print()

    # Test 5: Multi-chunk blob
    print("5. Multi-chunk Blob (2.5 MiB)")
    print("-" * 40)
    blob_file = golden_dir / 'blob-multi.bin'
    with open(blob_file, 'rb') as f:
        blob_data = f.read()

    plaintext = VaultDecryptor.decrypt_blob(fk_multi, blob_data)
    print(f"  ✓ Decrypted: {len(plaintext)} bytes")
    expected_size = 2 * 1024 * 1024 + 512 * 1024  # 2.5 MiB
    assert len(plaintext) == expected_size, f"Expected {expected_size} bytes, got {len(plaintext)}"
    assert all(b == 0x99 for b in plaintext), "Expected all bytes to be 0x99"
    print(f"  ✓ Verified: {expected_size} bytes of 0x99")
    print()

    # Summary
    print("=" * 60)
    print("✓ ALL TESTS PASSED")
    print("=" * 60)
    print("Python successfully decrypted all golden files.")
    print("Format interoperability verified!")
    print()


if __name__ == '__main__':
    main()
