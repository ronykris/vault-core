# Golden Files Metadata

**NOTE: These are deterministic test vectors for format verification only.**
**All keys and passwords shown here are generated from fixed seeds for testing purposes.**
**They are not real secrets and are intentionally public for interoperability testing.**

Format version: 1
Generated: 2026-11-07T05:27:50.860239355+00:00

## Test Vectors
Password: correct-horse-battery-staple
VMK: 04c4773ea4b1dd18b5709fab76e36108d29a49991368caabeb64f8e934751247
Vault ID: eaf3216602e3e2ad23f62a3b6586b4e3
Device ID: 28a1075d60a91d1e092c92cf67718b90
Argon2 salt: 505281db367fda2a112821664e721ca5
Argon2 params: m=19456, t=2, p=1
Recovery entropy: fe7999c4a0840d04a773551bfc98ba175c2d98164dbda2e02d9dcc2df8812f47
Ingest public key: c6aa4339d388661fcf3edbcf6cfe266364bb2d50e21b03b2958c348962ab3099
Ingest private key: 32a1b33ee63109fbcb23a5ccc5ce0782b0ffeffeb7623447f14178f158f5888c
Device signing key: 5e261f085cca7ca08760381e408a16cabcf05e8a761377330d9589594174483f
Device verifying key: 4aa6b19a846763a203f1ca13d384110b88dafb521e0e0acee9e1d618dea1a5f4

## Files
- header.cbor: Vault header (CBOR)
- blob-empty.bin: Empty file blob (fk: 0228583aee78a6175b0682de5b827e7a0043f954187324c601c70d97668991d6)
- blob-small.bin: Small file blob, 13 bytes plaintext "Hello, Vault!" (fk: 9634c74df4f5533e5fa868a2730da807b4b937ab7e78aa1aa5f0af43696c0bd6)
- blob-1mib.bin: Exactly 1 MiB blob, all 0x42 (fk: 2e7aba823efdb656174c2a42bc4bc7290cc991ba2a120e1c1d4b59b2b609caa7)
- blob-multi.bin: Multi-chunk blob, 2.5 MiB, all 0x99 (fk: 1a97d6f9f57f14cf9375d00982fb6244d8978736cd18fd42f9d8e15a17b953cf)
