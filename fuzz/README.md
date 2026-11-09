# Fuzz Targets

Fuzz targets for all parsers to find panics, crashes, and edge cases.

## Targets

1. **fuzz_blob_header** - STREAM blob 47-byte header parser
2. **fuzz_vault_header** - CBOR vault header parser
3. **fuzz_item_record** - CBOR item record parser
4. **fuzz_blob_decrypt** - Full STREAM blob decryption
5. **fuzz_wrapping** - Key wrapping/unwrapping

## Running with cargo-fuzz (Nightly CI)

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a specific target for 1 hour
cargo fuzz run fuzz_blob_header -- -max_total_time=3600

# Run all targets
for target in fuzz_targets/*; do
    cargo fuzz run $(basename $target .rs) -- -max_total_time=300
done
```

## Running without cargo-fuzz (Development)

For quick local testing without cargo-fuzz:

```bash
# Run fuzz test harnesses with proptest
cargo test --test fuzz_harness
```

## Fuzzing Strategy

From DESIGN.md section 10:
> Fuzzing: Every parser: blob header, segment, inbox batch, header file, CBOR records.
> cargo-fuzz in nightly CI. No panics. Cap every length field to prevent huge allocations.

### Key Requirements

1. **No panics** - All parsers must return `Result` on invalid input
2. **Bounded allocations** - Cap length fields to prevent OOM
3. **Defensive parsing** - Validate all fields before use
4. **No unwrap on external data** - Use `?` or explicit error handling

### What to Fuzz

- ✅ Magic bytes (wrong values)
- ✅ Version numbers (future versions, 0, 255)
- ✅ Length fields (0, max, overflow values)
- ✅ Reserved fields (non-zero values)
- ✅ Truncated data
- ✅ Extra data after structure
- ✅ Invalid CBOR
- ✅ Nested CBOR depth
- ✅ Large strings/arrays in CBOR

## CI Integration

```yaml
# .github/workflows/fuzz.yml
name: Fuzzing
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: nightly-2024-12-01
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Fuzz blob header (1 hour)
        run: cargo fuzz run fuzz_blob_header -- -max_total_time=3600
      - name: Fuzz vault header (1 hour)
        run: cargo fuzz run fuzz_vault_header -- -max_total_time=3600
      # ... other targets
```

## Results

Document any crashes found and fixed here.

### Known Issues Fixed

None yet - parsers are defensive from the start.
