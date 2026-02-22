# BTP - Embedded Cryptography Benchmark

A `no_std` Rust implementation of PRESENT, SPECK, and ASCON cryptographic algorithms for the Raspberry Pi Pico (RP2040), with hardware benchmarking via UART output.

## Features

### Cryptographic Algorithms

- **PRESENT-80/128**: 64-bit block cipher with 80-bit and 128-bit key variants
- **SPECK-64/96 & SPECK-64/128**: ARX-based block cipher (Add-Rotate-XOR)
- **ASCON-128**: AEAD (Authenticated Encryption with Associated Data) and ASCON-Hash

### Operating Modes

- ECB (Electronic Codebook)
- CBC (Cipher Block Chaining)  
- CTR (Counter Mode) - SPECK only

### Hardware Benchmarking

- Hardware timer-based cycle-accurate benchmarking on RP2040
- UART output at 115200 baud (GPIO0=TX, GPIO1=RX)
- Results include cycles per byte (cpb) for each algorithm

## Project Structure

```
btp/
├── Cargo.toml                    # Project configuration
├── memory.x                      # RP2040 memory layout
├── .cargo/config.toml           # Build target configuration
├── src/
│   ├── main.rs                 # Embedded entry point
│   ├── lib.rs                  # Library root (std feature)
│   ├── present.rs              # PRESENT cipher implementation
│   ├── speck.rs                # SPECK cipher implementation
│   ├── ascon.rs               # ASCON AEAD & Hash implementation
│   └── benchmark.rs           # Hardware benchmarking
└── tests/
    └── crypto_tests.rs        # Host-based tests
```

## Building

### Prerequisites

- Rust toolchain with thumbv6m-none-eabi target:
  ```bash
  rustup target add thumbv6m-none-eabi
  ```

- `elf2uf2-rs` for UF2 generation:
  ```bash
  cargo install elf2uf2-rs
  ```

### Build Commands

**For embedded target (Raspberry Pi Pico):**
```bash
cargo build --release --target thumbv6m-none-eabi
```

**For host testing:**
```bash
cargo test --no-default-features --features std
```

## Flashing to Pico

1. **Generate UF2 file:**
   ```bash
   elf2uf2-rs target/thumbv6m-none-eabi/release/btp btp.uf2
   ```

2. **Enter bootloader mode:**
   - Hold the BOOT button on the Pico
   - Plug in USB while holding BOOT
   - Release button (Pico appears as RPI-RP2 drive)

3. **Copy UF2 to Pico:**
   ```bash
   cp btp.uf2 /path/to/RPI-RP2/
   ```

   The Pico will automatically reboot and run the benchmark.

## Viewing Results

Connect to UART at 115200 baud:

```bash
# Using picocom
picocom -b 115200 /dev/ttyACM0

# Using minicom
minicom -b 115200 -o -D /dev/ttyACM0
```

Expected output:
```
=== BTP Crypto Benchmark ===

Running tests and benchmarks...

=== Results ===
Tests passed: true

Block cipher benchmarks (cycles per byte):
  PRESENT-80:  XXX cpb
  PRESENT-128: XXX cpb
  SPECK-64/96: XXX cpb
  SPECK-64/128: XXX cpb
  ASCON-128:   XXX cpb

ASCON phase breakdown (cycles):
  Init:     XXX
  Absorb:   XXX
  Encrypt:  XXX
  Finalize: XXX

Mode benchmarks (64-byte block, cycles per byte):
  PRESENT ECB: XXX cpb
  PRESENT CBC: XXX cpb
  SPECK ECB:   XXX cpb
  SPECK CBC:   XXX cpb
  SPECK CTR:   XXX cpb

=== Done ===
```

## Clippy Linting

The project is clippy-clean with strict warnings enabled:

```bash
cargo clippy -- -W clippy::all -W clippy::pedantic
```

## Features

| Feature   | Description                                    |
|-----------|------------------------------------------------|
| `embedded` | Default. Builds for RP2040 (no_std)          |
| `std`     | Builds for host machine with standard library |

## Technical Details

### PRESENT

- 64-bit block, 80-bit or 128-bit key
- 31 rounds
- S-box based substitution + bit permutation (P-layer)
- Implemented in `src/present.rs`

### SPECK

- 64-bit block, 96-bit or 128-bit key
- 26-27 rounds (variant dependent)
- ARX design (Add-Rotate-XOR)
- Implemented in `src/speck.rs`

### ASCON-128

- 128-bit key, 128-bit nonce
- Sponge-based AEAD
- 6 or 12 rounds (variant dependent)
- Supports associated data
- Also includes ASCON-Hash (256-bit output)
- Implemented in `src/ascon.rs`
