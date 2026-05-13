# BTP - Lightweight Cryptography Library

A `no_std` Rust implementation of PRESENT, SPECK, and ASCON cryptographic algorithms for embedded systems (Raspberry Pi Pico RP2040), with comprehensive benchmarking.

## Features

### Cryptographic Algorithms

- **PRESENT-80/128**: 64-bit block cipher with 80-bit and 128-bit key variants
- **SPECK-64/96 & SPECK-64/128**: ARX-based lightweight block cipher
- **ASCON-128 AEAD**: NIST SP 800-232 compliant authenticated encryption
- **ASCON-Hash256**: Sponge-based hash function

### Operating Modes

- ECB (Electronic Codebook)
- CBC (Cipher Block Chaining)
- CTR (Counter Mode) - SPECK only

## Project Structure

```
btp/
├── Cargo.toml              # Project configuration
├── memory.x               # RP2040 memory layout
├── .cargo/config.toml     # Build target configuration
├── requirements.txt       # Python dependencies for visualization
├── src/
│   ├── lib.rs            # Library root
│   ├── main.rs           # Embedded entry point (RP2040)
│   ├── main_host.rs      # Host entry point
│   ├── present.rs        # PRESENT cipher implementation
│   ├── speck.rs          # SPECK cipher implementation
│   ├── ascon.rs          # ASCON AEAD & Hash (NIST SP 800-232)
│   ├── benchmark.rs      # Hardware benchmarking (embedded)
│   ├── energy.rs         # Energy estimation
│   └── stats.rs          # Statistical analysis
├── tests/
│   ├── ascon_tests.rs    # ASCON unit tests + KAT
│   ├── present_tests.rs  # PRESENT unit tests + KAT
│   └── speck_tests.rs    # SPECK unit tests + KAT
├── benches/
│   └── ascon_bench.rs    # Criterion benchmarks
├── bench/
│   ├── visualize.py      # Python visualization
│   └── requirements.txt  # Visualization dependencies
├── bench_results/        # Benchmark output (generated)
└── test_data/           # KAT test vectors
```

## Quick Start

### Run Tests

```bash
cargo test --no-default-features --features std
```

### Run Benchmarks

```bash
cargo bench --no-default-features --features std --bench ascon_bench
```

### Generate Charts

```bash
uv run python bench/visualize.py
```

## Building

### Prerequisites

**Rust toolchain:**
```bash
rustup target add thumbv6m-none-eabi  # For embedded
cargo install elf2uf2-rs             # For UF2 generation
```

**Python visualization:**
```bash
uv pip install -r requirements.txt
```

### Build Commands

**Embedded target (Raspberry Pi Pico):**
```bash
cargo build --release --target thumbv6m-none-eabi
```

**Host testing/benchmarking:**
```bash
cargo test --no-default-features --features std
cargo bench --no-default-features --features std --bench ascon_bench
```

## Flashing to Pico

1. **Generate UF2 file:**
   ```bash
   elf2uf2-rs target/thumbv6m-none-eabi/release/btp btp.uf2
   ```

2. **Enter bootloader mode:**
   - Hold BOOT button on Pico
   - Plug in USB while holding BOOT
   - Release button (Pico appears as RPI-RP2 drive)

3. **Copy UF2 to Pico:**
   ```bash
   cp btp.uf2 /path/to/RPI-RP2/
   ```

## Benchmarking

### Host Benchmarks (criterion)

The project uses [criterion](https://bheisner.github.io/criterion.rs/) for statistical benchmarking on the host machine.

**Run all benchmarks:**
```bash
cargo bench --bench ascon_bench
```

**Benchmark groups:**
- `ascon-aead128` - AEAD encryption with varying PT/AD lengths
- `ascon-hash256` - Hash operations
- `ascon-phases` - Per-phase breakdown (init, absorb, encrypt, finalize)
- `ascon-scaling` - Message length scaling (8-4096 bytes)
- `present-80-ecb` / `present-128-ecb` - PRESENT ECB mode
- `speck-64-96-ecb` - SPECK ECB mode

**Output locations:**
- `target/criterion/*/new/estimates.json` - Raw JSON with statistics
- `target/criterion/report/index.html` - HTML report
- `bench_results/` - Generated charts and CSV

### Hardware Benchmarks (RP2040)

Hardware cycle-accurate benchmarking on the Raspberry Pi Pico:

1. Flash the firmware (see above)
2. Connect UART at 115200 baud:
   ```bash
   picocom -b 115200 /dev/ttyACM0
   minicom -b 115200 -o -D /dev/ttyACM0
   ```

## Visualization

Generate paper-ready charts from benchmark results:

```bash
uv run python bench/visualize.py
```

**Output files:**
- `bench_results/criterion_results.csv` - All benchmark data
- `bench_results/throughput_comparison.png/pdf` - Throughput charts
- `bench_results/cycles_per_byte.png/pdf` - Efficiency charts
- `bench_results/power_comparison.png/pdf` - Power estimates
- `bench_results/benchmark_table.tex` - LaTeX table

## Known Answer Tests

### ASCON (NIST SP 800-232)

The ASCON implementation follows NIST SP 800-232 exactly:
- IV constants: `0x00000800806c0001`
- Little-endian byte ordering
- Padding: 0x01
- Hash squeeze: 4 rounds of P12 between 8-byte blocks

Test vectors from: https://csrc.nist.gov/projects/computational-cryptography/cryptographic-standardization/initial-assessments

### PRESENT & SPECK

KAT vectors verified against reference implementations.

## Features

| Feature    | Description                              |
|------------|------------------------------------------|
| `embedded` | Default. Builds for RP2040 (no_std)      |
| `std`      | Builds for host with standard library     |
| `kat-tests`| Enables KAT verification tests            |

## Technical Details

### PRESENT

- 64-bit block, 80-bit or 128-bit key
- 31 rounds
- S-box substitution + bit permutation
- Located in `src/present.rs`

### SPECK

- 64-bit block, 96-bit or 128-bit key
- 26-27 rounds (variant dependent)
- ARX design (Add-Rotate-XOR)
- Located in `src/speck.rs`

### ASCON-128 (NIST SP 800-232)

- 128-bit key, 128-bit nonce
- Sponge-based AEAD
- 6 rounds for initialization, 12 for data processing
- Supports associated data (AD)
- ASCON-Hash256 with 32-byte output
- Located in `src/ascon.rs`

## Clippy

The project is clippy-clean:

```bash
cargo clippy -- -W clippy::all -W clippy::pedantic
```