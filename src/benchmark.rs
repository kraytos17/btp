#[cfg(feature = "embedded")]
use rp2040_hal::Timer;

pub static mut PRESENT_80_CYCLES: u64 = 0;
pub static mut PRESENT_80_CPB: u64 = 0;
pub static mut PRESENT_128_CYCLES: u64 = 0;
pub static mut PRESENT_128_CPB: u64 = 0;
pub static mut SPECK_64_CYCLES: u64 = 0;
pub static mut SPECK_64_CPB: u64 = 0;
pub static mut SPECK_128_CYCLES: u64 = 0;
pub static mut SPECK_128_CPB: u64 = 0;
pub static mut ASCON_CYCLES: u64 = 0;
pub static mut ASCON_CPB: u64 = 0;

pub static mut ASCON_INIT_CYCLES: u64 = 0;
pub static mut ASCON_ABSORB_CYCLES: u64 = 0;
pub static mut ASCON_ENCRYPT_CYCLES: u64 = 0;
pub static mut ASCON_FINALIZE_CYCLES: u64 = 0;

pub static mut TESTS_PASSED: u32 = 0;

const BENCH_ITERATIONS: u32 = 1000;
const WARMUP_ITERATIONS: u32 = 50;
const MHZ: u64 = 133;

pub fn run_all(timer: &mut Timer) {
    run_tests();
    bench_present_80(timer);
    bench_present_128(timer);
    bench_speck_64(timer);
    bench_speck_128(timer);
    bench_ascon(timer);
    bench_ascon_detailed(timer);
    modes::bench_present_modes(timer);
    modes::bench_speck_modes(timer);
}

fn run_tests() {
    let mut passed = 0u32;
    if crate::present::test_vectors::run_tests() {
        passed += 1;
    }
    if crate::speck::test_vectors::run_tests() {
        passed += 1;
    }
    if crate::ascon::test_vectors::run_tests() {
        passed += 1;
    }

    unsafe {
        TESTS_PASSED = core::hint::black_box(passed);
    }
}

fn bench_present_80(timer: &mut Timer) {
    let plaintext: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    let key: [u8; 10] = [0x00; 10];

    let cipher = crate::present::Present::new(&key).unwrap();
    for _ in 0..WARMUP_ITERATIONS {
        let _val = cipher.encrypt_block(plaintext);
    }

    let t0 = timer.get_counter().ticks();
    for _ in 0..BENCH_ITERATIONS {
        let _val = cipher.encrypt_block(plaintext);
    }
    let elapsed_us = timer.get_counter().ticks() - t0;

    let avg_us = elapsed_us / BENCH_ITERATIONS as u64;
    let cycles = avg_us * MHZ;
    let cpb = cycles / 8;

    unsafe {
        PRESENT_80_CYCLES = core::hint::black_box(cycles);
        PRESENT_80_CPB = core::hint::black_box(cpb);
    }
}

fn bench_present_128(timer: &mut Timer) {
    let plaintext: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    let key: [u8; 16] = [0x00; 16];

    let cipher = crate::present::Present::new(&key).unwrap();
    for _ in 0..WARMUP_ITERATIONS {
        let _val = cipher.encrypt_block(plaintext);
    }

    let t0 = timer.get_counter().ticks();
    for _ in 0..BENCH_ITERATIONS {
        let _val = cipher.encrypt_block(plaintext);
    }
    let elapsed_us = timer.get_counter().ticks() - t0;

    let avg_us = elapsed_us / BENCH_ITERATIONS as u64;
    let cycles = avg_us * MHZ;
    let cpb = cycles / 8;

    unsafe {
        PRESENT_128_CYCLES = core::hint::black_box(cycles);
        PRESENT_128_CPB = core::hint::black_box(cpb);
    }
}

fn bench_speck_64(timer: &mut Timer) {
    let pt: [u32; 2] = [0x7461_4620, 0x736e_6165];
    let key: [u32; 2] = [0x0302_0100, 0x0b0a_0908];

    let cipher = crate::speck::Speck64::new(&key).unwrap();
    for _ in 0..WARMUP_ITERATIONS {
        let _val = cipher.encrypt_block(pt);
    }

    let t0 = timer.get_counter().ticks();
    for _ in 0..BENCH_ITERATIONS {
        let _val = cipher.encrypt_block(pt);
    }
    let elapsed_us = timer.get_counter().ticks() - t0;

    let avg_us = elapsed_us / BENCH_ITERATIONS as u64;
    let cycles = avg_us * MHZ;
    let cpb = cycles / 8;

    unsafe {
        SPECK_64_CYCLES = core::hint::black_box(cycles);
        SPECK_64_CPB = core::hint::black_box(cpb);
    }
}

/// SPECK-64/128 benchmark using 128-bit key (4-word) per NSA spec.
///
/// This variant uses SpeckVariant::Speck64_128 with:
/// - Block size: 64 bits (2×32-bit words)
/// - Key size: 128 bits (4×32-bit words)
/// - Rounds: 27
fn bench_speck_128(timer: &mut Timer) {
    let pt: [u32; 2] = [0x7461_4620, 0x736e_6165];
    // NSA spec SPECK-64/128: 128-bit key = 4×32-bit words
    let key: [u32; 4] = [0x0302_0100, 0x0b0a_0908, 0x1312_1110, 0x1b1a_1918];

    let cipher = crate::speck::Speck64::new(&key).unwrap();
    for _ in 0..WARMUP_ITERATIONS {
        let _val = cipher.encrypt_block(pt);
    }

    let t0 = timer.get_counter().ticks();
    for _ in 0..BENCH_ITERATIONS {
        let _val = cipher.encrypt_block(pt);
    }
    let elapsed_us = timer.get_counter().ticks() - t0;

    let avg_us = elapsed_us / BENCH_ITERATIONS as u64;
    let cycles = avg_us * MHZ;
    let cpb = cycles / 8;

    unsafe {
        SPECK_128_CYCLES = core::hint::black_box(cycles);
        SPECK_128_CPB = core::hint::black_box(cpb);
    }
}

fn bench_ascon(timer: &mut Timer) {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let nonce: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let ad: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    for _ in 0..WARMUP_ITERATIONS {
        let _val = crate::ascon::encrypt_aead(&key, &nonce, &plaintext, &ad);
    }

    let t0 = timer.get_counter().ticks();
    for _ in 0..BENCH_ITERATIONS {
        let _val = crate::ascon::encrypt_aead(&key, &nonce, &plaintext, &ad);
    }
    let elapsed_us = timer.get_counter().ticks() - t0;

    let avg_us = elapsed_us / BENCH_ITERATIONS as u64;
    let cycles = avg_us * MHZ;
    let cpb = cycles / 16;

    unsafe {
        ASCON_CYCLES = core::hint::black_box(cycles);
        ASCON_CPB = core::hint::black_box(cpb);
    }
}

fn bench_ascon_detailed(timer: &mut Timer) {
    use crate::ascon::AsconAead;

    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let nonce: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let ad: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    let mut init_cycles = 0u64;
    let mut absorb_cycles = 0u64;
    let mut encrypt_cycles = 0u64;
    let mut finalize_cycles = 0u64;

    for _ in 0..BENCH_ITERATIONS {
        let t0 = timer.get_counter().ticks();
        let mut cipher = AsconAead::new(&key, &nonce);
        let t1 = timer.get_counter().ticks();
        init_cycles += t1 - t0;

        let t2 = timer.get_counter().ticks();
        cipher.absorb_ad(&ad);
        let t3 = timer.get_counter().ticks();
        absorb_cycles += t3 - t2;

        let mut ct = [0u8; 16];
        let t4 = timer.get_counter().ticks();
        cipher.encrypt_in_place(&plaintext, &mut ct);
        let t5 = timer.get_counter().ticks();
        encrypt_cycles += t5 - t4;

        let t6 = timer.get_counter().ticks();
        let _tag = cipher.finalize(&key);
        let t7 = timer.get_counter().ticks();
        finalize_cycles += t7 - t6;

        core::hint::black_box(ct);
    }

    let avg_iter = BENCH_ITERATIONS as u64;

    unsafe {
        ASCON_INIT_CYCLES = core::hint::black_box((init_cycles / avg_iter) * MHZ);
        ASCON_ABSORB_CYCLES = core::hint::black_box((absorb_cycles / avg_iter) * MHZ);
        ASCON_ENCRYPT_CYCLES = core::hint::black_box((encrypt_cycles / avg_iter) * MHZ);
        ASCON_FINALIZE_CYCLES = core::hint::black_box((finalize_cycles / avg_iter) * MHZ);
    }
}

pub mod modes {
    use crate::present::{Present, modes as present_modes};
    use crate::speck::{Speck64, modes as speck_modes};

    #[cfg(feature = "embedded")]
    use rp2040_hal::Timer;

    const BENCH_ITERATIONS: u32 = 1000;
    const WARMUP_ITERATIONS: u32 = 50;
    const MHZ: u64 = 133;

    pub static mut PRESENT_ECB_CPB: u64 = 0;
    pub static mut PRESENT_CBC_CPB: u64 = 0;
    pub static mut SPECK_ECB_CPB: u64 = 0;
    pub static mut SPECK_CBC_CPB: u64 = 0;
    pub static mut SPECK_CTR_CPB: u64 = 0;

    pub fn bench_present_modes(timer: &mut Timer) {
        let key: [u8; 10] = [0x00; 10];
        let cipher = Present::new(&key).unwrap();
        let iv: [u8; 8] = [0x00; 8];

        let mut plaintext = [0u8; 64];
        let mut ciphertext = [0u8; 64];
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap_or(0);
        }
        for _ in 0..WARMUP_ITERATIONS {
            present_modes::encrypt_ecb(&cipher, &plaintext, &mut ciphertext);
        }

        let t0 = timer.get_counter().ticks();
        for _ in 0..BENCH_ITERATIONS {
            present_modes::encrypt_ecb(&cipher, &plaintext, &mut ciphertext);
        }
        let elapsed_us = timer.get_counter().ticks() - t0;

        let cycles = (elapsed_us / BENCH_ITERATIONS as u64) * MHZ;
        let cpb = cycles / 64;

        unsafe {
            PRESENT_ECB_CPB = core::hint::black_box(cpb);
        }

        for _ in 0..WARMUP_ITERATIONS {
            present_modes::encrypt_cbc(&cipher, &plaintext, &mut ciphertext, iv);
        }

        let t0 = timer.get_counter().ticks();
        for _ in 0..BENCH_ITERATIONS {
            present_modes::encrypt_cbc(&cipher, &plaintext, &mut ciphertext, iv);
        }
        let elapsed_us = timer.get_counter().ticks() - t0;

        let cycles = (elapsed_us / BENCH_ITERATIONS as u64) * MHZ;
        let cpb = cycles / 64;

        unsafe {
            PRESENT_CBC_CPB = core::hint::black_box(cpb);
        }
    }

    pub fn bench_speck_modes(timer: &mut Timer) {
        let key: [u32; 3] = [0x0302_0100, 0x0b0a_0908, 0x1312_1110];
        let cipher = Speck64::new(&key).unwrap();
        let iv: [u8; 8] = [0x00; 8];

        let mut plaintext = [0u8; 64];
        let mut ciphertext = [0u8; 64];
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap_or(0);
        }
        for _ in 0..WARMUP_ITERATIONS {
            speck_modes::encrypt_ecb(&cipher, &plaintext, &mut ciphertext);
        }

        let t0 = timer.get_counter().ticks();
        for _ in 0..BENCH_ITERATIONS {
            speck_modes::encrypt_ecb(&cipher, &plaintext, &mut ciphertext);
        }
        let elapsed_us = timer.get_counter().ticks() - t0;

        let cycles = (elapsed_us / BENCH_ITERATIONS as u64) * MHZ;
        let cpb = cycles / 64;

        unsafe {
            SPECK_ECB_CPB = core::hint::black_box(cpb);
        }

        for _ in 0..WARMUP_ITERATIONS {
            speck_modes::encrypt_cbc(&cipher, &plaintext, &mut ciphertext, iv);
        }

        let t0 = timer.get_counter().ticks();
        for _ in 0..BENCH_ITERATIONS {
            speck_modes::encrypt_cbc(&cipher, &plaintext, &mut ciphertext, iv);
        }
        let elapsed_us = timer.get_counter().ticks() - t0;

        let cycles = (elapsed_us / BENCH_ITERATIONS as u64) * MHZ;
        let cpb = cycles / 64;

        unsafe {
            SPECK_CBC_CPB = core::hint::black_box(cpb);
        }

        for _ in 0..WARMUP_ITERATIONS {
            speck_modes::encrypt_ctr(&cipher, &plaintext, &mut ciphertext, iv);
        }

        let t0 = timer.get_counter().ticks();
        for _ in 0..BENCH_ITERATIONS {
            speck_modes::encrypt_ctr(&cipher, &plaintext, &mut ciphertext, iv);
        }
        let elapsed_us = timer.get_counter().ticks() - t0;

        let cycles = (elapsed_us / BENCH_ITERATIONS as u64) * MHZ;
        let cpb = cycles / 64;

        unsafe {
            SPECK_CTR_CPB = core::hint::black_box(cpb);
        }
    }
}
