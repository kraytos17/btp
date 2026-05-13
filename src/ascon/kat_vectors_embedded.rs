#![allow(clippy::empty_line_after_doc_comments)]
/// NIST SP 800-232 Known Answer Test vectors for ASCON-AEAD128 (embedded-compatible).
///
/// This module provides hardcoded KAT vectors that work in no_std environments.
/// For full KAT file parsing with std, see kat_vectors.rs.
///
/// Source: <https://github.com/ascon/ascon-c/blob/main/crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt>
use super::{AsconAead, AsconVariant};

const EMPTY_PT_AD_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];
const EMPTY_PT_AD_NONCE: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];
const EMPTY_PT_AD_EXPECTED: [u8; 16] = [
    0x4F, 0x9C, 0x27, 0x82, 0x11, 0xBE, 0xC9, 0x31, 0x6B, 0xF6, 0x8F, 0x46, 0xEE, 0x8B, 0x2E, 0xC6,
];

#[must_use]
pub fn run_kat_tests() -> bool {
    let mut cipher = AsconAead::with_variant(
        &EMPTY_PT_AD_KEY,
        &EMPTY_PT_AD_NONCE,
        AsconVariant::Ascon128a,
    );

    cipher.absorb_ad(&[]);
    let mut ct = [0u8; 16];
    cipher.encrypt_in_place(&[], &mut ct);

    let tag = cipher.finalize(&EMPTY_PT_AD_KEY);
    let mut full_ct = [0u8; 32];

    full_ct[..16].copy_from_slice(&ct);
    full_ct[16..].copy_from_slice(&tag);
    full_ct[..16] == EMPTY_PT_AD_EXPECTED
}
