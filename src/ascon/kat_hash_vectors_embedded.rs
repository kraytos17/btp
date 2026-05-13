#![allow(clippy::empty_line_after_doc_comments)]
/// NIST SP 800-232 Known Answer Test vectors for ASCON-Hash256 (embedded-compatible).
///
/// This module provides hardcoded KAT vectors that work in no_std environments.
/// For full KAT file parsing with std, see kat_hash_vectors.rs.
///
/// Source: <https://github.com/ascon/ascon-c/blob/main/crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt>
use super::AsconHash;

const EMPTY_MSG_HASH: &[u8; 32] = &[
    0x0B, 0x3B, 0xE5, 0x85, 0x0F, 0x2F, 0x6B, 0x98, 0x0F, 0x3A, 0xB6, 0x0D, 0x93, 0x34, 0x43, 0x25,
    0x33, 0xF1, 0x82, 0xF8, 0x66, 0x63, 0x52, 0xEC, 0x4A, 0x24, 0xD8, 0x5B, 0xFD, 0xCF, 0x6E, 0xFF,
];

#[must_use]
pub fn run_kat_tests() -> bool {
    let mut hash = AsconHash::new();
    hash.absorb(&[]);
    let result = hash.finalize();
    result == *EMPTY_MSG_HASH
}
