#![allow(clippy::empty_line_after_doc_comments)]
/// Big-endian SPECK KAT verification using published NSA/Crypto++ vectors.
///
/// Source: test_data/speck_kat.txt
///
/// Our implementation follows the algorithmic description per the NSA paper,
/// which uses big-endian byte representation. This matches the Linux kernel
/// and Crypto++ 6.1+ implementation approach.
///
/// We parse the KAT vectors (big-endian hex) directly into u32 words and compare
/// against our encryption output.
extern crate alloc;

use super::Speck64;
use alloc::vec::Vec;

fn parse_be_hex_word(hex: &str) -> u32 {
    let hex = hex.trim();
    u32::from_be_bytes([
        u8::from_str_radix(&hex[0..2], 16).unwrap(),
        u8::from_str_radix(&hex[2..4], 16).unwrap(),
        u8::from_str_radix(&hex[4..6], 16).unwrap(),
        u8::from_str_radix(&hex[6..8], 16).unwrap(),
    ])
}

fn parse_be_hex_pair(hex1: &str, hex2: &str) -> [u32; 2] {
    [parse_be_hex_word(hex1), parse_be_hex_word(hex2)]
}

fn verify_vector_96(key: [u32; 3], plaintext: [u32; 2], expected_ct: [u32; 2]) -> bool {
    let cipher = match Speck64::new(&key) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let ct = cipher.encrypt_block(plaintext);
    ct[0] == expected_ct[0] && ct[1] == expected_ct[1]
}

fn verify_vector_128(key: [u32; 4], plaintext: [u32; 2], expected_ct: [u32; 2]) -> bool {
    let cipher = match Speck64::new(&key[..3]) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let ct = cipher.encrypt_block(plaintext);
    ct[0] == expected_ct[0] && ct[1] == expected_ct[1]
}

const SPECK_KAT_DATA: &str = include_str!("../../test_data/speck_kat.txt");

#[must_use]
pub fn run_kat_tests() -> bool {
    for vector_text in SPECK_KAT_DATA.split('#').skip(1) {
        let vector_text = vector_text.trim();
        if vector_text.is_empty() {
            continue;
        }

        let lines: Vec<&str> = vector_text.lines().collect();
        if lines.len() < 4 {
            continue;
        }

        let key_line = lines[0];
        let pt_line = lines[1];
        let ct_line = lines[2];

        if !key_line.starts_with("Key:")
            || !pt_line.starts_with("Plaintext:")
            || !ct_line.starts_with("Ciphertext:")
        {
            continue;
        }

        let key_hex = key_line.trim_start_matches("Key:").trim();
        let pt_hex = pt_line.trim_start_matches("Plaintext:").trim();
        let ct_hex = ct_line.trim_start_matches("Ciphertext:").trim();

        let key_parts: Vec<&str> = key_hex.split_whitespace().collect();
        let pt_parts: Vec<&str> = pt_hex.split_whitespace().collect();
        let ct_parts: Vec<&str> = ct_hex.split_whitespace().collect();

        if key_parts.len() == 3 && pt_parts.len() == 2 && ct_parts.len() == 2 {
            let key = [
                parse_be_hex_word(key_parts[0]),
                parse_be_hex_word(key_parts[1]),
                parse_be_hex_word(key_parts[2]),
            ];

            let plaintext = parse_be_hex_pair(pt_parts[0], pt_parts[1]);
            let expected_ct = parse_be_hex_pair(ct_parts[0], ct_parts[1]);
            if !verify_vector_96(key, plaintext, expected_ct) {
                return false;
            }
        } else if key_parts.len() == 4 && pt_parts.len() == 2 && ct_parts.len() == 2 {
            let key = [
                parse_be_hex_word(key_parts[0]),
                parse_be_hex_word(key_parts[1]),
                parse_be_hex_word(key_parts[2]),
                parse_be_hex_word(key_parts[3]),
            ];
            let plaintext = parse_be_hex_pair(pt_parts[0], pt_parts[1]);
            let expected_ct = parse_be_hex_pair(ct_parts[0], ct_parts[1]);
            if !verify_vector_128(key, plaintext, expected_ct) {
                return false;
            }
        }
    }

    true
}
