extern crate alloc;

use super::Present;
use alloc::vec::Vec;

pub fn verify_present_80() -> bool {
    let key_hex = "0123456789abcdef0123";
    let pt_hex = "0123456789abcdef";
    let ct_hex = "f8dd50531d973bde"; // Note: pypresent reference gives d at position 10, not a

    let key = match hex_to_bytes_80(key_hex) {
        Some(k) => k,
        None => return false,
    };
    let pt = match hex_to_be_bytes_64(pt_hex) {
        Some(p) => p,
        None => return false,
    };
    let expected_ct = match hex_to_be_bytes_64(ct_hex) {
        Some(c) => c,
        None => return false,
    };

    let cipher = match Present::new(&key) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let result = cipher.encrypt_block(pt);
    result == expected_ct
}

pub fn verify_present_128() -> bool {
    let key_hex = "00112233445566778899aabbccddeeff";
    let pt_hex = "0123456789abcdef";
    let ct_hex = "88728500054418de";

    let key = match hex_to_bytes_128(key_hex) {
        Some(k) => k,
        None => return false,
    };
    let pt = match hex_to_be_bytes_64(pt_hex) {
        Some(p) => p,
        None => return false,
    };
    let expected_ct = match hex_to_be_bytes_64(ct_hex) {
        Some(c) => c,
        None => return false,
    };

    let cipher = match Present::new(&key) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let result = cipher.encrypt_block(pt);
    result == expected_ct
}

fn hex_to_bytes_80(hex: &str) -> Option<[u8; 10]> {
    let hex = hex.trim();
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| {
            let s = core::str::from_utf8(chunk).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect();

    if bytes.len() != 10 {
        return None;
    }
    let mut result = [0u8; 10];
    result.copy_from_slice(&bytes);
    Some(result)
}

fn hex_to_bytes_128(hex: &str) -> Option<[u8; 16]> {
    let hex = hex.trim();
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| {
            let s = core::str::from_utf8(chunk).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect();

    if bytes.len() != 16 {
        return None;
    }
    let mut result = [0u8; 16];
    result.copy_from_slice(&bytes);
    Some(result)
}

fn hex_to_be_bytes_64(hex: &str) -> Option<[u8; 8]> {
    let hex = hex.trim();
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| {
            let s = core::str::from_utf8(chunk).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect();

    if bytes.len() != 8 {
        return None;
    }
    let mut result = [0u8; 8];
    result.copy_from_slice(&bytes);
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_present_80_iso_vector() {
        assert!(verify_present_80());
    }

    #[test]
    fn test_present_128_iso_vector() {
        assert!(verify_present_128());
    }
}
