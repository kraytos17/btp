#![allow(dead_code)]

#[derive(Clone, Copy, Debug)]
pub enum KeySize {
    Key80,
    Key128,
}

const SBOX: [u8; 16] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];

const SBOX_INV: [u8; 16] = [
    0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA,
];

fn sbox_layer(state: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..16 {
        let nibble = ((state >> (i * 4)) & 0xF) as usize;
        result |= u64::from(SBOX[nibble]) << (i * 4);
    }
    result
}

fn sbox_layer_inv(state: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..16 {
        let nibble = ((state >> (i * 4)) & 0xF) as usize;
        result |= u64::from(SBOX_INV[nibble]) << (i * 4);
    }
    result
}

fn p_layer(state: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..64 {
        let bit = (state >> i) & 1;
        let new_pos = if i == 63 { 63 } else { (i * 16) % 63 };
        result |= bit << new_pos;
    }
    result
}

fn p_layer_inv(state: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..64 {
        let new_pos = if i == 63 { 63 } else { (i * 16) % 63 };
        let bit = (state >> new_pos) & 1;
        result |= bit << i;
    }
    result
}

fn generate_round_keys_80(key: [u8; 10]) -> [u64; 32] {
    let mut round_keys = [0u64; 32];
    let mut key_state = 0u128;
    for (i, &byte) in key.iter().enumerate() {
        key_state |= u128::from(byte) << (i * 8);
    }

    for (i, rk) in round_keys.iter_mut().enumerate() {
        *rk = (key_state >> 79) as u64;

        let top = ((key_state >> 76) & 0xF) as usize;
        let top = u128::from(SBOX[top]);
        key_state = ((key_state & ((1u128 << 76) - 1)) << 4) | (top << 76);
        key_state ^= ((i as u128) << 15) | ((i as u128) << 14);
    }

    round_keys
}

fn generate_round_keys_128(key: [u8; 16]) -> [u64; 32] {
    let mut round_keys = [0u64; 32];
    let mut key_state = 0u128;
    for (i, &byte) in key.iter().enumerate() {
        key_state |= u128::from(byte) << (i * 8);
    }

    for (i, rk) in round_keys.iter_mut().enumerate() {
        *rk = (key_state >> 64) as u64;

        let top = ((key_state >> 60) & 0xF) as usize;
        let top = u128::from(SBOX[top]);
        key_state = ((key_state & ((1u128 << 60) - 1)) << 4) | (top << 60);
        key_state ^= ((i as u128) << 15) | ((i as u128) << 14);
    }

    round_keys
}

pub struct Present {
    round_keys: [u64; 32],
}

impl Present {
    pub fn new(key: &[u8]) -> Result<Self, &'static str> {
        match key.len() {
            10 => {
                let mut k = [0u8; 10];
                k.copy_from_slice(key);
                Ok(Self {
                    round_keys: generate_round_keys_80(k),
                })
            }
            16 => {
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                Ok(Self {
                    round_keys: generate_round_keys_128(k),
                })
            }
            _ => Err("Key must be 10 bytes (80-bit) or 16 bytes (128-bit)"),
        }
    }

    #[must_use]
    pub fn encrypt_block(&self, block: [u8; 8]) -> [u8; 8] {
        let mut state = 0u64;
        for (i, &byte) in block.iter().enumerate() {
            state |= u64::from(byte) << (i * 8);
        }

        for rk in &self.round_keys[..31] {
            state ^= *rk;
            state = sbox_layer(state);
            state = p_layer(state);
        }
        state ^= self.round_keys[31];

        let mut ciphertext = [0u8; 8];
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte = ((state >> (i * 8)) & 0xFF) as u8;
        }
        ciphertext
    }

    #[must_use]
    pub fn decrypt_block(&self, block: [u8; 8]) -> [u8; 8] {
        let mut state = 0u64;
        for (i, &byte) in block.iter().enumerate() {
            state |= u64::from(byte) << (i * 8);
        }

        state ^= self.round_keys[31];

        for rk in self.round_keys[..31].iter().rev() {
            state = p_layer_inv(state);
            state = sbox_layer_inv(state);
            state ^= *rk;
        }

        let mut plaintext = [0u8; 8];
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte = ((state >> (i * 8)) & 0xFF) as u8;
        }
        plaintext
    }
}

#[must_use]
pub fn encrypt(plaintext: [u8; 8], key: &[u8; 10]) -> [u8; 8] {
    let cipher = Present::new(key).unwrap();
    cipher.encrypt_block(plaintext)
}

#[must_use]
pub fn decrypt(ciphertext: [u8; 8], key: &[u8; 10]) -> [u8; 8] {
    let cipher = Present::new(key).unwrap();
    cipher.decrypt_block(ciphertext)
}

#[must_use]
pub fn encrypt_128(plaintext: [u8; 8], key: &[u8; 16]) -> [u8; 8] {
    let cipher = Present::new(key).unwrap();
    cipher.encrypt_block(plaintext)
}

#[must_use]
pub fn decrypt_128(ciphertext: [u8; 8], key: &[u8; 16]) -> [u8; 8] {
    let cipher = Present::new(key).unwrap();
    cipher.decrypt_block(ciphertext)
}

pub mod modes {
    use super::Present;

    pub fn encrypt_ecb(cipher: &Present, plaintext: &[u8], ciphertext: &mut [u8]) {
        let blocks = plaintext.len() / 8;
        for i in 0..blocks {
            let mut block = [0u8; 8];
            block.copy_from_slice(&plaintext[i * 8..(i + 1) * 8]);
            let encrypted = cipher.encrypt_block(block);
            ciphertext[i * 8..(i + 1) * 8].copy_from_slice(&encrypted);
        }
    }

    pub fn decrypt_ecb(cipher: &Present, ciphertext: &[u8], plaintext: &mut [u8]) {
        let blocks = ciphertext.len() / 8;
        for i in 0..blocks {
            let mut block = [0u8; 8];
            block.copy_from_slice(&ciphertext[i * 8..(i + 1) * 8]);
            let decrypted = cipher.decrypt_block(block);
            plaintext[i * 8..(i + 1) * 8].copy_from_slice(&decrypted);
        }
    }

    pub fn encrypt_cbc(cipher: &Present, plaintext: &[u8], ciphertext: &mut [u8], mut iv: [u8; 8]) {
        let blocks = plaintext.len() / 8;
        for i in 0..blocks {
            let mut block = [0u8; 8];
            block.copy_from_slice(&plaintext[i * 8..(i + 1) * 8]);
            for j in 0..8 {
                block[j] ^= iv[j];
            }
            let encrypted = cipher.encrypt_block(block);
            ciphertext[i * 8..(i + 1) * 8].copy_from_slice(&encrypted);
            iv = encrypted;
        }
    }

    pub fn decrypt_cbc(cipher: &Present, ciphertext: &[u8], plaintext: &mut [u8], mut iv: [u8; 8]) {
        let blocks = ciphertext.len() / 8;
        for i in 0..blocks {
            let mut block = [0u8; 8];
            block.copy_from_slice(&ciphertext[i * 8..(i + 1) * 8]);
            let decrypted = cipher.decrypt_block(block);
            for j in 0..8 {
                plaintext[i * 8 + j] = decrypted[j] ^ iv[j];
            }
            iv.copy_from_slice(&ciphertext[i * 8..(i + 1) * 8]);
        }
    }
}

pub mod test_vectors {
    use super::Present;

    #[must_use]
    pub fn run_tests() -> bool {
        let mut failed = 0;

        // Test encrypt/decrypt roundtrip for PRESENT-80
        for key_byte in 0u8..5u8 {
            let key = [key_byte; 10];
            let cipher = Present::new(&key).unwrap();
            for pt_byte in 0u8..5u8 {
                let pt = [pt_byte; 8];
                let ct = cipher.encrypt_block(pt);
                let decrypted = cipher.decrypt_block(ct);
                if decrypted != pt {
                    failed += 1;
                }
            }
        }

        // Test encrypt/decrypt roundtrip for PRESENT-128
        for key_byte in 0u8..3u8 {
            let key = [key_byte; 16];
            let cipher = Present::new(&key).unwrap();
            for pt_byte in 0u8..3u8 {
                let pt = [pt_byte; 8];
                let ct = cipher.encrypt_block(pt);
                let decrypted = cipher.decrypt_block(ct);
                if decrypted != pt {
                    failed += 1;
                }
            }
        }

        failed == 0
    }
}
