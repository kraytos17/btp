#![allow(dead_code)]

#[derive(Clone, Copy, Debug)]
pub enum SpeckVariant {
    Speck32_64,
    Speck48_72,
    Speck48_96,
    Speck64_96,
    Speck64_128,
    Speck96_96,
    Speck96_144,
    Speck128_128,
    Speck128_192,
    Speck128_256,
}

impl SpeckVariant {
    #[must_use]
    pub const fn rounds(self) -> usize {
        match self {
            Self::Speck32_64 | Self::Speck48_72 => 22,
            Self::Speck48_96 => 23,
            Self::Speck64_96 => 26,
            Self::Speck64_128 => 27,
            Self::Speck96_96 => 28,
            Self::Speck96_144 => 29,
            Self::Speck128_128 => 32,
            Self::Speck128_192 => 33,
            Self::Speck128_256 => 34,
        }
    }

    #[must_use]
    pub const fn alpha_beta(self) -> (u32, u32) {
        match self {
            Self::Speck32_64 => (7, 2),
            Self::Speck48_72
            | Self::Speck48_96
            | Self::Speck64_96
            | Self::Speck64_128
            | Self::Speck96_96
            | Self::Speck96_144
            | Self::Speck128_128
            | Self::Speck128_192
            | Self::Speck128_256 => (8, 3),
        }
    }

    #[must_use]
    pub const fn key_words(self) -> usize {
        match self {
            Self::Speck32_64
            | Self::Speck48_72
            | Self::Speck64_96
            | Self::Speck96_96
            | Self::Speck128_128 => 2,
            Self::Speck48_96 | Self::Speck64_128 | Self::Speck96_144 | Self::Speck128_192 => 3,
            Self::Speck128_256 => 4,
        }
    }
}

pub struct Speck64 {
    round_keys: [u32; 34],
    rounds: usize,
    alpha: u32,
    beta: u32,
}

impl Speck64 {
    pub fn new(key: &[u32]) -> Result<Self, &'static str> {
        let variant = match key.len() {
            2 => SpeckVariant::Speck64_96,
            3 => SpeckVariant::Speck64_128,
            _ => return Err("Key must be 2 or 3 u32 words"),
        };

        let rounds = variant.rounds();
        let (alpha, beta) = variant.alpha_beta();
        let key_words = variant.key_words();

        let mut round_keys = [0u32; 34];
        let mut k = [0u32; 4];
        k[..key_words].copy_from_slice(&key[..key_words]);

        for (i, rk) in round_keys.iter_mut().enumerate().take(rounds) {
            *rk = k[0];
            let new_l = (rotate_right(k[0], alpha).wrapping_add(k[key_words - 1]))
                ^ u32::try_from(i).unwrap();
            for j in (1..key_words).rev() {
                k[j] ^= rotate_left(k[j - 1], beta);
            }
            k[0] = new_l;
        }

        Ok(Self {
            round_keys,
            rounds,
            alpha,
            beta,
        })
    }

    #[must_use]
    pub fn encrypt_block(&self, plaintext: [u32; 2]) -> [u32; 2] {
        let mut x = plaintext[0];
        let mut y = plaintext[1];

        for rk in self.round_keys.iter().take(self.rounds) {
            x = rotate_right(x, self.alpha);
            x = x.wrapping_add(y);
            x ^= *rk;
            y = rotate_left(y, self.beta);
            y ^= x;
        }

        [x, y]
    }

    #[must_use]
    pub fn decrypt_block(&self, ciphertext: [u32; 2]) -> [u32; 2] {
        let mut x = ciphertext[0];
        let mut y = ciphertext[1];

        for rk in self.round_keys.iter().take(self.rounds).rev() {
            y ^= x;
            y = rotate_right(y, self.beta);
            x ^= *rk;
            x = x.wrapping_sub(y);
            x = rotate_left(x, self.alpha);
        }

        [x, y]
    }

    #[must_use]
    pub fn encrypt_bytes(&self, plaintext: [u8; 8]) -> [u8; 8] {
        let pt = [
            u32::from_le_bytes(plaintext[0..4].try_into().unwrap()),
            u32::from_le_bytes(plaintext[4..8].try_into().unwrap()),
        ];

        let ct = self.encrypt_block(pt);
        let mut result = [0u8; 8];
        result[0..4].copy_from_slice(&ct[0].to_le_bytes());
        result[4..8].copy_from_slice(&ct[1].to_le_bytes());
        result
    }

    #[must_use]
    pub fn decrypt_bytes(&self, ciphertext: [u8; 8]) -> [u8; 8] {
        let ct = [
            u32::from_le_bytes(ciphertext[0..4].try_into().unwrap()),
            u32::from_le_bytes(ciphertext[4..8].try_into().unwrap()),
        ];

        let pt = self.decrypt_block(ct);
        let mut result = [0u8; 8];
        result[0..4].copy_from_slice(&pt[0].to_le_bytes());
        result[4..8].copy_from_slice(&pt[1].to_le_bytes());
        result
    }
}

const fn rotate_right(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

const fn rotate_left(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

#[must_use]
pub fn encrypt(plaintext: [u32; 2], key: &[u32; 4]) -> [u32; 2] {
    let cipher = Speck64::new(&key[..3]).unwrap();
    cipher.encrypt_block(plaintext)
}

#[must_use]
pub fn decrypt(ciphertext: [u32; 2], key: &[u32; 4]) -> [u32; 2] {
    let cipher = Speck64::new(&key[..3]).unwrap();
    cipher.decrypt_block(ciphertext)
}

pub mod modes {
    use super::Speck64;

    pub fn encrypt_ecb(cipher: &Speck64, plaintext: &[u8], ciphertext: &mut [u8]) {
        let blocks = plaintext.len() / 8;
        for i in 0..blocks {
            let encrypted = cipher.encrypt_bytes(plaintext[i * 8..(i + 1) * 8].try_into().unwrap());
            ciphertext[i * 8..(i + 1) * 8].copy_from_slice(&encrypted);
        }
    }

    pub fn decrypt_ecb(cipher: &Speck64, ciphertext: &[u8], plaintext: &mut [u8]) {
        let blocks = ciphertext.len() / 8;
        for i in 0..blocks {
            let decrypted =
                cipher.decrypt_bytes(ciphertext[i * 8..(i + 1) * 8].try_into().unwrap());
            plaintext[i * 8..(i + 1) * 8].copy_from_slice(&decrypted);
        }
    }

    pub fn encrypt_cbc(cipher: &Speck64, plaintext: &[u8], ciphertext: &mut [u8], mut iv: [u8; 8]) {
        let blocks = plaintext.len() / 8;
        for i in 0..blocks {
            let mut block: [u8; 8] = plaintext[i * 8..(i + 1) * 8].try_into().unwrap();
            for j in 0..8 {
                block[j] ^= iv[j];
            }
            let encrypted = cipher.encrypt_bytes(block);
            ciphertext[i * 8..(i + 1) * 8].copy_from_slice(&encrypted);
            iv = encrypted;
        }
    }

    pub fn decrypt_cbc(cipher: &Speck64, ciphertext: &[u8], plaintext: &mut [u8], mut iv: [u8; 8]) {
        let blocks = ciphertext.len() / 8;
        for i in 0..blocks {
            let block: [u8; 8] = ciphertext[i * 8..(i + 1) * 8].try_into().unwrap();
            let decrypted = cipher.decrypt_bytes(block);
            for j in 0..8 {
                plaintext[i * 8 + j] = decrypted[j] ^ iv[j];
            }
            iv = block;
        }
    }

    pub fn encrypt_ctr(cipher: &Speck64, plaintext: &[u8], ciphertext: &mut [u8], nonce: [u8; 8]) {
        let mut counter = u64::from_le_bytes(nonce);
        let full_blocks = plaintext.len() / 8;
        let remainder = plaintext.len() % 8;

        for i in 0..full_blocks {
            let counter_bytes = counter.to_le_bytes();
            let keystream = cipher.encrypt_bytes(counter_bytes);
            for j in 0..8 {
                ciphertext[i * 8 + j] = plaintext[i * 8 + j] ^ keystream[j];
            }
            counter = counter.wrapping_add(1);
        }

        if remainder > 0 {
            let counter_bytes = counter.to_le_bytes();
            let keystream = cipher.encrypt_bytes(counter_bytes);
            for j in 0..remainder {
                ciphertext[full_blocks * 8 + j] = plaintext[full_blocks * 8 + j] ^ keystream[j];
            }
        }
    }

    pub fn decrypt_ctr(cipher: &Speck64, ciphertext: &[u8], plaintext: &mut [u8], nonce: [u8; 8]) {
        encrypt_ctr(cipher, ciphertext, plaintext, nonce);
    }
}

pub mod test_vectors {
    use super::Speck64;

    #[must_use]
    pub fn run_tests() -> bool {
        let mut failed = 0;

        // Test SPECK64/96 roundtrip (2 key words)
        let cipher = Speck64::new(&[0x0302_0100, 0x0b0a_0908]).unwrap();
        for pt0 in 0u32..5u32 {
            for pt1 in 0u32..5u32 {
                let pt = [pt0, pt1];
                let ct = cipher.encrypt_block(pt);
                let decrypted = cipher.decrypt_block(ct);
                if decrypted != pt {
                    failed += 1;
                }
            }
        }

        // Test SPECK64/128 roundtrip (3 key words)
        let cipher = Speck64::new(&[0x0302_0100, 0x0b0a_0908, 0x1312_1110]).unwrap();
        for pt0 in 0u32..5u32 {
            for pt1 in 0u32..5u32 {
                let pt = [pt0, pt1];
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
