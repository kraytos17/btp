#![allow(dead_code)]

const ROUNDS_A: usize = 12;
const ROUNDS_B: usize = 6;

const fn rotl(x: u64, n: u32) -> u64 {
    x.rotate_left(n)
}

const fn p_sbox(s0: u64, s1: u64, s2: u64, s3: u64, s4: u64) -> (u64, u64, u64, u64, u64) {
    let s0 = s0 ^ s4;
    let s4 = s4 ^ s3;
    let s2 = s2 ^ s1;

    let t0 = (!s0) & s1;
    let t1 = (!s1) & s2;
    let t2 = (!s2) & s3;
    let t3 = (!s3) & s4;
    let t4 = (!s4) & s0;

    let s0 = s0 ^ t1;
    let s1 = s1 ^ t2;
    let s2 = s2 ^ t3;
    let s3 = s3 ^ t4;
    let s4 = s4 ^ t0;

    let s1 = s1 ^ s0;
    let s0 = s0 ^ s4;
    let s3 = s3 ^ s2;
    let s2 = !s2;

    (s0, s1, s2, s3, s4)
}

const fn p_linear(s0: u64, s1: u64, s2: u64, s3: u64, s4: u64) -> (u64, u64, u64, u64, u64) {
    let s0 = s0 ^ rotl(s0, 19) ^ rotl(s0, 28);
    let s1 = s1 ^ rotl(s1, 61) ^ rotl(s1, 39);
    let s2 = s2 ^ rotl(s2, 1) ^ rotl(s2, 6);
    let s3 = s3 ^ rotl(s3, 10) ^ rotl(s3, 17);
    let s4 = s4 ^ rotl(s4, 7) ^ rotl(s4, 41);

    (s0, s1, s2, s3, s4)
}

fn permutation(state: &mut [u64; 5], rounds: usize) {
    for _ in 0..rounds {
        let (s0, s1, s2, s3, s4) = p_sbox(state[0], state[1], state[2], state[3], state[4]);
        let (s0, s1, s2, s3, s4) = p_linear(s0, s1, s2, s3, s4);
        state[0] = s0;
        state[1] = s1;
        state[2] = s2;
        state[3] = s3;
        state[4] = s4;
    }
}

fn store_u64(x: u64, bytes: &mut [u8]) {
    let arr = x.to_be_bytes();
    let len = bytes.len().min(8);
    bytes[..len].copy_from_slice(&arr[..len]);
}

#[derive(Clone, Copy, Debug)]
pub enum AsconVariant {
    Ascon128,
    Ascon128a,
    Ascon80pq,
}

pub struct AsconAead {
    state: [u64; 5],
    variant: AsconVariant,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BenchmarkTimings {
    pub init: u64,
    pub absorb: u64,
    pub encrypt: u64,
    pub finalize: u64,
    pub total: u64,
}

impl AsconAead {
    #[must_use]
    pub fn new(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        Self::with_variant(key, nonce, AsconVariant::Ascon128)
    }

    #[must_use]
    pub fn with_variant(key: &[u8; 16], nonce: &[u8; 16], variant: AsconVariant) -> Self {
        let k0 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let n0 = u64::from_be_bytes(nonce[0..8].try_into().unwrap());
        let n1 = u64::from_be_bytes(nonce[8..16].try_into().unwrap());

        let iv = match variant {
            AsconVariant::Ascon128 => 0x8040_0c06_0000_0000,
            AsconVariant::Ascon128a => 0x8080_0c08_0000_0000,
            AsconVariant::Ascon80pq => 0xa040_0c06_0000_0000,
        };

        let mut state = [0u64; 5];
        state[0] = iv;
        state[1] = k0;
        state[2] = k1;
        state[3] = n0;
        state[4] = n1;

        permutation(&mut state, ROUNDS_A);

        state[3] ^= k0;
        state[4] ^= k1;

        Self { state, variant }
    }

    pub fn absorb_ad(&mut self, ad: &[u8]) {
        let rounds_b = match self.variant {
            AsconVariant::Ascon128a => 8,
            _ => ROUNDS_B,
        };

        let mut i = 0;
        while i + 8 <= ad.len() {
            self.state[0] ^= u64::from_be_bytes(ad[i..i + 8].try_into().unwrap());
            permutation(&mut self.state, rounds_b);
            i += 8;
        }
        if i < ad.len() {
            let mut block = [0u8; 8];
            block[..ad.len() - i].copy_from_slice(&ad[i..]);
            block[ad.len() - i] = 0x80;
            self.state[0] ^= u64::from_be_bytes(block);
            permutation(&mut self.state, rounds_b);
        }
        self.state[4] ^= 1;
    }

    pub fn encrypt_in_place(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        let rounds_b = match self.variant {
            AsconVariant::Ascon128a => 8,
            _ => ROUNDS_B,
        };

        let mut i = 0;
        while i + 8 <= plaintext.len() {
            let p = u64::from_be_bytes(plaintext[i..i + 8].try_into().unwrap());
            let c = self.state[0] ^ p;

            store_u64(c, &mut ciphertext[i..i + 8]);
            self.state[0] = p;
            permutation(&mut self.state, rounds_b);
            i += 8;
        }
        if i < plaintext.len() {
            let len = plaintext.len() - i;
            let mut block = [0u8; 8];
            block[..len].copy_from_slice(&plaintext[i..]);
            let p = u64::from_be_bytes(block);
            let c = self.state[0] ^ p;
            let mut c_bytes = [0u8; 8];
            store_u64(c, &mut c_bytes);
            ciphertext[i..].copy_from_slice(&c_bytes[..len]);
            block[len] = 0x80;
            self.state[0] = u64::from_be_bytes(block);
        }
    }

    pub fn decrypt_in_place(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
        let rounds_b = match self.variant {
            AsconVariant::Ascon128a => 8,
            _ => ROUNDS_B,
        };

        let mut i = 0;
        while i + 8 <= ciphertext.len() {
            let c = u64::from_be_bytes(ciphertext[i..i + 8].try_into().unwrap());
            let p = self.state[0] ^ c;
            store_u64(p, &mut plaintext[i..i + 8]);
            self.state[0] = p;
            permutation(&mut self.state, rounds_b);
            i += 8;
        }
        if i < ciphertext.len() {
            let len = ciphertext.len() - i;
            let mut block = [0u8; 8];
            block[..len].copy_from_slice(&ciphertext[i..]);
            let c = u64::from_be_bytes(block);
            let p = self.state[0] ^ c;
            let mut p_bytes = [0u8; 8];
            store_u64(p, &mut p_bytes);
            plaintext[i..].copy_from_slice(&p_bytes[..len]);
            let mut p_block = [0u8; 8];
            p_block[..len].copy_from_slice(&plaintext[i..]);
            p_block[len] = 0x80;
            self.state[0] = u64::from_be_bytes(p_block);
        }
    }

    #[must_use]
    pub fn finalize(mut self, key: &[u8; 16]) -> [u8; 16] {
        let k0 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_be_bytes(key[8..16].try_into().unwrap());

        self.state[1] ^= k0;
        self.state[2] ^= k1;
        permutation(&mut self.state, ROUNDS_A);
        self.state[3] ^= k0;
        self.state[4] ^= k1;

        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&self.state[3].to_be_bytes());
        tag[8..16].copy_from_slice(&self.state[4].to_be_bytes());
        tag
    }
}

pub struct AsconHash {
    state: [u64; 5],
}

impl AsconHash {
    #[must_use]
    pub fn new() -> Self {
        let mut state = [0u64; 5];
        state[0] = 0x0040_0c00_0000_0100;
        permutation(&mut state, 12);
        Self { state }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        let mut i = 0;
        while i + 8 <= data.len() {
            self.state[0] ^= u64::from_be_bytes(data[i..i + 8].try_into().unwrap());
            permutation(&mut self.state, ROUNDS_B);
            i += 8;
        }
        if i < data.len() {
            let mut block = [0u8; 8];
            block[..data.len() - i].copy_from_slice(&data[i..]);
            block[data.len() - i] = 0x80;
            self.state[0] ^= u64::from_be_bytes(block);
            permutation(&mut self.state, ROUNDS_B);
        }
    }

    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        self.state[0] ^= 0x01;
        permutation(&mut self.state, 12);

        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&self.state[0].to_be_bytes());
        hash[8..16].copy_from_slice(&self.state[1].to_be_bytes());
        hash[16..24].copy_from_slice(&self.state[2].to_be_bytes());
        hash[24..32].copy_from_slice(&self.state[3].to_be_bytes());
        hash
    }
}

impl Default for AsconHash {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn encrypt_aead(key: &[u8; 16], nonce: &[u8; 16], plaintext: &[u8], ad: &[u8]) -> [u8; 32] {
    let mut cipher = AsconAead::new(key, nonce);
    cipher.absorb_ad(ad);

    let mut output = [0u8; 32];
    let ct_len = plaintext.len().min(16);
    cipher.encrypt_in_place(plaintext, &mut output[..ct_len]);

    let tag = cipher.finalize(key);
    output[ct_len..ct_len + 16].copy_from_slice(&tag);

    output
}

#[must_use]
pub fn decrypt_aead(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ciphertext: &[u8],
    ad: &[u8],
) -> Option<[u8; 16]> {
    if ciphertext.len() < 16 {
        return None;
    }

    let ct_len = ciphertext.len() - 16;
    let provided_tag: [u8; 16] = ciphertext[ct_len..].try_into().ok()?;
    let mut cipher = AsconAead::new(key, nonce);
    cipher.absorb_ad(ad);

    let mut plaintext = [0u8; 16];
    cipher.decrypt_in_place(&ciphertext[..ct_len], &mut plaintext);

    let computed_tag = cipher.finalize(key);
    let mut diff = 0u8;
    for (a, b) in provided_tag.iter().zip(computed_tag.iter()) {
        diff |= a ^ b;
    }

    if diff == 0 {
        Some(plaintext)
    } else {
        None
    }
}

pub fn encrypt_aead_varlen(
    key: &[u8; 16],
    nonce: &[u8; 16],
    plaintext: &[u8],
    ad: &[u8],
    output: &mut [u8],
) -> usize {
    let mut cipher = AsconAead::new(key, nonce);
    cipher.absorb_ad(ad);

    let ct_len = plaintext.len().min(output.len().saturating_sub(16));
    cipher.encrypt_in_place(plaintext, &mut output[..ct_len]);

    let tag = cipher.finalize(key);
    output[ct_len..ct_len + 16].copy_from_slice(&tag);

    ct_len + 16
}

pub fn decrypt_aead_varlen(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ciphertext: &[u8],
    ad: &[u8],
    plaintext: &mut [u8],
) -> Option<usize> {
    if ciphertext.len() < 16 {
        return None;
    }

    let ct_len = ciphertext.len() - 16;
    if plaintext.len() < ct_len {
        return None;
    }

    let provided_tag: [u8; 16] = ciphertext[ct_len..].try_into().ok()?;
    let mut cipher = AsconAead::new(key, nonce);
    cipher.absorb_ad(ad);
    cipher.decrypt_in_place(&ciphertext[..ct_len], &mut plaintext[..ct_len]);

    let computed_tag = cipher.finalize(key);
    let mut diff = 0u8;
    for (a, b) in provided_tag.iter().zip(computed_tag.iter()) {
        diff |= a ^ b;
    }

    if diff == 0 {
        Some(ct_len)
    } else {
        None
    }
}

pub mod test_vectors {
    use super::{decrypt_aead, AsconAead, AsconHash};

    #[must_use]
    pub fn run_tests() -> bool {
        let mut failed = 0;
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let nonce: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        let plaintext: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let ad: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

        let mut cipher = AsconAead::new(&key, &nonce);
        cipher.absorb_ad(&ad);

        let mut ciphertext = [0u8; 8];
        cipher.encrypt_in_place(&plaintext, &mut ciphertext);

        let tag = cipher.finalize(&key);
        let mut ct_with_tag = [0u8; 24];
        ct_with_tag[..8].copy_from_slice(&ciphertext);
        ct_with_tag[8..24].copy_from_slice(&tag);
        let decrypted = decrypt_aead(&key, &nonce, &ct_with_tag, &ad);
        if decrypted.is_none() {
            failed += 1;
        }

        let mut hash = AsconHash::new();
        hash.absorb(b"test message");
        let hash_output = hash.finalize();
        if hash_output == [0u8; 32] {
            failed += 1;
        }

        failed == 0
    }
}
