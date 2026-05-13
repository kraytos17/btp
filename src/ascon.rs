#![allow(dead_code)]

const ROUNDS_A: usize = 12;
const ROUNDS_B: usize = 6;
const ROUNDS_B_128A: usize = 8;

const IV_128: u64 = 0x0000_0800_806C_0001;
const IV_128A: u64 = 0x0000_1000_808C_0001;
const IV_80PQ: u64 = 0x0000_0000_806C_0800;
const IV_HASH: u64 = 0x0000_0801_00CC_0002;

const DSEP: u64 = 0x8000_0000_0000_0000;

#[inline]
const fn rotl(x: u64, n: u32) -> u64 {
    x.rotate_left(n)
}

const ROUND_CONSTANTS: [u64; 12] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
];

#[inline]
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

#[inline]
const fn p_linear(s0: u64, s1: u64, s2: u64, s3: u64, s4: u64) -> (u64, u64, u64, u64, u64) {
    let s0 = s0 ^ rotl(s0, 19) ^ rotl(s0, 28);
    let s1 = s1 ^ rotl(s1, 61) ^ rotl(s1, 39);
    let s2 = s2 ^ rotl(s2, 1) ^ rotl(s2, 6);
    let s3 = s3 ^ rotl(s3, 10) ^ rotl(s3, 17);
    let s4 = s4 ^ rotl(s4, 7) ^ rotl(s4, 41);

    (s0, s1, s2, s3, s4)
}

#[inline]
const fn permutation_round(state: &mut [u64; 5], rc: u64) {
    state[2] ^= rc;
    let (s0, s1, s2, s3, s4) = p_sbox(state[0], state[1], state[2], state[3], state[4]);
    let (s0, s1, s2, s3, s4) = p_linear(s0, s1, s2, s3, s4);

    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
    state[3] = s3;
    state[4] = s4;
}

#[inline]
const fn permutation_12(state: &mut [u64; 5]) {
    permutation_round(state, ROUND_CONSTANTS[0]);
    permutation_round(state, ROUND_CONSTANTS[1]);
    permutation_round(state, ROUND_CONSTANTS[2]);
    permutation_round(state, ROUND_CONSTANTS[3]);
    permutation_round(state, ROUND_CONSTANTS[4]);
    permutation_round(state, ROUND_CONSTANTS[5]);
    permutation_round(state, ROUND_CONSTANTS[6]);
    permutation_round(state, ROUND_CONSTANTS[7]);
    permutation_round(state, ROUND_CONSTANTS[8]);
    permutation_round(state, ROUND_CONSTANTS[9]);
    permutation_round(state, ROUND_CONSTANTS[10]);
    permutation_round(state, ROUND_CONSTANTS[11]);
}

#[inline]
const fn permutation_8(state: &mut [u64; 5]) {
    permutation_round(state, ROUND_CONSTANTS[4]);
    permutation_round(state, ROUND_CONSTANTS[5]);
    permutation_round(state, ROUND_CONSTANTS[6]);
    permutation_round(state, ROUND_CONSTANTS[7]);
    permutation_round(state, ROUND_CONSTANTS[8]);
    permutation_round(state, ROUND_CONSTANTS[9]);
    permutation_round(state, ROUND_CONSTANTS[10]);
    permutation_round(state, ROUND_CONSTANTS[11]);
}

#[inline]
const fn permutation_6(state: &mut [u64; 5]) {
    permutation_round(state, ROUND_CONSTANTS[6]);
    permutation_round(state, ROUND_CONSTANTS[7]);
    permutation_round(state, ROUND_CONSTANTS[8]);
    permutation_round(state, ROUND_CONSTANTS[9]);
    permutation_round(state, ROUND_CONSTANTS[10]);
    permutation_round(state, ROUND_CONSTANTS[11]);
}

#[inline]
fn permutation(state: &mut [u64; 5], rounds: usize) {
    match rounds {
        12 => permutation_12(state),
        8 => permutation_8(state),
        6 => permutation_6(state),
        _ => {
            let start = 12 - rounds;
            for i in 0..rounds {
                permutation_round(state, ROUND_CONSTANTS[start + i]);
            }
        }
    }
}

#[inline]
fn store_u64(x: u64, bytes: &mut [u8]) {
    let arr = x.to_le_bytes();
    let len = bytes.len().min(8);
    bytes[..len].copy_from_slice(&arr[..len]);
}

#[inline]
const fn store_u64_full(x: u64, bytes: &mut [u8; 8]) {
    *bytes = x.to_le_bytes();
}

#[inline]
fn load_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

#[derive(Clone, Copy, Debug)]
pub enum AsconVariant {
    Ascon128,
    Ascon128a,
    Ascon80pq,
}

#[derive(Clone)]
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
        let k0 = load_u64(&key[0..8]);
        let k1 = load_u64(&key[8..16]);
        let n0 = load_u64(&nonce[0..8]);
        let n1 = load_u64(&nonce[8..16]);

        let iv = match variant {
            AsconVariant::Ascon128 => IV_128,
            AsconVariant::Ascon128a => IV_128A,
            AsconVariant::Ascon80pq => IV_80PQ,
        };

        let mut state = [iv, k0, k1, n0, n1];

        permutation_12(&mut state);

        state[3] ^= k0;
        state[4] ^= k1;

        Self { state, variant }
    }

    pub fn absorb_ad(&mut self, ad: &[u8]) {
        match self.variant {
            AsconVariant::Ascon128 | AsconVariant::Ascon80pq => self.absorb_ad_rate8(ad),
            AsconVariant::Ascon128a => self.absorb_ad_rate16(ad),
        }
    }

    fn absorb_ad_rate16(&mut self, ad: &[u8]) {
        let mut i = 0;
        while i + 16 <= ad.len() {
            self.state[0] ^= load_u64(&ad[i..i + 8]);
            self.state[1] ^= load_u64(&ad[i + 8..i + 16]);
            permutation_8(&mut self.state);
            i += 16;
        }
        if i < ad.len() {
            let len = ad.len() - i;
            if len < 8 {
                let mut block = [0u8; 8];
                block[..len].copy_from_slice(&ad[i..]);
                block[len] = 0x01;
                self.state[0] ^= load_u64(&block);
            } else {
                self.state[0] ^= load_u64(&ad[i..i + 8]);
                let rem2 = len - 8;
                if rem2 > 0 {
                    let mut block = [0u8; 8];
                    block[..rem2].copy_from_slice(&ad[i + 8..]);
                    block[rem2] = 0x01;
                    self.state[1] ^= load_u64(&block);
                } else {
                    self.state[1] ^= 0x01;
                }
            }
            permutation_8(&mut self.state);
        }
        self.state[4] ^= DSEP;
    }

    fn absorb_ad_rate8(&mut self, ad: &[u8]) {
        let mut i = 0;
        while i + 8 <= ad.len() {
            self.state[0] ^= load_u64(&ad[i..i + 8]);
            permutation_8(&mut self.state);
            i += 8;
        }
        if i < ad.len() {
            let remaining = ad.len() - i;
            let mut block = [0u8; 8];
            block[..remaining].copy_from_slice(&ad[i..]);
            block[remaining] = 0x01;
            self.state[0] ^= load_u64(&block);
            permutation_8(&mut self.state);
        }
        self.state[4] ^= DSEP;
    }

    pub fn encrypt_in_place(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        match self.variant {
            AsconVariant::Ascon128 | AsconVariant::Ascon80pq => {
                self.encrypt_rate8(plaintext, ciphertext);
            }
            AsconVariant::Ascon128a => self.encrypt_rate16(plaintext, ciphertext),
        }
    }

    fn encrypt_rate16(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        let mut i = 0;
        while i + 16 <= plaintext.len() {
            let p0 = load_u64(&plaintext[i..i + 8]);
            let p1 = load_u64(&plaintext[i + 8..i + 16]);
            let c0 = self.state[0] ^ p0;
            let c1 = self.state[1] ^ p1;
            store_u64_full(c0, (&mut ciphertext[i..i + 8]).try_into().unwrap());
            store_u64_full(c1, (&mut ciphertext[i + 8..i + 16]).try_into().unwrap());
            self.state[0] = c0;
            self.state[1] = c1;
            permutation_8(&mut self.state);
            i += 16;
        }
        if i < plaintext.len() {
            self.encrypt_partial_16(&plaintext[i..], &mut ciphertext[i..]);
        }
    }

    fn encrypt_rate8(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= plaintext.len() {
            let p = load_u64(&plaintext[i..i + 8]);
            let c = self.state[0] ^ p;
            store_u64_full(c, (&mut ciphertext[i..i + 8]).try_into().unwrap());
            self.state[0] = c;
            permutation_8(&mut self.state);
            i += 8;
        }
        if i < plaintext.len() {
            let remaining = plaintext.len() - i;
            let mut block = [0u8; 8];
            block[..remaining].copy_from_slice(&plaintext[i..i + remaining]);
            block[remaining] = 0x01;
            let p = load_u64(&block);
            self.state[0] ^= p;
            let c = self.state[0];
            store_u64(c, &mut ciphertext[i..i + remaining]);
            self.state[0] = c;
        }
    }

    fn encrypt_partial_16(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        let len = plaintext.len();
        if len < 8 {
            let mut block = [0u8; 8];
            block[..len].copy_from_slice(plaintext);
            block[len] = 0x01;
            let p0 = load_u64(&block);
            self.state[0] ^= p0;
            let c0 = self.state[0];
            store_u64(c0, &mut ciphertext[..len]);
            self.state[0] = c0;
        } else {
            self.state[0] ^= load_u64(&plaintext[..8]);
            let c0 = self.state[0];
            store_u64_full(c0, (&mut ciphertext[..8]).try_into().unwrap());
            self.state[0] = c0;

            let rem2 = len - 8;
            if rem2 > 0 {
                let mut block = [0u8; 8];
                block[..rem2].copy_from_slice(&plaintext[8..]);
                block[rem2] = 0x01;
                let p1 = load_u64(&block);
                self.state[1] ^= p1;
                let c1 = self.state[1];
                store_u64(c1, &mut ciphertext[8..len]);
            } else {
                self.state[1] ^= 0x01;
            }
        }
    }

    pub fn decrypt_in_place(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
        match self.variant {
            AsconVariant::Ascon128 | AsconVariant::Ascon80pq => {
                self.decrypt_rate8(ciphertext, plaintext);
            }
            AsconVariant::Ascon128a => self.decrypt_rate16(ciphertext, plaintext),
        }
    }

    fn decrypt_rate16(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
        let mut i = 0;
        while i + 16 <= ciphertext.len() {
            let c0 = load_u64(&ciphertext[i..i + 8]);
            let c1 = load_u64(&ciphertext[i + 8..i + 16]);
            let p0 = self.state[0] ^ c0;
            let p1 = self.state[1] ^ c1;
            store_u64_full(p0, (&mut plaintext[i..i + 8]).try_into().unwrap());
            store_u64_full(p1, (&mut plaintext[i + 8..i + 16]).try_into().unwrap());
            self.state[0] = c0;
            self.state[1] = c1;
            permutation_8(&mut self.state);
            i += 16;
        }
        if i < ciphertext.len() {
            self.decrypt_partial_16(&ciphertext[i..], &mut plaintext[i..]);
        }
    }

    fn decrypt_rate8(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= ciphertext.len() {
            let c = load_u64(&ciphertext[i..i + 8]);
            let p = self.state[0] ^ c;
            store_u64_full(p, (&mut plaintext[i..i + 8]).try_into().unwrap());
            self.state[0] = c;
            permutation_8(&mut self.state);
            i += 8;
        }
        if i < ciphertext.len() {
            let remaining = ciphertext.len() - i;
            let mut block = [0u8; 8];
            block[..remaining].copy_from_slice(&ciphertext[i..i + remaining]);
            block[remaining] = 0x01;
            let cx = load_u64(&block);
            self.state[0] ^= cx;
            let p = self.state[0];
            store_u64(p, &mut plaintext[i..i + remaining]);
            // Mask preserves upper bytes of state before XOR
            // Then OR with ciphertext bytes to match encryption pattern
            let mask = 0xFFFF_FFFF_FFFF_FFFFu64 >> (8 * remaining);
            self.state[0] = (self.state[0] & !mask) ^ cx;
        }
    }

    fn decrypt_partial_16(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
        let len = ciphertext.len();
        if len < 8 {
            let mut block = [0u8; 8];
            block[..len].copy_from_slice(ciphertext);
            block[len] = 0x01;
            let cx = load_u64(&block);
            self.state[0] ^= cx;
            let p = self.state[0];
            store_u64(p, &mut plaintext[..len]);
            let mask = 0xFFFF_FFFF_FFFF_FFFFu64 >> (8 * len);
            self.state[0] = (self.state[0] & !mask) ^ cx;
        } else {
            let cx0 = load_u64(&ciphertext[..8]);
            self.state[0] ^= cx0;
            let p0 = self.state[0];
            store_u64_full(p0, (&mut plaintext[..8]).try_into().unwrap());
            self.state[0] = cx0;

            let rem2 = len - 8;
            if rem2 > 0 {
                let mut block = [0u8; 8];
                block[..rem2].copy_from_slice(&ciphertext[8..8 + rem2]);
                block[rem2] = 0x01;
                let cx1 = load_u64(&block);
                self.state[1] ^= cx1;
                let p1 = self.state[1];
                store_u64(p1, &mut plaintext[8..len]);
                let mask = 0xFFFF_FFFF_FFFF_FFFFu64 >> (8 * rem2);
                self.state[1] = (self.state[1] & !mask) ^ cx1;
            } else {
                self.state[1] ^= 0x01;
            }
        }
    }

    #[must_use]
    pub fn finalize(mut self, key: &[u8; 16]) -> [u8; 16] {
        let k0 = load_u64(&key[0..8]);
        let k1 = load_u64(&key[8..16]);

        self.state[2] ^= k0;
        self.state[3] ^= k1;
        permutation_12(&mut self.state);
        self.state[3] ^= k0;
        self.state[4] ^= k1;

        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&self.state[3].to_le_bytes());
        tag[8..16].copy_from_slice(&self.state[4].to_le_bytes());
        tag
    }
}

pub struct AsconHash {
    state: [u64; 5],
}

impl AsconHash {
    #[must_use]
    pub const fn new() -> Self {
        let mut state = [IV_HASH, 0, 0, 0, 0];
        permutation_12(&mut state);
        Self { state }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        let mut i = 0;
        while i + 8 <= data.len() {
            self.state[0] ^= load_u64(&data[i..i + 8]);
            permutation_12(&mut self.state);
            i += 8;
        }
        if i < data.len() {
            let mut block = [0u8; 8];
            block[..data.len() - i].copy_from_slice(&data[i..]);
            block[data.len() - i] = 0x01;
            self.state[0] ^= load_u64(&block);
            permutation_12(&mut self.state);
        }
    }

    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        let mut hash = [0u8; 32];

        // First squeeze (8 bytes from S0)
        hash[0..8].copy_from_slice(&self.state[0].to_le_bytes());

        // Remaining 3 squeezes with permutations
        let mut offset = 8;
        while offset < 32 {
            permutation_12(&mut self.state);
            let remaining = 32 - offset;
            let n = remaining.min(8);
            hash[offset..offset + n].copy_from_slice(&self.state[0].to_le_bytes()[..n]);
            offset += n;
        }
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

    if diff == 0 { Some(plaintext) } else { None }
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

    if diff == 0 { Some(ct_len) } else { None }
}

pub mod test_vectors {
    extern crate alloc;
    use super::{AsconAead, AsconHash, decrypt_aead};

    #[must_use]
    pub fn run_tests() -> bool {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        let nonce: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];

        let plaintext: [u8; 16] = [
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let ad: [u8; 0] = [];
        let mut cipher = AsconAead::new(&key, &nonce);
        cipher.absorb_ad(&ad);

        let mut ct = [0u8; 16];
        cipher.encrypt_in_place(&plaintext, &mut ct);
        let tag = cipher.finalize(&key);

        let mut ct_with_tag = [0u8; 32];
        ct_with_tag[..16].copy_from_slice(&ct);
        ct_with_tag[16..].copy_from_slice(&tag);

        let result = decrypt_aead(&key, &nonce, &ct_with_tag, &ad);

        assert!(result.is_some(), "AEAD decrypt failed");
        assert_eq!(result.unwrap(), plaintext, "AEAD plaintext mismatch");

        let mut hash = AsconHash::new();
        hash.absorb(b"test");
        let hash_output = hash.finalize();

        assert!(hash_output != [0u8; 32], "Hash should not be all zeros");

        true
    }
}

pub mod kat_hash_vectors;
pub mod kat_hash_vectors_embedded;
pub mod kat_vectors;
pub mod kat_vectors_embedded;

#[cfg(feature = "std")]
pub mod kat_tests {
    extern crate alloc;
    use super::{AsconAead, AsconVariant};
    use crate::ascon::kat_vectors::AsconKatVector;

    #[must_use]
    pub fn run_kat_vector(vector: &AsconKatVector) -> bool {
        let mut cipher =
            AsconAead::with_variant(&vector.key, &vector.nonce, AsconVariant::Ascon128a);
        cipher.absorb_ad(&vector.ad);

        let mut ciphertext = alloc::vec![0u8; vector.pt.len()];
        cipher.encrypt_in_place(&vector.pt, &mut ciphertext);

        let tag = cipher.finalize(&vector.key);

        let mut actual_output = ciphertext;
        actual_output.extend_from_slice(&tag);

        if actual_output != vector.ct {
            eprintln!("MISMATCH for vector {}", vector.count);
            eprintln!("  PT len: {}, AD len: {}", vector.pt.len(), vector.ad.len());
            eprintln!("  Expected CT: {:02X?}", vector.ct);
            eprintln!("  Actual CT:   {actual_output:02X?}");
            return false;
        }

        true
    }

    #[must_use]
    pub fn run_all_kat() -> (usize, usize) {
        let vectors = crate::ascon::kat_vectors::load_kat_vectors();
        let total = vectors.len();
        let mut passed = 0;
        for v in &vectors {
            if run_kat_vector(v) {
                passed += 1;
            }
        }

        (passed, total)
    }
}
