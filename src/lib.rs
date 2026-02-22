#![cfg_attr(not(feature = "std"), no_std)]

pub mod ascon;
pub mod present;
pub mod speck;

#[cfg(not(feature = "std"))]
pub mod benchmark;

#[cfg(feature = "std")]
pub mod host_tests {
    use crate::ascon::{AsconAead, AsconHash};
    use crate::present::Present;
    use crate::speck::Speck64;

    pub fn run_all_tests() {
        println!("=== Running Host Tests ===\n");

        test_present();
        test_speck();
        test_ascon();

        println!("\n=== All Tests Passed ===");
    }

    fn test_present() {
        println!("Testing PRESENT cipher...");

        // Test PRESENT-80
        let key80 = [0x00u8; 10];
        let cipher = Present::new(&key80).unwrap();
        let plaintext = [0x00u8; 8];
        let ciphertext = cipher.encrypt_block(plaintext);
        let decrypted = cipher.decrypt_block(ciphertext);
        assert_eq!(plaintext, decrypted, "PRESENT-80 encrypt/decrypt mismatch");
        println!("  PRESENT-80: OK");

        // Test PRESENT-128
        let key128 = [0x00u8; 16];
        let cipher = Present::new(&key128).unwrap();
        let ciphertext = cipher.encrypt_block(plaintext);
        let decrypted = cipher.decrypt_block(ciphertext);
        assert_eq!(plaintext, decrypted, "PRESENT-128 encrypt/decrypt mismatch");
        println!("  PRESENT-128: OK");

        // Test test vectors
        assert!(
            crate::present::test_vectors::run_tests(),
            "PRESENT test vectors failed"
        );
        println!("  Test vectors: OK");
    }

    fn test_speck() {
        println!("\nTesting SPECK cipher...");

        // Test SPECK64/96
        let key96 = [0x0302_0100u32, 0x0b0a_0908, 0x1312_1110];
        let cipher = Speck64::new(&key96).unwrap();
        let plaintext = [0x7461_4620u32, 0x736e_6165];
        let ciphertext = cipher.encrypt_block(plaintext);
        let decrypted = cipher.decrypt_block(ciphertext);
        assert_eq!(plaintext, decrypted, "SPECK64/96 encrypt/decrypt mismatch");
        println!("  SPECK64/96: OK");

        // Test SPECK64/128
        let key128 = [0x0302_0100u32, 0x0b0a_0908, 0x1312_1110, 0x1b1a_1918];
        let cipher = Speck64::new(&key128[..3]).unwrap();
        let ciphertext = cipher.encrypt_block(plaintext);
        let decrypted = cipher.decrypt_block(ciphertext);
        assert_eq!(plaintext, decrypted, "SPECK64/128 encrypt/decrypt mismatch");
        println!("  SPECK64/128: OK");

        // Test test vectors
        assert!(
            crate::speck::test_vectors::run_tests(),
            "SPECK test vectors failed"
        );
        println!("  Test vectors: OK");
    }

    fn test_ascon() {
        println!("\nTesting ASCON AEAD...");

        let key = [0x00u8; 16];
        let nonce = [0x00u8; 16];
        let plaintext = [0x00u8; 16];
        let ad = [0x00u8; 8];

        // Test encrypt/decrypt roundtrip
        let mut cipher = AsconAead::new(&key, &nonce);
        cipher.absorb_ad(&ad);
        let mut ciphertext = [0u8; 16];
        cipher.encrypt_in_place(&plaintext, &mut ciphertext);
        let tag = cipher.finalize(&key);

        // Verify we can decrypt
        let ct_with_tag = {
            let mut arr = [0u8; 32];
            arr[..16].copy_from_slice(&ciphertext);
            arr[16..].copy_from_slice(&tag);
            arr
        };
        let decrypted = crate::ascon::decrypt_aead(&key, &nonce, &ct_with_tag, &ad);
        assert!(decrypted.is_some(), "ASCON decryption failed");
        assert_eq!(
            decrypted.unwrap()[..plaintext.len()],
            plaintext,
            "ASCON plaintext mismatch"
        );
        println!("  ASCON-128 encrypt/decrypt: OK");

        // Test hash
        let mut hasher = AsconHash::new();
        hasher.absorb(b"test message");
        let hash = hasher.finalize();
        assert_ne!(hash, [0u8; 32], "ASCON hash should not be all zeros");
        println!("  ASCON-Hash: OK");

        // Test test vectors
        assert!(
            crate::ascon::test_vectors::run_tests(),
            "ASCON test vectors failed"
        );
        println!("  Test vectors: OK");
    }

    pub fn benchmark_host() {
        use std::time::Instant;

        println!("\n=== Host Benchmarks ===\n");

        // PRESENT-80 benchmark
        let cipher = Present::new(&[0u8; 10]).unwrap();
        let pt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let start = Instant::now();
        for _ in 0..100_000 {
            let _ = cipher.encrypt_block(pt);
        }
        let elapsed = start.elapsed();
        let ns_per_block = elapsed.as_nanos() / 100_000;
        println!("PRESENT-80: {} ns/block", ns_per_block);

        // SPECK benchmark
        let cipher = Speck64::new(&[0x0302_0100u32, 0x0b0a_0908, 0x1312_1110]).unwrap();
        let pt = [0x7461_4620u32, 0x736e_6165];
        let start = Instant::now();
        for _ in 0..100_000 {
            let _ = cipher.encrypt_block(pt);
        }
        let elapsed = start.elapsed();
        let ns_per_block = elapsed.as_nanos() / 100_000;
        println!("SPECK64/128: {} ns/block", ns_per_block);

        // ASCON benchmark
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let pt = [0u8; 16];
        let ad = [0u8; 8];
        let start = Instant::now();
        for _ in 0..10_000 {
            let _ = crate::ascon::encrypt_aead(&key, &nonce, &pt, &ad);
        }
        let elapsed = start.elapsed();
        let ns_per_encrypt = elapsed.as_nanos() / 10_000;
        println!("ASCON-128: {} ns/encrypt", ns_per_encrypt);
    }
}

#[cfg(feature = "std")]
pub use host_tests::run_all_tests;

#[cfg(feature = "std")]
pub use host_tests::benchmark_host;
