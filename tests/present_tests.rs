use btp::present::{Present, modes, test_vectors};

#[test]
fn present_aead_kat() {
    let passed = test_vectors::run_tests();
    assert!(passed, "PRESENT KAT tests failed");
}

#[test]
fn present_80_roundtrip() {
    let key = [0x00u8; 10];
    let cipher = Present::new(&key).unwrap();
    let plaintext = [0x00u8; 8];
    let ciphertext = cipher.encrypt_block(plaintext);
    let decrypted = cipher.decrypt_block(ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn present_128_roundtrip() {
    let key = [0x00u8; 16];
    let cipher = Present::new(&key).unwrap();
    let plaintext = [0x00u8; 8];
    let ciphertext = cipher.encrypt_block(plaintext);
    let decrypted = cipher.decrypt_block(ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn present_ecb_mode() {
    let key = [0x00u8; 10];
    let cipher = Present::new(&key).unwrap();
    let plaintext = [0x00u8; 16];
    let mut ciphertext = [0u8; 16];
    modes::encrypt_ecb(&cipher, &plaintext, &mut ciphertext);
    assert_ne!(ciphertext, plaintext);
}
