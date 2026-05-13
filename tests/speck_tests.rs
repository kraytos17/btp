use btp::speck::{Speck64, kat_bigendian, modes, test_vectors};

#[test]
fn speck_kat() {
    let passed = test_vectors::run_tests();
    assert!(passed, "SPECK KAT tests failed");
}

#[test]
fn speck_kat_bigendian() {
    let passed = kat_bigendian::run_kat_tests();
    assert!(passed, "SPECK big-endian KAT tests failed");
}

#[test]
fn speck_64_96_roundtrip() {
    let key = [0x0302_0100u32, 0x0b0a_0908, 0x1312_1110];
    let cipher = Speck64::new(&key).unwrap();
    let plaintext = [0x7461_4620u32, 0x736e_6165];
    let ciphertext = cipher.encrypt_block(plaintext);
    let decrypted = cipher.decrypt_block(ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn speck_64_128_roundtrip() {
    let key = [0x0302_0100u32, 0x0b0a_0908, 0x1312_1110];
    let cipher = Speck64::new(&key).unwrap();
    let plaintext = [0x7461_4620u32, 0x736e_6165];
    let ciphertext = cipher.encrypt_block(plaintext);
    let decrypted = cipher.decrypt_block(ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn speck_ctr_mode() {
    let key = [0x0302_0100u32, 0x0b0a_0908, 0x1312_1110];
    let cipher = Speck64::new(&key).unwrap();
    let nonce = [0x00u8; 8];
    let plaintext = [0x00u8; 16];
    let mut ciphertext = [0u8; 16];
    modes::encrypt_ctr(&cipher, &plaintext, &mut ciphertext, nonce);
    assert_ne!(ciphertext, plaintext);
}
