use btp::ascon::{AsconAead, AsconHash, test_vectors};

#[test]
fn ascon_aead_kat() {
    let passed = test_vectors::run_tests();
    assert!(passed, "ASCON KAT tests failed");
}

#[test]
fn ascon_aead_roundtrip() {
    let key = [0x00u8; 16];
    let nonce = [0x00u8; 16];
    let plaintext = [0x00u8; 16];
    let ad = [0x00u8; 8];

    let mut cipher = AsconAead::new(&key, &nonce);
    cipher.absorb_ad(&ad);
    let mut ciphertext = [0u8; 16];
    cipher.encrypt_in_place(&plaintext, &mut ciphertext);
    let tag = cipher.finalize(&key);

    let ct_with_tag = {
        let mut arr = [0u8; 32];
        arr[..16].copy_from_slice(&ciphertext);
        arr[16..].copy_from_slice(&tag);
        arr
    };

    let decrypted = btp::ascon::decrypt_aead(&key, &nonce, &ct_with_tag, &ad);
    assert!(decrypted.is_some(), "ASCON decryption failed");
    assert_eq!(decrypted.unwrap()[..plaintext.len()], plaintext);
}

#[test]
fn ascon_hash_roundtrip() {
    let mut hasher = AsconHash::new();
    hasher.absorb(b"test message");
    let hash = hasher.finalize();
    assert_ne!(hash, [0u8; 32], "ASCON hash should not be all zeros");
}
