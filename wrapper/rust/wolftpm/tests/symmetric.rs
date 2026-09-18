//! Symmetric AES-CFB encrypt/decrypt with a TPM key.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{Hierarchy, KeyAlg, Template};

#[test]
fn aes_cfb_roundtrip() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let key = dev
        .create_and_load(&srk, &Template::symmetric(256).unwrap(), None)
        .unwrap();

    let iv = [0u8; 16];
    let plaintext = b"symmetric plaintext, two blocks!";
    let ciphertext = key.aes_encrypt(plaintext, &iv).unwrap();
    assert_ne!(ciphertext.as_slice(), &plaintext[..], "ciphertext must differ");

    let recovered = key.aes_decrypt(&ciphertext, &iv).unwrap();
    assert_eq!(
        recovered.as_bytes(),
        &plaintext[..],
        "AES-CFB decrypt must recover the plaintext"
    );
}
