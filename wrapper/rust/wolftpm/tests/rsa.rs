//! RSA-OAEP encrypt and decrypt round-trip.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{HashAlg, Hierarchy, KeyAlg, Template};

#[test]
fn rsa_oaep_roundtrip() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let key = dev
        .create_and_load(&srk, &Template::rsa_decrypt().unwrap(), None)
        .unwrap();

    let msg = b"session key material";
    let ciphertext = key.rsa_encrypt(msg).unwrap();
    assert_ne!(ciphertext.as_slice(), &msg[..], "ciphertext must differ from plaintext");

    let recovered = key.rsa_decrypt(&ciphertext).unwrap();
    assert_eq!(recovered.as_bytes(), &msg[..], "decrypt must recover the plaintext");
}

#[test]
fn rsa_oaep_sha1_roundtrip() {
    // Microsoft device enrollment (MS-OAPXBC) wraps its session key with
    // OAEP-SHA1, so the explicit-hash variant must round-trip with SHA-1.
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let key = dev
        .create_and_load(&srk, &Template::rsa_decrypt().unwrap(), None)
        .unwrap();

    let msg = b"ms enrollment session key";
    let ciphertext = key.rsa_encrypt_with_hash(msg, HashAlg::Sha1).unwrap();
    let recovered = key.rsa_decrypt_with_hash(&ciphertext, HashAlg::Sha1).unwrap();
    assert_eq!(recovered.as_bytes(), &msg[..], "OAEP-SHA1 decrypt must recover the plaintext");
}
