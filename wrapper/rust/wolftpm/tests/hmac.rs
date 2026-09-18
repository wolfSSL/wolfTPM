//! TPM keyed-hash HMAC.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{HashAlg, Hierarchy, KeyAlg, Template};

#[test]
fn hmac_deterministic_and_keyed() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();

    let a = dev.hmac(&srk, b"secret-key", b"message", HashAlg::Sha256).unwrap();
    let b = dev.hmac(&srk, b"secret-key", b"message", HashAlg::Sha256).unwrap();
    assert_eq!(a, b, "same key and data must give the same HMAC");
    assert_eq!(a.len(), 32);

    let c = dev.hmac(&srk, b"other-key", b"message", HashAlg::Sha256).unwrap();
    assert_ne!(a, c, "a different key must give a different HMAC");
}

#[test]
fn loaded_hmac_key_compute() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();

    // A TPM-generated keyed-hash key: the secret never leaves the TPM, we
    // compute HMAC on the loaded handle.
    let key = dev
        .create_and_load(&srk, &Template::hmac(HashAlg::Sha256).unwrap(), None)
        .unwrap();
    let m1 = key.hmac(b"message", HashAlg::Sha256).unwrap();
    let m2 = key.hmac(b"message", HashAlg::Sha256).unwrap();
    assert_eq!(m1, m2, "same loaded key and data must give the same HMAC");
    assert_eq!(m1.len(), 32);
    let m3 = key.hmac(b"different", HashAlg::Sha256).unwrap();
    assert_ne!(m1, m3, "different data must give a different HMAC");
}
