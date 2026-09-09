//! Seal/unseal round-trip and a wrong-auth negative test.
#![cfg(all(feature = "swtpm-tests"))]

mod common;

use wolftpm::{Hierarchy, KeyAlg};

#[test]
fn seal_unseal_roundtrip() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let secret = b"himmelblau-device-secret";
    let sealed = dev.seal(&srk, secret, None).unwrap();
    let out = dev.unseal(sealed, &srk, None).unwrap();
    assert_eq!(out.as_bytes(), &secret[..], "unsealed data must match the sealed secret");
}

#[test]
fn unseal_wrong_auth_fails() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let sealed = dev.seal(&srk, b"top secret", Some(b"correcthorse")).unwrap();
    assert!(
        dev.unseal(sealed, &srk, Some(b"wrongpass")).is_err(),
        "unseal with the wrong auth must fail"
    );
}
