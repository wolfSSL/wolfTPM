//! Sign / verify round-trip and a tamper-rejection negative test.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{Hierarchy, KeyAlg, Template};

fn ecc_signing_key(dev: &wolftpm::Device) -> wolftpm::Key<'_> {
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    // Once loaded, the child is independent of the parent, so the SRK is free
    // to be flushed when it drops at the end of this function.
    dev.create_and_load(&srk, &Template::signing(KeyAlg::EccP256).unwrap(), None)
        .unwrap()
}

#[test]
fn sign_then_verify() {
    let dev = common::open();
    let key = ecc_signing_key(&dev);
    let digest = [0x11u8; 32];
    let sig = key.sign_hash(&digest).unwrap();
    assert!(!sig.is_empty());
    key.verify_hash(&digest, &sig).expect("valid signature verifies");
}

#[test]
fn verify_rejects_tampered_signature() {
    let dev = common::open();
    let key = ecc_signing_key(&dev);
    let digest = [0x22u8; 32];
    let mut sig = key.sign_hash(&digest).unwrap();
    sig[0] ^= 0xFF;
    assert!(
        key.verify_hash(&digest, &sig).is_err(),
        "tampered signature must not verify"
    );
}
