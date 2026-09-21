//! Attestation: an AIK certifies a key object.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{Hierarchy, KeyAlg, Template};

fn certify_with(aik_alg: KeyAlg) {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();

    let object = dev
        .create_and_load(&srk, &Template::signing(KeyAlg::EccP256).unwrap(), None)
        .unwrap();
    let aik = dev
        .create_and_load(&srk, &Template::attestation(aik_alg).unwrap(), None)
        .unwrap();

    let att = dev.certify(&object, &aik, b"verifier-nonce-1234").unwrap();
    assert!(!att.attest.is_empty(), "attestation data must be non-empty");
    assert!(!att.signature.is_empty(), "signature must be returned");
    assert_ne!(att.sig_alg, 0, "signature algorithm must be set");
}

#[test]
fn certify_with_ecc_aik() {
    certify_with(KeyAlg::EccP256);
}

#[test]
fn certify_with_rsa_aik() {
    certify_with(KeyAlg::Rsa);
}
