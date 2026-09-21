//! PCR quote attestation.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{HashAlg, Hierarchy, KeyAlg, Template};

#[test]
fn quote_ecc_aik() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let aik = dev
        .create_and_load(&srk, &Template::attestation(KeyAlg::EccP256).unwrap(), None)
        .unwrap();

    let quote = dev.quote(&aik, &[16], HashAlg::Sha256, b"verifier-nonce").unwrap();
    assert!(!quote.attest.is_empty(), "quote must carry the signed PCR digest");
    assert_ne!(quote.sig_alg, 0, "signature algorithm must be set");
    assert_eq!(
        quote.signature.len(),
        64,
        "an ECDSA P-256 signature must be a fixed 64-byte R||S"
    );
}

#[test]
fn quote_rsa_aik() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let aik = dev
        .create_and_load(&srk, &Template::attestation(KeyAlg::Rsa).unwrap(), None)
        .unwrap();

    let quote = dev.quote(&aik, &[16], HashAlg::Sha256, b"verifier-nonce").unwrap();
    assert!(!quote.attest.is_empty());
    assert!(!quote.signature.is_empty(), "RSA signature must be returned");
}

#[test]
fn quote_rejects_invalid_pcr_selection() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let aik = dev
        .create_and_load(&srk, &Template::attestation(KeyAlg::EccP256).unwrap(), None)
        .unwrap();
    assert!(
        dev.quote(&aik, &[], HashAlg::Sha256, b"n").is_err(),
        "empty PCR selection must be rejected"
    );
    assert!(
        dev.quote(&aik, &[99], HashAlg::Sha256, b"n").is_err(),
        "out-of-range PCR must be rejected"
    );
}
