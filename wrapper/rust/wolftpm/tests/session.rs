//! Parameter-encryption session.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{HashAlg, Hierarchy, KeyAlg, Template};

#[test]
fn secret_ops_under_encrypted_session() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();

    // With the session at slot 1, seal (command param) and unseal (response
    // param) travel encrypted; both must still round-trip correctly.
    let session = dev.start_encrypted_session(&srk).unwrap();
    let sealed = dev.seal(&srk, b"secret-under-session", None).unwrap();
    let out = dev.unseal(sealed, &srk, None).unwrap();
    assert_eq!(out.as_bytes(), &b"secret-under-session"[..]);

    drop(session);
}

#[test]
fn quote_allowed_during_session() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let aik = dev
        .create_and_load(&srk, &Template::attestation(KeyAlg::EccP256).unwrap(), None)
        .unwrap();
    let _session = dev.start_encrypted_session(&srk).unwrap();

    let quote = dev
        .quote(&aik, &[16], HashAlg::Sha256, b"verifier-nonce")
        .unwrap();
    assert!(!quote.attest.is_empty());
    assert!(!quote.signature.is_empty());
}

#[test]
fn second_session_rejected() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let _s1 = dev.start_encrypted_session(&srk).unwrap();
    assert!(
        dev.start_encrypted_session(&srk).is_err(),
        "a second concurrent encrypted session must be rejected"
    );
}

#[test]
fn two_auth_attestation_refused_during_session() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let _session = dev.start_encrypted_session(&srk).unwrap();
    // Certify needs two object-authorization slots, including the slot the
    // encryption session holds. srk stands in for both handles; the guard fires
    // before the command is submitted.
    assert!(
        dev.certify(&srk, &srk, b"nonce").is_err(),
        "certify must be refused while an encrypted session is active"
    );
}
