//! Parameter-encryption session.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{Hierarchy, KeyAlg};

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

    // GetRandom's response is also encrypted while the session is live.
    let mut buf = [0u8; 32];
    dev.get_random(&mut buf).unwrap();
    assert_ne!(buf, [0u8; 32]);
    drop(session);
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
fn attestation_refused_during_session() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let _session = dev.start_encrypted_session(&srk).unwrap();
    // certify needs the auth slot the session holds, so it is refused rather
    // than silently displacing the session (which would leave later commands
    // unencrypted). srk stands in for both handles; the guard fires first.
    assert!(
        dev.certify(&srk, &srk, b"nonce").is_err(),
        "certify must be refused while an encrypted session is active"
    );
}
