//! Child key creation, load, and blob serialization round-trips.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{Hierarchy, KeyAlg, KeyBlob, Template};

#[test]
fn create_and_load_child() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let key = dev
        .create_and_load(&srk, &Template::signing(KeyAlg::EccP256).unwrap(), None)
        .unwrap();
    assert_ne!(key.handle(), 0);
}

#[test]
fn key_blob_roundtrip_then_load() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();

    let blob = dev
        .create_key(&srk, &Template::signing(KeyAlg::EccP256).unwrap(), None)
        .unwrap();
    let bytes = blob.to_bytes().unwrap();
    assert!(!bytes.is_empty(), "serialized blob should be non-empty");

    let restored = KeyBlob::from_bytes(&dev, &bytes).unwrap();
    let key = restored.load(&srk, None).unwrap();
    assert_ne!(key.handle(), 0, "reloaded key should have a live handle");
}

#[test]
fn key_blob_roundtrip_preserves_short_auth() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();

    // A short auth is zero-padded to the nameAlg digest size when the TPM
    // stores it, so load must restore it the same way for an authorized
    // operation on the reloaded key to succeed.
    let blob = dev
        .create_key(&srk, &Template::signing(KeyAlg::EccP256).unwrap(), Some(b"pw"))
        .unwrap();
    let bytes = blob.to_bytes().unwrap();
    let restored = KeyBlob::from_bytes(&dev, &bytes).unwrap();
    let key = restored.load(&srk, Some(b"pw")).unwrap();
    let sig = key.sign_hash(&[0x44u8; 32]).unwrap();
    assert!(!sig.is_empty(), "authorized sign on a reloaded short-auth key must succeed");
}

#[test]
fn auth_protected_parent_loads_child() {
    let dev = common::open();
    let auth: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, Some(auth))
        .unwrap();
    let child = dev
        .create_and_load(&srk, &Template::signing(KeyAlg::EccP256).unwrap(), None)
        .unwrap();
    assert_ne!(child.handle(), 0, "child under an auth-protected parent must load");
}
