//! Endorsement key creation and public-key export.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::KeyAlg;

#[test]
fn create_ek_and_export_public() {
    let dev = common::open();
    let ek = dev.create_ek(KeyAlg::EccP256).unwrap();
    assert_ne!(ek.handle(), 0, "EK should have a live handle");

    let der = ek.export_public(false).unwrap();
    assert!(!der.is_empty(), "exported DER public key should be non-empty");
}
