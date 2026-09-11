//! Integration smoke test against a software TPM (swtpm/fwtpm/ibmswtpm2).
//!
//! Needs a server on `TPM2_SWTPM_HOST:TPM2_SWTPM_PORT` (default localhost:2321),
//! so it is gated behind the `swtpm-tests` feature.
#![cfg(feature = "swtpm-tests")]

use wolftpm::{Device, Hierarchy, KeyAlg};

#[test]
fn random_and_primary_keys() {
    let dev = Device::open_swtpm().expect("open swtpm (is a TPM server on :2321?)");

    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    dev.get_random(&mut a).expect("get_random a");
    dev.get_random(&mut b).expect("get_random b");
    assert_ne!(a, b, "two random draws should differ");

    let ecc = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .expect("create ECC SRK");
    assert_ne!(ecc.handle(), 0, "SRK should have a live handle");

    let rsa = dev
        .create_primary(Hierarchy::Owner, KeyAlg::Rsa, None)
        .expect("create RSA SRK");
    assert_ne!(rsa.handle(), 0);
}
