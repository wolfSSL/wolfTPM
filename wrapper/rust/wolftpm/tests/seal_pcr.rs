//! PCR-policy sealing: measured-boot-bound seal and unseal.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{HashAlg, Hierarchy, KeyAlg};

#[test]
fn pcr_bound_seal_roundtrip() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let pcrs = [16u8];

    let sealed = dev.seal_pcr(&srk, b"pcr-bound secret", &pcrs).unwrap();
    let out = dev.unseal_pcr(sealed, &srk, &pcrs).unwrap();
    assert_eq!(out.as_bytes(), &b"pcr-bound secret"[..], "unseal must recover the secret");
}

#[test]
fn pcr_change_breaks_unseal() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let pcrs = [23u8]; // a debug PCR distinct from other tests

    let sealed = dev.seal_pcr(&srk, b"bound to pcr23", &pcrs).unwrap();
    dev.pcr_extend(23, HashAlg::Sha256, &[0xFFu8; 32]).unwrap();

    assert!(
        dev.unseal_pcr(sealed, &srk, &pcrs).is_err(),
        "unseal must fail once the bound PCR has changed"
    );
}

#[test]
fn seal_pcr_rejects_invalid_selection() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    assert!(
        dev.seal_pcr(&srk, b"x", &[]).is_err(),
        "an empty PCR selection must be rejected, not bound to nothing"
    );
    assert!(
        dev.seal_pcr(&srk, b"x", &[255]).is_err(),
        "an out-of-range PCR index must be rejected"
    );
}
