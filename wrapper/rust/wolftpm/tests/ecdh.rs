//! ECDH key agreement.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{Hierarchy, KeyAlg, Template};

#[test]
fn ecdh_gen_then_z_agree() {
    let dev = common::open();
    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    let key = dev
        .create_and_load(&srk, &Template::ecdh().unwrap(), None)
        .unwrap();

    // One-shot ephemeral ECDH yields an ephemeral point and secret Z; feeding
    // that point back through this key's private part must recover the same Z.
    let gen = key.ecdh_gen().unwrap();
    assert!(!gen.point.is_empty());
    assert!(!gen.secret.is_empty());

    let z = key.ecdh_z(&gen.point).unwrap();
    assert_eq!(
        gen.secret.as_bytes(),
        z.as_bytes(),
        "ECDHGenZ must recover the same shared secret as ECDHGen"
    );
}
