//! PCR read and extend.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::HashAlg;

#[test]
fn pcr_extend_changes_digest() {
    let dev = common::open();
    let idx = 16; // debug PCR, safe to extend

    let before = dev.pcr_read(idx, HashAlg::Sha256).unwrap();
    assert_eq!(before.len(), 32);

    dev.pcr_extend(idx, HashAlg::Sha256, &[0xABu8; 32]).unwrap();

    let after = dev.pcr_read(idx, HashAlg::Sha256).unwrap();
    assert_eq!(after.len(), 32);
    assert_ne!(before, after, "extend must change the PCR value");
}
