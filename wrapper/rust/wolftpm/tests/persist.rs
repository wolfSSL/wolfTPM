//! Persistent key handles: store, read back, and evict.
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{Hierarchy, KeyAlg};

#[test]
fn persist_read_evict() {
    let dev = common::open();
    let handle: u32 = 0x8100_0200;

    // Clean up any leftover from a prior run.
    if let Ok(old) = dev.read_persistent(handle, None) {
        let _ = dev.evict_key(&old, Hierarchy::Owner);
    }

    let srk = dev
        .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
        .unwrap();
    dev.persist_key(&srk, Hierarchy::Owner, handle).unwrap();

    let readback = dev.read_persistent(handle, None).unwrap();
    assert_eq!(readback.handle(), handle, "key should live at the persistent handle");

    dev.evict_key(&readback, Hierarchy::Owner).unwrap();
    assert!(
        dev.read_persistent(handle, None).is_err(),
        "evicted key should no longer be readable"
    );
}
