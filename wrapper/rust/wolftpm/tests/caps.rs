//! TPM self-test and capability query.
#![cfg(feature = "swtpm-tests")]

mod common;

#[test]
fn self_test_and_capabilities() {
    let dev = common::open();
    dev.self_test().unwrap();

    let caps = dev.capabilities().unwrap();
    assert!(
        !caps.manufacturer.is_empty(),
        "the TPM should report a manufacturer id"
    );
}
