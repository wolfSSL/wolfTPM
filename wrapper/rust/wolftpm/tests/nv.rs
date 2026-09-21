//! NV storage write/read round-trip and delete.
#![cfg(feature = "swtpm-tests")]

mod common;

#[test]
fn nv_write_read_delete() {
    let dev = common::open();
    let index: u32 = 0x0150_0100;

    // Clean any leftover from a prior run so the define succeeds.
    let _ = dev.nv_delete(index);

    let mut slot = dev.nv_create(index, 32, None).unwrap();
    assert_eq!(slot.index(), index);

    let data = b"root-of-trust-metadata";
    dev.nv_write(&mut slot, data, 0).unwrap();

    let mut buf = [0u8; 32];
    let n = dev.nv_read(&mut slot, &mut buf, 0).unwrap();
    assert_eq!(n, 32);
    assert_eq!(&buf[..data.len()], data, "NV read must return what was written");

    dev.nv_delete(index).unwrap();
}
