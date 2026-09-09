//! Raw FFI layer: bindgen output for wolfTPM's public headers.
//!
//! Generated at build time into `$OUT_DIR/bindings.rs`; never hand-edited.
//! Everything here is `unsafe` to call — the safe API lives in the sibling
//! modules.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(improper_ctypes)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
