//! Safe Rust bindings for [wolfTPM](https://github.com/wolfSSL/wolfTPM), the
//! portable TPM 2.0 library.
//!
//! The raw FFI lives in [`sys`]; everything else wraps it in a safe API that
//! turns TPM return codes into [`Result`], manages device and key handle
//! lifetimes with RAII, and keeps all `unsafe` confined to this crate.
//!
//! Backend availability (swtpm socket, fwTPM HAL, sealing, NV, RNG, …) is
//! detected from the linked C library at build time via `cfg` flags emitted by
//! `build.rs`, so the surface reflects how libwolftpm was actually configured.
//!
//! # Safety
//!
//! `Device` boxes its `WOLFTPM2_DEV` in an `UnsafeCell` so it is heap-pinned
//! and self-referential-safe; `Device::ptr()` is therefore a stable pointer
//! for the whole `Device` lifetime, and every wolfTPM2 C call in this crate
//! takes it. `Key`/`KeyBlob` borrow `&Device` and hold their own
//! `UnsafeCell`-wrapped, pinned C struct plus the dev pointer, so their
//! `kptr()`/`handle_ptr()` accessors are likewise stable for as long as the
//! borrow lives. C structs passed to FFI are zero-initialized with
//! `core::mem::zeroed()` first — valid for these C plain-old-data types — and
//! then filled by the callee; buffer copies into fixed C arrays are bounds-
//! checked beforehand so they cannot overflow. Union fields are read only
//! after the code that set the matching selector (an `is_ecc`/scheme flag) ran
//! immediately before. `zeroize_raw` and volatile-write scrubbing always
//! operate on a live, correctly-sized, exclusively-owned local.

pub mod sys;

#[cfg(wrapper)]
mod device;
#[cfg(wrapper)]
mod key;
#[cfg(wrapper)]
mod sign;
#[cfg(all(wrapper, seal))]
mod seal;
#[cfg(all(wrapper, nv))]
mod nv;
#[cfg(all(wrapper, pcr))]
mod pcr;
#[cfg(wrapper)]
mod certify;
#[cfg(all(wrapper, rsa))]
mod rsa;
#[cfg(all(wrapper, persist))]
mod persist;
#[cfg(all(wrapper, hmac))]
mod hmac;
#[cfg(wrapper)]
mod session;
#[cfg(all(wrapper, caps))]
mod caps;
#[cfg(all(wrapper, symmetric))]
mod symmetric;
#[cfg(all(wrapper, ecdh))]
mod ecdh;
#[cfg(all(wrapper, ek_policy))]
mod credential;

#[cfg(wrapper)]
pub use device::Device;
#[cfg(wrapper)]
pub use session::Session;
#[cfg(wrapper)]
pub use key::{HashAlg, Hierarchy, Key, KeyAlg, KeyBlob, Template};
#[cfg(all(wrapper, nv))]
pub use nv::NvSlot;
#[cfg(wrapper)]
pub use certify::Attestation;
#[cfg(all(wrapper, caps))]
pub use caps::Caps;
#[cfg(all(wrapper, ecdh))]
pub use ecdh::EcdhResult;
#[cfg(all(wrapper, ek_policy))]
pub use credential::Credential;

use core::fmt;
use std::os::raw::c_int;

/// A wolfTPM operation that failed, carrying the raw TPM return code.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmError(pub c_int);

impl TpmError {
    /// The raw TPM/wolfTPM return code (`TPM_RC_*` / wolfCrypt error).
    pub fn code(&self) -> c_int {
        self.0
    }
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            E_DEVICE_IN_USE => return write!(f, "another wolfTPM Device is already open"),
            E_SESSION_IN_USE => {
                return write!(f, "an encrypted session is active and conflicts with this operation")
            }
            BUFFER_E => return write!(f, "buffer size error (BUFFER_E)"),
            _ => {}
        }
        #[cfg(rc_string)]
        {
            // TPM2_GetRCString returns a static, NUL-terminated string.
            // SAFETY: self.0 is a plain integer return code; TPM2_GetRCString has no pointer preconditions.
            let p = unsafe { sys::TPM2_GetRCString(self.0) };
            if !p.is_null() {
                // SAFETY: p was just checked non-null and points at TPM2_GetRCString's static NUL-terminated string.
                let s = unsafe { std::ffi::CStr::from_ptr(p) };
                return write!(f, "{} (0x{:x})", s.to_string_lossy(), self.0);
            }
        }
        write!(f, "TPM error 0x{:x}", self.0)
    }
}

impl fmt::Debug for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TpmError(0x{:x})", self.0)
    }
}

impl std::error::Error for TpmError {}

/// Result of a wolfTPM operation.
pub type Result<T> = core::result::Result<T, TpmError>;

/// An owned secret byte buffer that scrubs its heap allocation when dropped.
///
/// Returned by operations that recover plaintext or key material (unseal, RSA
/// decrypt, ECDH, credential activation) so the secret does not linger in
/// reusable process memory. Deref gives read-only slice access.
pub struct Secret(Vec<u8>);

impl Secret {
    pub(crate) fn new(v: Vec<u8>) -> Self {
        Secret(v)
    }

    /// The secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::ops::Deref for Secret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            // SAFETY: b is a valid &mut u8 into the live Vec; the volatile write scrubs the secret byte from the compiler's view.
            unsafe { core::ptr::write_volatile(b, 0u8) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Turn a wolfTPM C return code into a [`Result`]. `TPM_RC_SUCCESS` is 0.
#[inline]
pub(crate) fn check_rc(rc: c_int) -> Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(TpmError(rc))
    }
}

/// Narrow a slice length to the C `word32` a wolfTPM API expects, rejecting a
/// value too large to represent rather than letting it wrap to a small count.
#[inline]
pub(crate) fn checked_u32(n: usize) -> Result<u32> {
    u32::try_from(n).map_err(|_| TpmError(BUFFER_E))
}

/// Narrow a slice length to the C `int` a wolfTPM API expects, rejecting a
/// value too large to represent (which would wrap to a negative count).
#[inline]
pub(crate) fn checked_c_int(n: usize) -> Result<c_int> {
    i32::try_from(n).map_err(|_| TpmError(BUFFER_E))
}

/// wolfCrypt `BUFFER_E`, used when a caller-supplied buffer is the wrong size.
pub(crate) const BUFFER_E: c_int = -132;

/// Sentinel: another `Device` is already open. wolfTPM routes commands through a
/// single active context, so only one live `Device` is supported at a time.
pub(crate) const E_DEVICE_IN_USE: c_int = -900;

/// Sentinel: an encrypted [`Session`] is active. Only one is allowed at a time,
/// and the attestation commands are refused while one holds the auth slot.
pub(crate) const E_SESSION_IN_USE: c_int = -901;

/// Zeroize an arbitrary FFI struct by raw bytes.
///
/// `Drop` impls that hold secret material scrub the backing bytes with volatile
/// writes so the compiler cannot elide them (the Rust equivalent of wolfSSL's
/// `ForceZero`).
#[inline]
#[allow(dead_code)] /* used by the sealed-secret modules landing next */
pub(crate) unsafe fn zeroize_raw<T>(v: &mut T) {
    let p = v as *mut T as *mut u8;
    let n = core::mem::size_of::<T>();
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(p.add(i), 0u8);
        i += 1;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
