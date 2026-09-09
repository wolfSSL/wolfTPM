//! The TPM connection: [`Device`] owns a `WOLFTPM2_DEV` and the transport to
//! the TPM (real hardware, the Linux kernel driver, or a software TPM over the
//! swtpm socket).

use crate::key::{Hierarchy, Key, KeyAlg};
use crate::{check_rc, sys, Result, TpmError, E_DEVICE_IN_USE};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// wolfTPM routes every command through a single active context that
/// `wolfTPM2_Init` overwrites, so only one live `Device` is supported at a time.
static DEVICE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// An initialized wolfTPM device.
///
/// `WOLFTPM2_DEV` holds a self-referential pointer (`spdmCtx -> spdmCtxData`),
/// so it must never move once initialized: it lives boxed on the heap. The
/// `UnsafeCell` reflects that every TPM command mutates the device through the
/// C pointer, which lets key handles borrow the device immutably and coexist.
pub struct Device {
    dev: Box<UnsafeCell<sys::WOLFTPM2_DEV>>,
}

impl Device {
    /// Open using a transport that needs no HAL callback: the swtpm socket, the
    /// Linux kernel device (including its autodetect variant), MMIO, or the
    /// Windows TBS, as selected when the C library was built. Hardware SPI/I2C
    /// HAL builds (including `WOLFTPM_AUTODETECT` over SPI/I2C) require a
    /// caller-provided callback and are not opened by this method.
    #[cfg(any(swtpm, devtpm, mmio, winapi, linux_autodetect))]
    pub fn open() -> Result<Self> {
        Self::init_with(None)
    }

    /// Open using a caller-supplied HAL I/O callback, for the SPI/I2C (and other
    /// callback-based) transports that [`open`](Device::open) does not cover.
    ///
    /// # Safety
    ///
    /// `io_cb` must be a valid wolfTPM HAL callback for the linked transport,
    /// and anything it dereferences (its user context) must remain valid for the
    /// whole lifetime of the returned `Device`.
    pub unsafe fn open_with_io_cb(io_cb: sys::TPM2HalIoCb) -> Result<Self> {
        Self::init_with(io_cb)
    }

    /// Open a software TPM over the swtpm/mssim socket.
    ///
    /// The endpoint comes from the `TPM2_SWTPM_HOST` / `TPM2_SWTPM_PORT`
    /// environment the C backend reads with `getenv` (default `localhost:2321`).
    /// Because that is process-global, set it once at startup before opening,
    /// rather than per connection.
    #[cfg(swtpm)]
    pub fn open_swtpm() -> Result<Self> {
        Self::init_with(None)
    }

    /// Acquire the single-live-`Device` lease, or fail if one is already held.
    fn acquire() -> Result<()> {
        if DEVICE_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(TpmError(E_DEVICE_IN_USE));
        }
        Ok(())
    }

    fn init_with(io_cb: sys::TPM2HalIoCb) -> Result<Self> {
        Self::acquire()?;
        Self::init_held(io_cb)
    }

    /// Initialize with the lease already held; releases it on failure.
    fn init_held(io_cb: sys::TPM2HalIoCb) -> Result<Self> {
        // SAFETY: WOLFTPM2_DEV is a C POD struct; all-zero is a valid state for wolfTPM2_Init to fill in.
        let dev: Box<UnsafeCell<sys::WOLFTPM2_DEV>> =
            Box::new(UnsafeCell::new(unsafe { core::mem::zeroed() }));
        // SAFETY: dev is heap-boxed and not yet moved again, so dev.get() is a stable pointer for Init to populate.
        let rc = unsafe { sys::wolfTPM2_Init(dev.get(), io_cb, core::ptr::null_mut()) };
        if rc != 0 {
            // Tear down any active context wolfTPM installed (for example on
            // TPM_RC_UPGRADE) before the box is freed, then release the slot.
            // SAFETY: dev.get() still points at the live, boxed WOLFTPM2_DEV Init partially set up.
            unsafe { sys::wolfTPM2_Cleanup(dev.get()) };
            DEVICE_ACTIVE.store(false, Ordering::Release);
            return Err(TpmError(rc));
        }
        Ok(Device { dev })
    }

    /// The raw device pointer for FFI. Stable for the life of the `Device`.
    pub(crate) fn ptr(&self) -> *mut sys::WOLFTPM2_DEV {
        self.dev.get()
    }

    /// Fill `buf` with TPM-generated random bytes.
    #[cfg(rng)]
    pub fn get_random(&self, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let n = crate::checked_u32(buf.len())?;
        // SAFETY: self.ptr() is the pinned dev pointer and buf.as_mut_ptr()/len describe a live, in-bounds slice.
        let rc = unsafe { sys::wolfTPM2_GetRandom(self.ptr(), buf.as_mut_ptr(), n) };
        check_rc(rc)
    }

    /// Create a primary key (a storage root key by default) under `hierarchy`.
    /// `auth` sets the new object's own authorization value, not the
    /// hierarchy's.
    ///
    /// The hierarchy itself is assumed to be unauthenticated (empty owner /
    /// endorsement / platform auth), which is the device-identity case and
    /// matches the underlying `wolfTPM2_CreatePrimaryKey`, which issues the
    /// command with a blank hierarchy authorization. Provisioned TPMs that have
    /// set a non-empty hierarchy authorization are not supported by this call.
    pub fn create_primary(
        &self,
        hierarchy: Hierarchy,
        alg: KeyAlg,
        auth: Option<&[u8]>,
    ) -> Result<Key<'_>> {
        Key::create_primary(self, hierarchy, alg, auth)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: the Device is being dropped, so self.dev.get() is still the valid, uniquely-owned dev pointer.
        unsafe { sys::wolfTPM2_Cleanup(self.dev.get()) };
        DEVICE_ACTIVE.store(false, Ordering::Release);
    }
}
