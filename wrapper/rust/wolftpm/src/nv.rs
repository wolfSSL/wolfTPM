//! Non-volatile (NV) storage: define an index, write, read, delete. Useful for
//! persisting device-identity metadata / a machine-key handle.
//!
//! These operate under the owner hierarchy assuming it is unauthenticated
//! (empty owner auth), the device-identity case; the per-index `auth` protects
//! the index itself. TPMs with a non-empty owner-hierarchy authorization are
//! not supported here.

use crate::device::Device;
use crate::key::auth_ptr;
use crate::{check_rc, sys, Result};

/// A defined NV index. NV state persists in the TPM until [`Device::nv_delete`].
pub struct NvSlot<'d> {
    nv: sys::WOLFTPM2_NV,
    index: u32,
    _marker: core::marker::PhantomData<&'d Device>,
}

impl<'d> NvSlot<'d> {
    /// The NV index handle (in the `0x0100_0000`–`0x01FF_FFFF` range).
    pub fn index(&self) -> u32 {
        self.index
    }
}

fn owner_handle() -> sys::WOLFTPM2_HANDLE {
    // SAFETY: WOLFTPM2_HANDLE is a C POD struct; all-zero is a valid state before setting hndl below.
    let mut h: sys::WOLFTPM2_HANDLE = unsafe { core::mem::zeroed() };
    h.hndl = sys::TPM_RH_T_TPM_RH_OWNER as sys::TPM_HANDLE;
    h
}

impl Device {
    /// Define an NV index of `size` bytes under the owner hierarchy,
    /// auth-protected (auth/owner read+write).
    pub fn nv_create(&self, index: u32, size: u32, auth: Option<&[u8]>) -> Result<NvSlot<'_>> {
        let attrs = sys::TPMA_NV_AUTHREAD | sys::TPMA_NV_AUTHWRITE;
        // SAFETY: WOLFTPM2_NV is a C POD struct; all-zero is a valid starting state for NVCreateAuth to fill.
        let mut nv: sys::WOLFTPM2_NV = unsafe { core::mem::zeroed() };
        let mut parent = owner_handle();
        let (authp, authsz) = auth_ptr(auth)?;
        // SAFETY: self.ptr() is live, &mut parent/&mut nv are valid out-params, and authp/authsz match (auth's ptr, len) or (null, 0).
        let rc = unsafe {
            sys::wolfTPM2_NVCreateAuth(
                self.ptr(),
                &mut parent,
                &mut nv,
                index,
                attrs,
                size,
                authp,
                authsz,
            )
        };
        check_rc(rc)?;
        Ok(NvSlot {
            nv,
            index,
            _marker: core::marker::PhantomData,
        })
    }

    /// Write `data` to the NV index at `offset`.
    pub fn nv_write(&self, slot: &mut NvSlot<'_>, data: &[u8], offset: u32) -> Result<()> {
        let mut buf = data.to_vec();
        let n = crate::checked_u32(buf.len())?;
        // SAFETY: self.ptr() is live, &mut slot.nv is this slot's own state, and buf.as_mut_ptr()/len describe the live buf Vec.
        let rc = unsafe {
            sys::wolfTPM2_NVWriteAuth(
                self.ptr(),
                &mut slot.nv,
                slot.index,
                buf.as_mut_ptr(),
                n,
                offset,
            )
        };
        for b in buf.iter_mut() {
            // SAFETY: b is a valid &mut u8 into the live buf Vec; the volatile write scrubs the temporary copy.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        check_rc(rc)
    }

    /// Read up to `buf.len()` bytes from the NV index at `offset`, returning the
    /// number of bytes read.
    pub fn nv_read(&self, slot: &mut NvSlot<'_>, buf: &mut [u8], offset: u32) -> Result<usize> {
        let mut sz = crate::checked_u32(buf.len())?;
        // SAFETY: self.ptr() is live, &mut slot.nv is this slot's own state, and buf.as_mut_ptr()/&mut sz describe the full buf capacity.
        let rc = unsafe {
            sys::wolfTPM2_NVReadAuth(
                self.ptr(),
                &mut slot.nv,
                slot.index,
                buf.as_mut_ptr(),
                &mut sz,
                offset,
            )
        };
        check_rc(rc)?;
        Ok(sz as usize)
    }

    /// Undefine (delete) an NV index.
    pub fn nv_delete(&self, index: u32) -> Result<()> {
        let mut parent = owner_handle();
        // SAFETY: self.ptr() is live and &mut parent is a valid, exclusively-borrowed handle for NVDeleteAuth.
        let rc = unsafe { sys::wolfTPM2_NVDeleteAuth(self.ptr(), &mut parent, index) };
        check_rc(rc)
    }

    /// Read a certificate stored in an NV index, such as the manufacturer's EK
    /// certificate (RSA EK cert at `0x01C00002`, ECC at `0x01C0000A`). Returns
    /// the raw certificate (DER) bytes.
    #[cfg(nvcert)]
    pub fn read_cert(&self, nv_handle: u32) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        let mut len = buf.len() as u32;
        // SAFETY: self.ptr() is live and buf.as_mut_ptr()/&mut len describe the full buf Vec capacity.
        let rc =
            unsafe { sys::wolfTPM2_NVReadCert(self.ptr(), nv_handle, buf.as_mut_ptr(), &mut len) };
        check_rc(rc)?;
        buf.truncate(len as usize);
        Ok(buf)
    }
}

impl<'d> Drop for NvSlot<'d> {
    fn drop(&mut self) {
        // SAFETY: self.nv is a live, uniquely-owned field being scrubbed as the slot is dropped.
        unsafe { crate::zeroize_raw(&mut self.nv) };
    }
}
