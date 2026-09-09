//! Keyed-hash HMAC computed inside the TPM.

use crate::device::Device;
use crate::key::{HashAlg, Key};
use crate::{check_rc, sys, Result, TpmError};

impl<'d> Key<'d> {
    /// Compute HMAC over `data` using this loaded keyed-hash key, whose secret
    /// stays inside the TPM. `hash` must match the algorithm the key was
    /// created with (see [`Template::hmac`](crate::Template::hmac)).
    ///
    /// This is the one-shot `TPM2_HMAC`, so `data` must fit the TPM's max
    /// command buffer; larger inputs are rejected rather than truncated.
    #[cfg(keyedhash)]
    pub fn hmac(&self, data: &[u8], hash: HashAlg) -> Result<Vec<u8>> {
        // SAFETY: HMAC_In is a C POD struct; all-zero is a valid starting state, and the length check above bounds the copy into cin.buffer.buffer.
        let mut cin: sys::HMAC_In = unsafe { core::mem::zeroed() };
        if data.len() > cin.buffer.buffer.len() {
            return Err(TpmError(crate::BUFFER_E));
        }
        // SAFETY: self.dev() is live and self.handle_ptr() addresses this Key's own pinned handle.
        unsafe { sys::wolfTPM2_SetAuthHandle(self.dev(), 0, self.handle_ptr()) };
        cin.handle = self.handle();
        cin.hashAlg = hash.alg_id() as sys::TPMI_ALG_HASH;
        cin.buffer.size = data.len() as u16;
        cin.buffer.buffer[..data.len()].copy_from_slice(data);

        // SAFETY: HMAC_Out is a C POD struct; all-zero is a valid starting state for TPM2_HMAC to fill.
        let mut cout: sys::HMAC_Out = unsafe { core::mem::zeroed() };
        // SAFETY: &mut cin/&mut cout are valid, exclusively-borrowed in/out-params for TPM2_HMAC.
        let rc = unsafe { sys::TPM2_HMAC(&mut cin, &mut cout) };
        // SAFETY: self.dev() is live; clear the auth slot and scrub the message
        // copy left in cin, regardless of the HMAC outcome.
        unsafe {
            sys::wolfTPM2_UnsetAuth(self.dev(), 0);
            crate::zeroize_raw(&mut cin);
        }
        check_rc(rc)?;
        let n = cout.outHMAC.size as usize;
        Ok(cout.outHMAC.buffer[..n].to_vec())
    }
}

impl Device {
    /// Compute an HMAC over `data` using `key` as the HMAC key. The keyed-hash
    /// object is created under `parent` (a loaded storage key such as the SRK)
    /// and freed before returning.
    pub fn hmac(
        &self,
        parent: &Key<'_>,
        key: &[u8],
        data: &[u8],
        hash: HashAlg,
    ) -> Result<Vec<u8>> {
        let key_len = crate::checked_u32(key.len())?;
        let data_len = crate::checked_u32(data.len())?;
        // SAFETY: WOLFTPM2_HMAC is a C POD struct; all-zero is a valid starting state for HmacStart to fill.
        let mut ctx: sys::WOLFTPM2_HMAC = unsafe { core::mem::zeroed() };
        // SAFETY: self.ptr()/parent.handle_ptr() are live, &mut ctx is a valid out-param, and key ptr+len bound its slice (data label is null/0, unused here).
        let rc = unsafe {
            sys::wolfTPM2_HmacStart(
                self.ptr(),
                &mut ctx,
                parent.handle_ptr(),
                hash.alg_id(),
                key.as_ptr(),
                key_len,
                core::ptr::null(),
                0,
            )
        };
        check_rc(rc)?;

        // SAFETY: ctx was just initialized by HmacStart above, and data ptr+len bound its slice.
        let rc_update = unsafe {
            sys::wolfTPM2_HmacUpdate(self.ptr(), &mut ctx, data.as_ptr(), data_len)
        };

        let mut out = vec![0u8; 64];
        let mut out_sz = out.len() as sys::word32;
        // SAFETY: ctx is still the live HMAC context, and out.as_mut_ptr()/&mut out_sz describe the full out capacity.
        let rc_finish =
            unsafe { sys::wolfTPM2_HmacFinish(self.ptr(), &mut ctx, out.as_mut_ptr(), &mut out_sz) };

        // Free the transient keyed-hash key if the finish left it loaded.
        if ctx.key.handle.hndl != 0 {
            // SAFETY: self.ptr() is live and &mut ctx.key.handle addresses the transient key HmacFinish left loaded.
            unsafe { sys::wolfTPM2_UnloadHandle(self.ptr(), &mut ctx.key.handle) };
        }

        check_rc(rc_update)?;
        check_rc(rc_finish)?;
        out.truncate(out_sz as usize);
        Ok(out)
    }
}
