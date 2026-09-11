//! PCR (Platform Configuration Register) read and extend — the measured-boot /
//! attestation primitives.

use crate::device::Device;
use crate::key::HashAlg;
use crate::{check_rc, sys, Result, TpmError};
use core::ffi::c_int;

impl Device {
    /// Read the current value of PCR `index` in the given hash bank.
    pub fn pcr_read(&self, index: u32, hash: HashAlg) -> Result<Vec<u8>> {
        let mut digest = vec![0u8; 64];
        let mut len = digest.len() as c_int;
        // SAFETY: self.ptr() is live and digest.as_mut_ptr()/&mut len describe the full digest Vec capacity.
        let rc = unsafe {
            sys::wolfTPM2_ReadPCR(
                self.ptr(),
                index as c_int,
                hash.as_c_int(),
                digest.as_mut_ptr(),
                &mut len,
            )
        };
        check_rc(rc)?;
        digest.truncate(len as usize);
        Ok(digest)
    }

    /// Extend PCR `index` in the given hash bank with `digest`, which must be
    /// exactly the bank's digest length (32/48/64 bytes for SHA-256/384/512).
    pub fn pcr_extend(&self, index: u32, hash: HashAlg, digest: &[u8]) -> Result<()> {
        if digest.len() != hash.digest_size() {
            return Err(TpmError(crate::BUFFER_E));
        }
        // SAFETY: self.ptr() is live and digest ptr+len bound the slice, already checked above to match the bank's digest size.
        let rc = unsafe {
            sys::wolfTPM2_ExtendPCR(
                self.ptr(),
                index as c_int,
                hash.as_c_int(),
                digest.as_ptr(),
                digest.len() as c_int,
            )
        };
        check_rc(rc)
    }
}
