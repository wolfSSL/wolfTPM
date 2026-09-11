//! Signing and verification on a loaded [`Key`].

use crate::key::Key;
use crate::{check_rc, sys, Result};
use core::ffi::c_int;

impl<'d> Key<'d> {
    /// Sign a pre-computed `digest` with this key, returning the raw signature.
    ///
    /// The scheme/hash come from the key's template (e.g. ECDSA-SHA256 for a
    /// P-256 signing key), so `digest` must be the matching hash length.
    pub fn sign_hash(&self, digest: &[u8]) -> Result<Vec<u8>> {
        let digest_len = crate::checked_c_int(digest.len())?;
        let mut sig = vec![0u8; sys::MAX_RSA_KEY_BYTES as usize];
        let mut sig_sz = sig.len() as c_int;
        // SAFETY: self.dev()/self.kptr() are live, digest ptr+len bound its slice, and sig.as_mut_ptr()/sig_sz describe the full sig capacity.
        let rc = unsafe {
            sys::wolfTPM2_SignHash(
                self.dev(),
                self.kptr(),
                digest.as_ptr(),
                digest_len,
                sig.as_mut_ptr(),
                &mut sig_sz,
            )
        };
        // wolfTPM2_SignHash caches the key auth in the device's slot 0; clear it
        // so it does not linger in the live Device after this returns.
        // SAFETY: self.dev() is the live pinned device pointer.
        unsafe { sys::wolfTPM2_UnsetAuth(self.dev(), 0) };
        check_rc(rc)?;
        sig.truncate(sig_sz as usize);
        Ok(sig)
    }

    /// Verify `sig` over `digest` with this key.
    pub fn verify_hash(&self, digest: &[u8], sig: &[u8]) -> Result<()> {
        let sig_len = crate::checked_c_int(sig.len())?;
        let digest_len = crate::checked_c_int(digest.len())?;
        // SAFETY: self.dev()/self.kptr() are live, and sig/digest ptr+len each bound their own slice.
        let rc = unsafe {
            sys::wolfTPM2_VerifyHash(
                self.dev(),
                self.kptr(),
                sig.as_ptr(),
                sig_len,
                digest.as_ptr(),
                digest_len,
            )
        };
        check_rc(rc)
    }
}
