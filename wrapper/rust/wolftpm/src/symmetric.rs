//! Symmetric (AES-CFB) encrypt/decrypt with a TPM-resident key.

use crate::key::Key;
use crate::{check_rc, sys, Result, Secret};

impl<'d> Key<'d> {
    /// Encrypt `data` with this loaded AES key (see
    /// [`Template::symmetric`](crate::Template::symmetric)). `iv` is the CFB
    /// initialization vector (16 bytes for AES).
    pub fn aes_encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        self.aes(data, iv, 0)
    }

    /// Decrypt `data` produced by [`aes_encrypt`](Key::aes_encrypt) with the
    /// same key and `iv`. The recovered plaintext is returned in a zeroizing
    /// [`Secret`](crate::Secret).
    pub fn aes_decrypt(&self, data: &[u8], iv: &[u8]) -> Result<Secret> {
        Ok(Secret::new(self.aes(data, iv, 1)?))
    }

    fn aes(&self, data: &[u8], iv: &[u8], is_decrypt: core::ffi::c_int) -> Result<Vec<u8>> {
        // AES-CFB uses a full 16-byte block as the IV; reject any other length
        // rather than forwarding it to the C layer.
        if iv.len() != 16 {
            return Err(crate::TpmError(crate::BUFFER_E));
        }
        let data_len = crate::checked_u32(data.len())?;
        let mut out = vec![0u8; data.len()];
        let mut iv_buf = iv.to_vec();
        let iv_len = crate::checked_u32(iv_buf.len())?;
        // SAFETY: self.dev()/self.kptr() are live, data/out and iv_buf ptr+len each describe their own live buffer, out sized to data.len().
        let rc = unsafe {
            sys::wolfTPM2_EncryptDecrypt(
                self.dev(),
                self.kptr(),
                data.as_ptr(),
                out.as_mut_ptr(),
                data_len,
                iv_buf.as_mut_ptr(),
                iv_len,
                is_decrypt,
            )
        };
        if rc != 0 {
            // The C side decrypts in chunks, so a mid-stream failure can leave
            // partial plaintext in `out`; scrub it before discarding.
            for b in out.iter_mut() {
                unsafe { core::ptr::write_volatile(b, 0) };
            }
            check_rc(rc)?;
        }
        Ok(out)
    }
}
