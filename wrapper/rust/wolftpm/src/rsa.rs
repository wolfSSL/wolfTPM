//! RSA-OAEP encrypt and decrypt on a loaded RSA decryption key. This is the
//! primitive the Microsoft device-enrollment path uses to wrap and unwrap
//! session keys.

use crate::key::{HashAlg, Key};
use crate::{check_rc, sys, Result, Secret, TpmError};
use core::ffi::c_int;

impl<'d> Key<'d> {
    /// Encrypt `msg` to this key's public part with RSA-OAEP.
    pub fn rsa_encrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let msg_len = crate::checked_c_int(msg.len())?;
        let mut out = vec![0u8; sys::MAX_RSA_KEY_BYTES as usize];
        let mut out_sz = out.len() as c_int;
        // SAFETY: self.dev()/self.kptr() are live, msg ptr+len bound its slice, and out.as_mut_ptr()/out_sz describe the full out capacity.
        let rc = unsafe {
            sys::wolfTPM2_RsaEncrypt(
                self.dev(),
                self.kptr(),
                sys::TPM_ALG_ID_T_TPM_ALG_OAEP as sys::TPM_ALG_ID,
                msg.as_ptr(),
                msg_len,
                out.as_mut_ptr(),
                &mut out_sz,
            )
        };
        check_rc(rc)?;
        out.truncate(out_sz as usize);
        Ok(out)
    }

    /// Decrypt an RSA-OAEP ciphertext with this key's private part.
    pub fn rsa_decrypt(&self, ciphertext: &[u8]) -> Result<Secret> {
        let ct_len = crate::checked_c_int(ciphertext.len())?;
        let mut out = vec![0u8; sys::MAX_RSA_KEY_BYTES as usize];
        let mut out_sz = out.len() as c_int;
        // SAFETY: self.dev()/self.kptr() are live, ciphertext ptr+len bound its slice, and out.as_mut_ptr()/out_sz describe the full out capacity.
        let rc = unsafe {
            sys::wolfTPM2_RsaDecrypt(
                self.dev(),
                self.kptr(),
                sys::TPM_ALG_ID_T_TPM_ALG_OAEP as sys::TPM_ALG_ID,
                ciphertext.as_ptr(),
                ct_len,
                out.as_mut_ptr(),
                &mut out_sz,
            )
        };
        check_rc(rc)?;
        out.truncate(out_sz as usize);
        Ok(Secret::new(out))
    }

    /// Encrypt `msg` with RSA-OAEP using an explicit label-hash algorithm.
    ///
    /// The plain [`rsa_encrypt`](Key::rsa_encrypt) uses the TPM's default OAEP
    /// hash (SHA-256). This variant issues the low-level command directly so any
    /// hash the TPM supports can be selected, including `HashAlg::Sha1`, which
    /// Microsoft device enrollment (MS-OAPXBC) requires for its session-key
    /// wrap. SHA-1 is legacy and cryptographically weak; select it only for that
    /// interop, not for new designs.
    pub fn rsa_encrypt_with_hash(&self, msg: &[u8], hash: HashAlg) -> Result<Vec<u8>> {
        // SAFETY: RSA_Encrypt_In is a C POD struct; all-zero is a valid starting state, and the length check above bounds the copy into cin.message.buffer.
        let mut cin: sys::RSA_Encrypt_In = unsafe { core::mem::zeroed() };
        if msg.len() > cin.message.buffer.len() {
            return Err(TpmError(crate::BUFFER_E));
        }
        // SAFETY: self.dev() is live and self.handle_ptr() addresses this Key's own pinned handle.
        unsafe { sys::wolfTPM2_SetAuthHandle(self.dev(), 0, self.handle_ptr()) };
        cin.keyHandle = self.handle();
        cin.message.size = msg.len() as u16;
        cin.message.buffer[..msg.len()].copy_from_slice(msg);
        cin.inScheme.scheme = sys::TPM_ALG_ID_T_TPM_ALG_OAEP as sys::TPMI_ALG_RSA_DECRYPT;
        cin.inScheme.details.anySig.hashAlg = hash.alg_id() as sys::TPMI_ALG_HASH;

        // SAFETY: RSA_Encrypt_Out is a C POD struct; all-zero is a valid starting state for TPM2_RSA_Encrypt to fill.
        let mut cout: sys::RSA_Encrypt_Out = unsafe { core::mem::zeroed() };
        // SAFETY: &mut cin/&mut cout are valid, exclusively-borrowed in/out-params; cin.inScheme.details.anySig was just set to match the OAEP scheme above.
        let rc = unsafe { sys::TPM2_RSA_Encrypt(&mut cin, &mut cout) };
        // SAFETY: self.dev() is live; clear the auth slot and scrub the plaintext
        // copy left in cin, on both the success and error paths.
        unsafe {
            sys::wolfTPM2_UnsetAuth(self.dev(), 0);
            crate::zeroize_raw(&mut cin);
        }
        check_rc(rc)?;
        let n = cout.outData.size as usize;
        Ok(cout.outData.buffer[..n].to_vec())
    }

    /// Decrypt an RSA-OAEP ciphertext using an explicit label-hash algorithm
    /// (see [`rsa_encrypt_with_hash`](Key::rsa_encrypt_with_hash)). Supports
    /// `HashAlg::Sha1` for Microsoft enrollment interop.
    pub fn rsa_decrypt_with_hash(&self, ciphertext: &[u8], hash: HashAlg) -> Result<Secret> {
        // SAFETY: RSA_Decrypt_In is a C POD struct; all-zero is a valid starting state, and the length check above bounds the copy into cin.cipherText.buffer.
        let mut cin: sys::RSA_Decrypt_In = unsafe { core::mem::zeroed() };
        if ciphertext.len() > cin.cipherText.buffer.len() {
            return Err(TpmError(crate::BUFFER_E));
        }
        // SAFETY: self.dev() is live and self.handle_ptr() addresses this Key's own pinned handle.
        unsafe { sys::wolfTPM2_SetAuthHandle(self.dev(), 0, self.handle_ptr()) };
        cin.keyHandle = self.handle();
        cin.cipherText.size = ciphertext.len() as u16;
        cin.cipherText.buffer[..ciphertext.len()].copy_from_slice(ciphertext);
        cin.inScheme.scheme = sys::TPM_ALG_ID_T_TPM_ALG_OAEP as sys::TPMI_ALG_RSA_DECRYPT;
        cin.inScheme.details.anySig.hashAlg = hash.alg_id() as sys::TPMI_ALG_HASH;

        // SAFETY: RSA_Decrypt_Out is a C POD struct; all-zero is a valid starting state for TPM2_RSA_Decrypt to fill.
        let mut cout: sys::RSA_Decrypt_Out = unsafe { core::mem::zeroed() };
        // SAFETY: &mut cin/&mut cout are valid, exclusively-borrowed in/out-params; cin.inScheme.details.anySig was just set to match the OAEP scheme above.
        let rc = unsafe { sys::TPM2_RSA_Decrypt(&mut cin, &mut cout) };
        // SAFETY: self.dev() is live; this clears the auth slot set above regardless of the decrypt outcome.
        unsafe { sys::wolfTPM2_UnsetAuth(self.dev(), 0) };
        let out = if rc == 0 {
            cout.message.buffer[..cout.message.size as usize].to_vec()
        } else {
            Vec::new()
        };
        // SAFETY: cout is a live, fully-owned local; zeroizing it after copying out scrubs the recovered plaintext.
        unsafe { crate::zeroize_raw(&mut cout) };
        check_rc(rc)?;
        Ok(Secret::new(out))
    }
}
