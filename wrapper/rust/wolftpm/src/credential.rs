//! EK-based credential activation (`TPM2_MakeCredential` /
//! `TPM2_ActivateCredential`): the handshake that binds an attestation identity
//! key to a specific TPM's endorsement key, proving both live in the same TPM
//! without exposing the EK private key.

use crate::device::Device;
use crate::key::Key;
use crate::{check_rc, sys, Result, Secret, TpmError};

/// A credential protected to a TPM's EK: the encrypted `credential_blob` and
/// the wrapped `secret`, both produced by [`Device::make_credential`] and
/// consumed by [`Device::activate_credential`].
pub struct Credential {
    pub credential_blob: Vec<u8>,
    pub secret: Vec<u8>,
}

impl Device {
    /// Encrypt `secret` so only the TPM holding `ek` can recover it, bound to
    /// the object named `object_name` (an AIK's [`Key::name`]). This is the
    /// verifier-side step; it needs only the EK's public part, no auth.
    pub fn make_credential(
        &self,
        ek: &Key<'_>,
        object_name: &[u8],
        secret: &[u8],
    ) -> Result<Credential> {
        // SAFETY: MakeCredential_In is a C POD struct; all-zero is a valid starting state, and the length checks below bound the copies into its buffers.
        let mut cin: sys::MakeCredential_In = unsafe { core::mem::zeroed() };
        if secret.len() > cin.credential.buffer.len()
            || object_name.len() > cin.objectName.name.len()
        {
            return Err(TpmError(crate::BUFFER_E));
        }
        cin.handle = ek.handle();
        cin.credential.size = secret.len() as u16;
        cin.credential.buffer[..secret.len()].copy_from_slice(secret);
        cin.objectName.size = object_name.len() as u16;
        cin.objectName.name[..object_name.len()].copy_from_slice(object_name);

        // SAFETY: MakeCredential_Out is a C POD struct; all-zero is a valid starting state for TPM2_MakeCredential to fill.
        let mut cout: sys::MakeCredential_Out = unsafe { core::mem::zeroed() };
        // SAFETY: &mut cin/&mut cout are valid, exclusively-borrowed in/out-params for TPM2_MakeCredential.
        let rc = unsafe { sys::TPM2_MakeCredential(&mut cin, &mut cout) };
        // Scrub the plaintext credential copy left in the input on every path.
        // SAFETY: cin is a live, fully-owned local being zeroized after the call.
        unsafe { crate::zeroize_raw(&mut cin) };
        check_rc(rc)?;

        let bsz = cout.credentialBlob.size as usize;
        let ssz = cout.secret.size as usize;
        Ok(Credential {
            credential_blob: cout.credentialBlob.buffer[..bsz].to_vec(),
            secret: cout.secret.secret[..ssz].to_vec(),
        })
    }

    /// Recover the secret from `cred` using `aik` (the activating key, auth in
    /// slot 0) and `ek` (the decrypting endorsement key, satisfied by an EK
    /// policy session in slot 1). Succeeds only on the TPM whose EK the
    /// credential was made for.
    #[cfg(ek_policy)]
    pub fn activate_credential(
        &self,
        aik: &Key<'_>,
        ek: &Key<'_>,
        cred: &Credential,
    ) -> Result<Secret> {
        // An encryption session holds auth slot 1, which the EK policy session
        // needs here; refuse rather than silently disable the session.
        if crate::session::is_active() {
            return Err(TpmError(crate::E_SESSION_IN_USE));
        }
        // EK auth is by policy (PolicySecret over the endorsement hierarchy),
        // not a password. Save the prior bit and restore it on every exit so the
        // caller's Key is not left mutated.
        // SAFETY: ek.handle_ptr() addresses the live, pinned handle bit-field for this Key.
        let prev_policy = unsafe { (*ek.handle_ptr()).policyAuth() };
        unsafe { (*ek.handle_ptr()).set_policyAuth(1) };
        // SAFETY: WOLFTPM2_SESSION is a C POD struct; all-zero is a valid starting state for CreateAuthSession_EkPolicy to fill.
        let mut session: sys::WOLFTPM2_SESSION = unsafe { core::mem::zeroed() };
        // SAFETY: self.ptr() is live and &mut session is a valid, exclusively-borrowed out-param.
        let rc = unsafe { sys::wolfTPM2_CreateAuthSession_EkPolicy(self.ptr(), &mut session) };
        if rc != 0 {
            // The helper may have started the session before PolicySecret failed
            // (e.g. a protected endorsement hierarchy); unload it so repeated
            // attempts don't exhaust the TPM's session slots.
            if session.handle.hndl != 0 {
                // SAFETY: self.ptr() is live and &mut session.handle addresses the partially-created session.
                unsafe { sys::wolfTPM2_UnloadHandle(self.ptr(), &mut session.handle) };
            }
            // SAFETY: session is a live, fully-owned local being scrubbed before return.
            unsafe { crate::zeroize_raw(&mut session) };
            // SAFETY: ek.handle_ptr() addresses the live handle bit-field.
            unsafe { (*ek.handle_ptr()).set_policyAuth(prev_policy) };
            return Err(TpmError(rc));
        }

        // SAFETY: ActivateCredential_In is a C POD struct; all-zero is a valid starting state before the checked field copies below.
        let mut cin: sys::ActivateCredential_In = unsafe { core::mem::zeroed() };
        if cred.credential_blob.len() > cin.credentialBlob.buffer.len()
            || cred.secret.len() > cin.secret.secret.len()
        {
            // SAFETY: self.ptr() is live; the just-opened session is torn down before returning on this error path.
            unsafe { sys::wolfTPM2_UnloadHandle(self.ptr(), &mut session.handle) };
            // SAFETY: ek.handle_ptr() addresses the live handle bit-field.
            unsafe { (*ek.handle_ptr()).set_policyAuth(prev_policy) };
            return Err(TpmError(crate::BUFFER_E));
        }

        // Slot 1: EK policy session, bound to the EK's Name.
        // SAFETY: &mut session still refers to the live session created above.
        let set_rc = unsafe {
            sys::wolfTPM2_SetAuthSession(self.ptr(), 1, &mut session, 0)
        };
        // SAFETY: self.ptr() is live, and ek.handle_ptr()/aik.handle_ptr() address each Key's own pinned handle.
        unsafe {
            sys::wolfTPM2_SetAuthHandleName(self.ptr(), 1, ek.handle_ptr());
            // Slot 0: the AIK's own (password) auth.
            sys::wolfTPM2_SetAuthHandle(self.ptr(), 0, aik.handle_ptr());
        }

        cin.activateHandle = aik.handle();
        cin.keyHandle = ek.handle();
        cin.credentialBlob.size = cred.credential_blob.len() as u16;
        cin.credentialBlob.buffer[..cred.credential_blob.len()]
            .copy_from_slice(&cred.credential_blob);
        cin.secret.size = cred.secret.len() as u16;
        cin.secret.secret[..cred.secret.len()].copy_from_slice(&cred.secret);

        // SAFETY: ActivateCredential_Out is a C POD struct; all-zero is a valid starting state for TPM2_ActivateCredential to fill.
        let mut cout: sys::ActivateCredential_Out = unsafe { core::mem::zeroed() };
        let rc = if set_rc != 0 {
            set_rc
        } else {
            // SAFETY: &mut cin/&mut cout are valid, exclusively-borrowed in/out-params, reached only once both auth slots were set successfully.
            unsafe { sys::TPM2_ActivateCredential(&mut cin, &mut cout) }
        };
        // SAFETY: self.ptr() is live; this clears both auth slots set above regardless of the activation outcome.
        unsafe {
            sys::wolfTPM2_UnsetAuth(self.ptr(), 0);
            sys::wolfTPM2_UnsetAuth(self.ptr(), 1);
        }
        // The TPM flushes the policy session on a successful use; only unload it
        // if the command did not consume it.
        if rc != 0 {
            // SAFETY: self.ptr() is live and &mut session.handle addresses the still-loaded policy session.
            unsafe { sys::wolfTPM2_UnloadHandle(self.ptr(), &mut session.handle) };
        }
        // SAFETY: ek.handle_ptr() addresses the live handle bit-field; restore the
        // caller's EK auth mode now that the command is done.
        unsafe { (*ek.handle_ptr()).set_policyAuth(prev_policy) };
        check_rc(rc)?;

        let n = cout.certInfo.size as usize;
        let out = cout.certInfo.buffer[..n].to_vec();
        // SAFETY: cout is a live, fully-owned local; zeroizing it after copying out scrubs the recovered secret.
        unsafe { crate::zeroize_raw(&mut cout) };
        Ok(Secret::new(out))
    }
}
