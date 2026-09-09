//! Seal a secret to the TPM and unseal it back (keyed-hash sealed objects).

use crate::device::Device;
use crate::key::{auth_ptr, Key, KeyBlob};
use crate::{check_rc, sys, Result, Secret, TpmError};
use core::ffi::c_int;

/// Number of PCRs a TPM 2.0 implementation exposes; valid indices are `0..24`.
const PCR_COUNT: u8 = 24;

/// Reject an empty or out-of-range PCR selection, which would otherwise bind a
/// sealed object to fewer PCRs than the caller asked for (silently dropped by
/// the TPM's selection builder).
fn check_pcr_indices(pcr_indices: &[u8]) -> Result<()> {
    if pcr_indices.is_empty() || pcr_indices.iter().any(|&i| i >= PCR_COUNT) {
        return Err(TpmError(crate::BUFFER_E));
    }
    Ok(())
}

impl Device {
    /// Seal `data` under `parent`, optionally protected by `auth`. Returns the
    /// sealed blob (persist it with [`KeyBlob::to_bytes`](crate::KeyBlob::to_bytes)).
    pub fn seal(&self, parent: &Key<'_>, data: &[u8], auth: Option<&[u8]>) -> Result<KeyBlob<'_>> {
        // SAFETY: TPMT_PUBLIC is a C POD struct; all-zero is a valid starting state for the seal template helper.
        let mut tmpl: sys::TPMT_PUBLIC = unsafe { core::mem::zeroed() };
        // SAFETY: &mut tmpl is a valid, exclusively-borrowed out-param for wolfTPM2_GetKeyTemplate_KeySeal.
        let rc = unsafe {
            sys::wolfTPM2_GetKeyTemplate_KeySeal(
                &mut tmpl,
                sys::TPM_ALG_ID_T_TPM_ALG_SHA256 as sys::TPM_ALG_ID,
            )
        };
        check_rc(rc)?;

        // SAFETY: WOLFTPM2_KEYBLOB is a C POD struct; all-zero is a valid starting state for CreateKeySeal to fill.
        let data_len = crate::checked_c_int(data.len())?;
        let mut blob: sys::WOLFTPM2_KEYBLOB = unsafe { core::mem::zeroed() };
        let (authp, authsz) = auth_ptr(auth)?;
        // SAFETY: self.ptr()/parent.handle_ptr() are live, &mut blob/&mut tmpl are valid out-params, authp/authsz match (ptr, len) or (null, 0), and data ptr+len bound its slice.
        let rc = unsafe {
            sys::wolfTPM2_CreateKeySeal(
                self.ptr(),
                &mut blob,
                parent.handle_ptr(),
                &mut tmpl,
                authp,
                authsz,
                data.as_ptr(),
                data_len,
            )
        };
        check_rc(rc)?;

        // Keep only the persistable pub/priv blob; drop any transient handle so
        // unseal re-loads it fresh under the parent.
        if blob.handle.hndl != 0 {
            // SAFETY: self.ptr() is live and &mut blob.handle addresses the transient handle CreateKeySeal returned.
            unsafe { sys::wolfTPM2_UnloadHandle(self.ptr(), &mut blob.handle) };
            blob.handle.hndl = 0;
        }
        Ok(KeyBlob::from_parts(self.ptr(), blob))
    }

    /// Load a `sealed` blob under `parent` and release its secret. Requires the
    /// same `auth` the blob was sealed with.
    pub fn unseal(
        &self,
        sealed: KeyBlob<'_>,
        parent: &Key<'_>,
        auth: Option<&[u8]>,
    ) -> Result<Secret> {
        let key = sealed.load(parent, None)?;
        if let Some(a) = auth {
            key.set_auth(a)?;
        }
        // SAFETY: self.ptr() is the pinned dev pointer and key.handle_ptr() addresses the just-loaded key's live handle.
        unsafe { sys::wolfTPM2_SetAuthHandle(self.ptr(), 0, key.handle_ptr()) };

        // SAFETY: Unseal_In/Unseal_Out are C POD structs; all-zero is a valid starting state for TPM2_Unseal to fill.
        let mut cmd_in: sys::Unseal_In = unsafe { core::mem::zeroed() };
        cmd_in.itemHandle = key.handle();
        // SAFETY: Unseal_Out is a C POD struct; all-zero is a valid starting state for TPM2_Unseal to fill.
        let mut cmd_out: sys::Unseal_Out = unsafe { core::mem::zeroed() };
        // SAFETY: &mut cmd_in/&mut cmd_out are valid, exclusively-borrowed in/out-params for TPM2_Unseal.
        let rc = unsafe { sys::TPM2_Unseal(&mut cmd_in, &mut cmd_out) };
        // SAFETY: self.ptr() is live; this clears the auth slot set above regardless of the unseal outcome.
        unsafe { sys::wolfTPM2_UnsetAuth(self.ptr(), 0) };

        let out = if rc == 0 {
            let n = cmd_out.outData.size as usize;
            cmd_out.outData.buffer[..n].to_vec()
        } else {
            Vec::new()
        };
        // SAFETY: cmd_out is a live, fully-owned local; zeroizing it after copying out scrubs the returned secret bytes.
        unsafe { crate::zeroize_raw(&mut cmd_out) };
        check_rc(rc)?;
        Ok(Secret::new(out))
    }

    /// Seal `data` under `parent`, bound to the current values of the PCRs in
    /// `pcr_indices` (SHA-256 bank). Unsealing later requires those PCRs to
    /// still hold the same values (measured-boot binding).
    ///
    /// Access is gated solely by the PCR policy: there is deliberately no auth
    /// value, since a PCR-policy object clears `userWithAuth` and any auth would
    /// not be enforced on unseal.
    pub fn seal_pcr(&self, parent: &Key<'_>, data: &[u8], pcr_indices: &[u8]) -> Result<KeyBlob<'_>> {
        check_pcr_indices(pcr_indices)?;
        let sha256 = sys::TPM_ALG_ID_T_TPM_ALG_SHA256 as sys::TPM_ALG_ID;
        let mut pcrs = pcr_indices.to_vec();

        // Compute the PCR policy digest exactly as unseal will, using a trial
        // session, so the sealed authPolicy matches what PolicyPCR produces.
        // SAFETY: WOLFTPM2_SESSION is a C POD struct; all-zero is a valid starting state for StartSession to fill.
        let mut trial: sys::WOLFTPM2_SESSION = unsafe { core::mem::zeroed() };
        // SAFETY: self.ptr() is live and &mut trial is a valid exclusive out-param.
        let rc = unsafe {
            sys::wolfTPM2_StartSession(
                self.ptr(),
                &mut trial,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                sys::TPM_SE_T_TPM_SE_TRIAL as sys::TPM_SE,
                sys::TPM_ALG_ID_T_TPM_ALG_NULL as c_int,
            )
        };
        check_rc(rc)?;
        // SAFETY: trial.handle.hndl is the session StartSession just opened, and pcrs ptr+len bound the live Vec.
        let policy_rc = unsafe {
            sys::wolfTPM2_PolicyPCR(
                self.ptr(),
                trial.handle.hndl,
                sha256,
                pcrs.as_mut_ptr(),
                pcrs.len() as sys::word32,
            )
        };
        let mut policy = vec![0u8; 64];
        let mut policy_sz = policy.len() as sys::word32;
        // SAFETY: policy.as_mut_ptr()/policy_sz describe the full policy Vec capacity, and trial.handle.hndl is still live.
        let digest_rc = unsafe {
            sys::wolfTPM2_GetPolicyDigest(
                self.ptr(),
                trial.handle.hndl,
                policy.as_mut_ptr(),
                &mut policy_sz,
            )
        };
        // SAFETY: the trial session's policy digest has been read; this unloads it regardless of the calls' outcomes.
        unsafe { sys::wolfTPM2_UnloadHandle(self.ptr(), &mut trial.handle) };
        check_rc(policy_rc)?;
        check_rc(digest_rc)?;
        policy.truncate(policy_sz as usize);

        // SAFETY: TPMT_PUBLIC is a C POD struct; all-zero is a valid starting state for the seal template helper.
        let mut tmpl: sys::TPMT_PUBLIC = unsafe { core::mem::zeroed() };
        // SAFETY: &mut tmpl is a valid, exclusively-borrowed out-param for wolfTPM2_GetKeyTemplate_KeySeal.
        let rc = unsafe { sys::wolfTPM2_GetKeyTemplate_KeySeal(&mut tmpl, sha256) };
        check_rc(rc)?;
        // Policy-only access: clear userWithAuth so the PCR policy is required.
        tmpl.objectAttributes &=
            !(sys::TPMA_OBJECT_mask_TPMA_OBJECT_userWithAuth as sys::TPMA_OBJECT);
        tmpl.authPolicy.size = policy.len() as u16;
        tmpl.authPolicy.buffer[..policy.len()].copy_from_slice(&policy);

        // SAFETY: WOLFTPM2_KEYBLOB is a C POD struct; all-zero is a valid starting state for CreateKeySeal_ex to fill.
        let data_len = crate::checked_c_int(data.len())?;
        let mut blob: sys::WOLFTPM2_KEYBLOB = unsafe { core::mem::zeroed() };
        let (authp, authsz) = auth_ptr(None)?;
        // SAFETY: self.ptr()/parent.handle_ptr() are live, &mut blob/&mut tmpl are valid out-params, authp/authsz is (null, 0), and data ptr+len bound its slice.
        let rc = unsafe {
            sys::wolfTPM2_CreateKeySeal_ex(
                self.ptr(),
                &mut blob,
                parent.handle_ptr(),
                &mut tmpl,
                authp,
                authsz,
                sha256,
                core::ptr::null_mut(),
                0,
                data.as_ptr(),
                data_len,
            )
        };
        check_rc(rc)?;
        if blob.handle.hndl != 0 {
            // SAFETY: self.ptr() is live and &mut blob.handle addresses the transient handle CreateKeySeal_ex returned.
            unsafe { sys::wolfTPM2_UnloadHandle(self.ptr(), &mut blob.handle) };
            blob.handle.hndl = 0;
        }
        Ok(KeyBlob::from_parts(self.ptr(), blob))
    }

    /// Unseal a PCR-bound blob. Succeeds only if the PCRs in `pcr_indices` still
    /// hold the values they had when [`seal_pcr`](Device::seal_pcr) ran.
    pub fn unseal_pcr(
        &self,
        sealed: KeyBlob<'_>,
        parent: &Key<'_>,
        pcr_indices: &[u8],
    ) -> Result<Secret> {
        check_pcr_indices(pcr_indices)?;
        let key = sealed.load(parent, None)?;

        // Policy session, satisfy the PCR policy, register it, then bind the
        // sealed object's name for the session HMAC before unsealing.
        // SAFETY: WOLFTPM2_SESSION is a C POD struct; all-zero is a valid starting state for StartSession to fill.
        let mut session: sys::WOLFTPM2_SESSION = unsafe { core::mem::zeroed() };
        // SAFETY: self.ptr() is live and &mut session is a valid exclusive out-param.
        let rc = unsafe {
            sys::wolfTPM2_StartSession(
                self.ptr(),
                &mut session,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                sys::TPM_SE_T_TPM_SE_POLICY as sys::TPM_SE,
                sys::TPM_ALG_ID_T_TPM_ALG_NULL as c_int,
            )
        };
        check_rc(rc)?;

        let mut pcrs = pcr_indices.to_vec();
        // SAFETY: session.handle.hndl is the session StartSession just opened, and pcrs ptr+len bound the live Vec.
        let policy_rc = unsafe {
            sys::wolfTPM2_PolicyPCR(
                self.ptr(),
                session.handle.hndl,
                sys::TPM_ALG_ID_T_TPM_ALG_SHA256 as sys::TPM_ALG_ID,
                pcrs.as_mut_ptr(),
                pcrs.len() as sys::word32,
            )
        };
        // SAFETY: &mut session still refers to the live session opened above.
        let set_rc = unsafe {
            sys::wolfTPM2_SetAuthSession(
                self.ptr(),
                0,
                &mut session,
                sys::TPMA_SESSION_mask_TPMA_SESSION_continueSession as sys::TPMA_SESSION,
            )
        };
        // SAFETY: self.ptr() is live and key.handle_ptr() addresses the just-loaded key's own handle.
        unsafe { sys::wolfTPM2_SetAuthHandleName(self.ptr(), 0, key.handle_ptr()) };

        // SAFETY: Unseal_In/Unseal_Out are C POD structs; all-zero is a valid starting state for TPM2_Unseal to fill.
        let mut cmd_in: sys::Unseal_In = unsafe { core::mem::zeroed() };
        cmd_in.itemHandle = key.handle();
        // SAFETY: Unseal_Out is a C POD struct; all-zero is a valid starting state for TPM2_Unseal to fill.
        let mut cmd_out: sys::Unseal_Out = unsafe { core::mem::zeroed() };
        let unseal_rc = if policy_rc != 0 {
            policy_rc
        } else if set_rc != 0 {
            set_rc
        } else {
            // SAFETY: &mut cmd_in/&mut cmd_out are valid, exclusively-borrowed in/out-params, reached only once policy/session setup succeeded.
            unsafe { sys::TPM2_Unseal(&mut cmd_in, &mut cmd_out) }
        };

        // SAFETY: self.ptr() is live; this clears the auth slot and unloads the policy session regardless of the unseal outcome.
        unsafe {
            sys::wolfTPM2_UnsetAuth(self.ptr(), 0);
            sys::wolfTPM2_UnloadHandle(self.ptr(), &mut session.handle);
        }

        let out = if unseal_rc == 0 {
            let n = cmd_out.outData.size as usize;
            cmd_out.outData.buffer[..n].to_vec()
        } else {
            Vec::new()
        };
        // SAFETY: cmd_out is a live, fully-owned local; zeroizing it after copying out scrubs the returned secret bytes.
        unsafe { crate::zeroize_raw(&mut cmd_out) };
        check_rc(unseal_rc)?;
        Ok(Secret::new(out))
    }
}
