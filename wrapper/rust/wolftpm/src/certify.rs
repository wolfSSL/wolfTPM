//! Attestation: have an AIK certify that an object resides in this TPM.

use crate::device::Device;
use crate::key::{HashAlg, Key};
use crate::{check_rc, sys, Result, TpmError};

/// Number of PCRs a TPM 2.0 implementation exposes; valid indices are `0..24`.
const PCR_COUNT: u32 = 24;

/// A TPM attestation: the signed `certifyInfo` (a `TPMS_ATTEST`) plus the
/// signature over it, which a verifier checks against the AIK's public key.
pub struct Attestation {
    /// The raw attestation structure that was signed.
    pub attest: Vec<u8>,
    /// Signature algorithm (`TPM_ALG_ECDSA` or `TPM_ALG_RSASSA`).
    pub sig_alg: u16,
    /// The signature bytes: `R || S` for ECDSA, or the RSA signature.
    pub signature: Vec<u8>,
}

impl Device {
    /// Have `signer` (an attestation key, see [`Template::attestation`](crate::Template::attestation))
    /// certify `object`, proving `object` lives in this TPM. `qualifying` is an
    /// optional verifier-supplied nonce (freshness); it must fit the TPM's
    /// `TPM2B_DATA` buffer.
    pub fn certify(
        &self,
        object: &Key<'_>,
        signer: &Key<'_>,
        qualifying: &[u8],
    ) -> Result<Attestation> {
        // An encryption session holds auth slot 1, which certify needs for its
        // signing key; refuse rather than silently disable the session.
        if crate::session::is_active() {
            return Err(TpmError(crate::E_SESSION_IN_USE));
        }
        // `is_ecc` only selects which signature union field to read back; the
        // command itself uses the signer's own configured scheme (below).
        let is_ecc = signer.alg() == sys::TPM_ALG_ID_T_TPM_ALG_ECC as sys::TPM_ALG_ID;

        // SAFETY: Certify_In is a C POD struct; all-zero is a valid starting state, and the length check below bounds the copy into cin.qualifyingData.buffer.
        let mut cin: sys::Certify_In = unsafe { core::mem::zeroed() };
        if qualifying.len() > cin.qualifyingData.buffer.len() {
            return Err(TpmError(crate::BUFFER_E));
        }

        // Certify needs two auth slots; a one-session build (MAX_SESSION_NUM=1)
        // rejects slot 1, so check both rather than submitting a half-authorized
        // command.
        // SAFETY: self.ptr() is live and object.handle_ptr()/signer.handle_ptr() address each Key's own pinned handle.
        let (s0, s1) = unsafe {
            (
                sys::wolfTPM2_SetAuthHandle(self.ptr(), 0, object.handle_ptr()),
                sys::wolfTPM2_SetAuthHandle(self.ptr(), 1, signer.handle_ptr()),
            )
        };
        if s0 != 0 || s1 != 0 {
            // SAFETY: self.ptr() is live; unwind whichever slots were set.
            unsafe {
                sys::wolfTPM2_UnsetAuth(self.ptr(), 0);
                sys::wolfTPM2_UnsetAuth(self.ptr(), 1);
            }
            return Err(TpmError(if s0 != 0 { s0 } else { s1 }));
        }
        cin.objectHandle = object.handle();
        cin.signHandle = signer.handle();
        // TPM_ALG_NULL: sign with the AIK's own fixed scheme and hash, which need
        // not be SHA-256 for a non-default-curve key.
        cin.inScheme.scheme = sys::TPM_ALG_ID_T_TPM_ALG_NULL as sys::TPMI_ALG_SIG_SCHEME;
        cin.qualifyingData.size = qualifying.len() as u16;
        cin.qualifyingData.buffer[..qualifying.len()].copy_from_slice(qualifying);

        // SAFETY: Certify_Out is a C POD struct; all-zero is a valid starting state for TPM2_Certify to fill.
        let mut cout: sys::Certify_Out = unsafe { core::mem::zeroed() };
        // SAFETY: &mut cin/&mut cout are valid, exclusively-borrowed in/out-params for TPM2_Certify.
        let rc = unsafe { sys::TPM2_Certify(&mut cin, &mut cout) };
        // SAFETY: self.ptr() is live; this clears both auth slots set above regardless of the certify outcome.
        unsafe {
            sys::wolfTPM2_UnsetAuth(self.ptr(), 0);
            sys::wolfTPM2_UnsetAuth(self.ptr(), 1);
        }
        check_rc(rc)?;

        let asz = cout.certifyInfo.size as usize;
        let attest = cout.certifyInfo.attestationData[..asz].to_vec();
        let signature = extract_signature(is_ecc, &cout.signature);

        Ok(Attestation {
            attest,
            sig_alg: cout.signature.sigAlg,
            signature,
        })
    }

    /// Have `signer` (an attestation key) sign a quote over the current values
    /// of the PCRs in `pcr_indices` (in the `hash` bank), proving the machine's
    /// measured-boot state. `qualifying` is an optional verifier nonce. This is
    /// the standard remote-attestation primitive.
    pub fn quote(
        &self,
        signer: &Key<'_>,
        pcr_indices: &[u32],
        hash: HashAlg,
        qualifying: &[u8],
    ) -> Result<Attestation> {
        // An encryption session holds auth slot 1, which quote needs for its
        // signing key; refuse rather than silently disable the session.
        if crate::session::is_active() {
            return Err(TpmError(crate::E_SESSION_IN_USE));
        }
        // `is_ecc` only selects which signature union field to read back; the
        // command uses the signer's own scheme and `hash` selects the PCR bank.
        let is_ecc = signer.alg() == sys::TPM_ALG_ID_T_TPM_ALG_ECC as sys::TPM_ALG_ID;

        // Reject empty or out-of-range PCRs: TPM2_SetupPCRSel silently drops
        // indices outside the implemented range, which would otherwise let the
        // TPM sign a quote bound to fewer (or zero) PCRs than requested.
        if pcr_indices.is_empty() || pcr_indices.iter().any(|&i| i >= PCR_COUNT) {
            return Err(TpmError(crate::BUFFER_E));
        }
        // SAFETY: Quote_In is a C POD struct; all-zero is a valid starting state, and the length check below bounds the copy into qin.qualifyingData.buffer.
        let mut qin: sys::Quote_In = unsafe { core::mem::zeroed() };
        if qualifying.len() > qin.qualifyingData.buffer.len() {
            return Err(TpmError(crate::BUFFER_E));
        }
        for &idx in pcr_indices {
            // SAFETY: &mut qin.PCRselect is a valid, exclusively-borrowed field of the live qin struct.
            unsafe { sys::TPM2_SetupPCRSel(&mut qin.PCRselect, hash.alg_id(), idx as core::ffi::c_int) };
        }

        // SAFETY: self.ptr() is live and signer.handle_ptr() addresses that Key's own pinned handle.
        unsafe { sys::wolfTPM2_SetAuthHandle(self.ptr(), 0, signer.handle_ptr()) };
        qin.signHandle = signer.handle();
        // TPM_ALG_NULL: sign with the AIK's own scheme/hash. The signature hash
        // is independent of the PCR-bank hash selected above.
        qin.inScheme.scheme = sys::TPM_ALG_ID_T_TPM_ALG_NULL as sys::TPMI_ALG_SIG_SCHEME;
        qin.qualifyingData.size = qualifying.len() as u16;
        qin.qualifyingData.buffer[..qualifying.len()].copy_from_slice(qualifying);

        // SAFETY: Quote_Out is a C POD struct; all-zero is a valid starting state for TPM2_Quote to fill.
        let mut qout: sys::Quote_Out = unsafe { core::mem::zeroed() };
        // SAFETY: &mut qin/&mut qout are valid, exclusively-borrowed in/out-params for TPM2_Quote.
        let rc = unsafe { sys::TPM2_Quote(&mut qin, &mut qout) };
        // SAFETY: self.ptr() is live; this clears the auth slot set above regardless of the quote outcome.
        unsafe { sys::wolfTPM2_UnsetAuth(self.ptr(), 0) };
        check_rc(rc)?;

        let asz = qout.quoted.size as usize;
        let attest = qout.quoted.attestationData[..asz].to_vec();
        let signature = extract_signature(is_ecc, &qout.signature);

        Ok(Attestation {
            attest,
            sig_alg: qout.signature.sigAlg,
            signature,
        })
    }
}

/// Field size (bytes) of NIST P-256, the ECC curve this crate's `KeyAlg`
/// exposes; used as the minimum ECDSA coordinate width.
const ECC_P256_COORD: usize = 32;

/// Marshal a TPM signature out of its alg-specific union: fixed-width
/// `R || S` for ECDSA (each component left-padded to the same width so the
/// split point is unambiguous — half the result each), or the raw signature
/// buffer for RSASSA. The width is the larger of the two returned components
/// and the P-256 field size, so P-256 always yields 32-byte halves and a
/// larger curve (in a P-256-disabled build) is never truncated.
fn extract_signature(is_ecc: bool, sig: &sys::TPMT_SIGNATURE) -> Vec<u8> {
    // SAFETY: is_ecc, derived from the signing key's own algorithm, selects the union field the TPM actually populated.
    unsafe {
        if is_ecc {
            let e = &sig.signature.ecdsa;
            let coord = (e.signatureR.size as usize)
                .max(e.signatureS.size as usize)
                .max(ECC_P256_COORD);
            let mut v = vec![0u8; coord * 2];
            put_left_padded(&mut v[..coord], &e.signatureR.buffer, e.signatureR.size);
            put_left_padded(&mut v[coord..], &e.signatureS.buffer, e.signatureS.size);
            v
        } else {
            let r = &sig.signature.rsassa;
            r.sig.buffer[..r.sig.size as usize].to_vec()
        }
    }
}

/// Right-align `src[..len]` into `dst` (left-padded with the existing zeros).
fn put_left_padded(dst: &mut [u8], src: &[u8], len: u16) {
    let n = (len as usize).min(dst.len());
    let start = dst.len() - n;
    dst[start..].copy_from_slice(&src[..n]);
}
