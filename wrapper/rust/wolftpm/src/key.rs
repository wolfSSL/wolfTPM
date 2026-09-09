//! TPM key objects, templates, and key blobs.

use crate::device::Device;
use crate::{check_rc, sys, Result, TpmError};
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::marker::PhantomData;

/// TPM authorization hierarchy a primary key is created under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hierarchy {
    Owner,
    Endorsement,
    Platform,
    Null,
}

impl Hierarchy {
    pub(crate) fn handle(self) -> sys::TPM_HANDLE {
        let h = match self {
            Hierarchy::Owner => sys::TPM_RH_T_TPM_RH_OWNER,
            Hierarchy::Endorsement => sys::TPM_RH_T_TPM_RH_ENDORSEMENT,
            Hierarchy::Platform => sys::TPM_RH_T_TPM_RH_PLATFORM,
            Hierarchy::Null => sys::TPM_RH_T_TPM_RH_NULL,
        };
        h as sys::TPM_HANDLE
    }
}

/// Asymmetric algorithm for a key template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlg {
    Rsa,
    EccP256,
}

impl KeyAlg {
    pub(crate) fn alg_id(self) -> sys::TPM_ALG_ID {
        let a = match self {
            KeyAlg::Rsa => sys::TPM_ALG_ID_T_TPM_ALG_RSA,
            KeyAlg::EccP256 => sys::TPM_ALG_ID_T_TPM_ALG_ECC,
        };
        a as sys::TPM_ALG_ID
    }
}

/// Hash algorithm selector (PCR banks, schemes, OAEP label hash).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-1. Legacy; the one place it is still needed is RSA-OAEP with the
    /// Microsoft enrollment scheme, which wraps its session key with OAEP-SHA1.
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub(crate) fn alg_id(self) -> sys::TPM_ALG_ID {
        let a = match self {
            HashAlg::Sha1 => sys::TPM_ALG_ID_T_TPM_ALG_SHA1,
            HashAlg::Sha256 => sys::TPM_ALG_ID_T_TPM_ALG_SHA256,
            HashAlg::Sha384 => sys::TPM_ALG_ID_T_TPM_ALG_SHA384,
            HashAlg::Sha512 => sys::TPM_ALG_ID_T_TPM_ALG_SHA512,
        };
        a as sys::TPM_ALG_ID
    }

    pub(crate) fn as_c_int(self) -> c_int {
        self.alg_id() as c_int
    }

    /// Digest length in bytes for this hash.
    pub fn digest_size(self) -> usize {
        match self {
            HashAlg::Sha1 => 20,
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }
}

/// A TPM public-area key template.
pub struct Template(pub(crate) sys::TPMT_PUBLIC);

impl Template {
    /// Storage root key template (restricted decryption parent).
    pub fn srk(alg: KeyAlg) -> Result<Self> {
        // SAFETY: TPMT_PUBLIC is a C POD struct; all-zero is a valid starting state for the template helper to fill.
        let mut t: sys::TPMT_PUBLIC = unsafe { core::mem::zeroed() };
        // SAFETY: &mut t is a valid, exclusively-borrowed out-param for the selected SRK template helper.
        let rc = unsafe {
            match alg {
                KeyAlg::Rsa => sys::wolfTPM2_GetKeyTemplate_RSA_SRK(&mut t),
                KeyAlg::EccP256 => sys::wolfTPM2_GetKeyTemplate_ECC_SRK(&mut t),
            }
        };
        check_rc(rc)?;
        check_p256(&t, alg)?;
        Ok(Template(t))
    }

    /// Attestation identity key (AIK) template — a restricted signing key used
    /// to certify other objects / quote PCRs.
    pub fn attestation(alg: KeyAlg) -> Result<Self> {
        // SAFETY: TPMT_PUBLIC is a C POD struct; all-zero is a valid starting state for the AIK template helper.
        let mut t: sys::TPMT_PUBLIC = unsafe { core::mem::zeroed() };
        // SAFETY: &mut t is a valid, exclusively-borrowed out-param for the selected AIK template helper.
        let rc = unsafe {
            match alg {
                KeyAlg::EccP256 => sys::wolfTPM2_GetKeyTemplate_ECC_AIK(&mut t),
                KeyAlg::Rsa => sys::wolfTPM2_GetKeyTemplate_RSA_AIK(&mut t),
            }
        };
        check_rc(rc)?;
        check_p256(&t, alg)?;
        Ok(Template(t))
    }

    /// Endorsement key (EK) template, created under the endorsement hierarchy.
    pub fn ek(alg: KeyAlg) -> Result<Self> {
        // SAFETY: TPMT_PUBLIC is a C POD struct; all-zero is a valid starting state for the EK template helper.
        let mut t: sys::TPMT_PUBLIC = unsafe { core::mem::zeroed() };
        // SAFETY: &mut t is a valid, exclusively-borrowed out-param for the selected EK template helper.
        let rc = unsafe {
            match alg {
                KeyAlg::EccP256 => sys::wolfTPM2_GetKeyTemplate_ECC_EK(&mut t),
                KeyAlg::Rsa => sys::wolfTPM2_GetKeyTemplate_RSA_EK(&mut t),
            }
        };
        check_rc(rc)?;
        Ok(Template(t))
    }

    /// RSA decryption-key template (non-restricted), for RSA-OAEP encrypt and
    /// decrypt.
    pub fn rsa_decrypt() -> Result<Self> {
        let attrs = (sys::TPMA_OBJECT_mask_TPMA_OBJECT_decrypt
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_fixedTPM
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_fixedParent
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_sensitiveDataOrigin
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_userWithAuth
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_noDA) as sys::TPMA_OBJECT;
        // SAFETY: TPMT_PUBLIC is a C POD struct; all-zero is a valid starting state for the template helper to fill.
        let mut t: sys::TPMT_PUBLIC = unsafe { core::mem::zeroed() };
        // SAFETY: &mut t is a valid, exclusively-borrowed out-param for wolfTPM2_GetKeyTemplate_RSA.
        let rc = unsafe { sys::wolfTPM2_GetKeyTemplate_RSA(&mut t, attrs) };
        check_rc(rc)?;
        Ok(Template(t))
    }

    /// General signing-key template (non-restricted, ECDSA/RSASSA).
    pub fn signing(alg: KeyAlg) -> Result<Self> {
        let attrs = (sys::TPMA_OBJECT_mask_TPMA_OBJECT_sign
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_fixedTPM
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_fixedParent
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_sensitiveDataOrigin
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_userWithAuth
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_noDA) as sys::TPMA_OBJECT;
        // SAFETY: TPMT_PUBLIC is a C POD struct; all-zero is a valid starting state for the signing template helper.
        let mut t: sys::TPMT_PUBLIC = unsafe { core::mem::zeroed() };
        // SAFETY: &mut t is a valid, exclusively-borrowed out-param for the selected signing template helper.
        let rc = unsafe {
            match alg {
                KeyAlg::EccP256 => sys::wolfTPM2_GetKeyTemplate_ECC(
                    &mut t,
                    attrs,
                    sys::TPM_ECC_CURVE_T_TPM_ECC_NIST_P256 as sys::TPM_ECC_CURVE,
                    sys::TPM_ALG_ID_T_TPM_ALG_ECDSA as sys::TPM_ALG_ID,
                ),
                // Set an explicit RSASSA-SHA256 scheme; the plain template
                // leaves the scheme NULL, which sign_hash cannot use for RSA.
                KeyAlg::Rsa => sys::wolfTPM2_GetKeyTemplate_RSA_ex(
                    &mut t,
                    sys::TPM_ALG_ID_T_TPM_ALG_SHA256 as sys::TPM_ALG_ID,
                    attrs,
                    2048,
                    0,
                    sys::TPM_ALG_ID_T_TPM_ALG_RSASSA as sys::TPM_ALG_ID,
                    sys::TPM_ALG_ID_T_TPM_ALG_SHA256 as sys::TPM_ALG_ID,
                ),
            }
        };
        check_rc(rc)?;
        check_p256(&t, alg)?;
        Ok(Template(t))
    }

    /// TPM-generated keyed-hash HMAC key template, bound to this TPM.
    ///
    /// The key material originates in the TPM (`sensitiveDataOrigin`) and is
    /// non-duplicable (`fixedTPM`/`fixedParent`), so the HMAC secret never
    /// leaves the TPM: create it once, keep only the wrapped blob, reload it,
    /// and compute with [`Key::hmac`](crate::Key::hmac).
    #[cfg(keyedhash)]
    pub fn hmac(hash: HashAlg) -> Result<Self> {
        // SAFETY: TPMT_PUBLIC is a C POD struct; all-zero is a valid starting state for the template helper to fill.
        let mut t: sys::TPMT_PUBLIC = unsafe { core::mem::zeroed() };
        // SAFETY: &mut t is a valid, exclusively-borrowed out-param for wolfTPM2_GetKeyTemplate_KeyedHash.
        let rc = unsafe { sys::wolfTPM2_GetKeyTemplate_KeyedHash(&mut t, hash.alg_id(), 1, 0) };
        check_rc(rc)?;
        // The helper leaves sensitiveDataOrigin clear (caller-supplied key);
        // set it plus the fixed bits so the TPM generates a bound secret.
        t.objectAttributes |= (sys::TPMA_OBJECT_mask_TPMA_OBJECT_sensitiveDataOrigin
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_fixedTPM
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_fixedParent)
            as sys::TPMA_OBJECT;
        Ok(Template(t))
    }

    /// AES symmetric-cipher key template (CFB mode) for TPM-backed bulk
    /// encrypt/decrypt via [`Key::aes_encrypt`](crate::Key::aes_encrypt) /
    /// [`Key::aes_decrypt`](crate::Key::aes_decrypt). `bits` is 128 or 256.
    #[cfg(symmetric)]
    pub fn symmetric(bits: u16) -> Result<Self> {
        // SAFETY: TPMT_PUBLIC is a C POD struct; all-zero is a valid starting state for the template helper to fill.
        let mut t: sys::TPMT_PUBLIC = unsafe { core::mem::zeroed() };
        // SAFETY: &mut t is a valid, exclusively-borrowed out-param for wolfTPM2_GetKeyTemplate_Symmetric.
        let rc = unsafe {
            sys::wolfTPM2_GetKeyTemplate_Symmetric(
                &mut t,
                bits as c_int,
                sys::TPM_ALG_ID_T_TPM_ALG_CFB as sys::TPM_ALG_ID,
                0,
                1,
            )
        };
        check_rc(rc)?;
        t.objectAttributes |= (sys::TPMA_OBJECT_mask_TPMA_OBJECT_fixedTPM
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_fixedParent)
            as sys::TPMA_OBJECT;
        Ok(Template(t))
    }

    /// ECDH key-agreement key template (NIST P-256, restricted-decrypt with the
    /// ECDH scheme). Use with [`Key::ecdh_gen`](crate::Key::ecdh_gen).
    #[cfg(ecdh)]
    pub fn ecdh() -> Result<Self> {
        // fixedTPM/fixedParent keep this child key non-duplicable (TPM-bound);
        // it is loaded under a storage parent, not an ephemeral primary.
        let attrs = (sys::TPMA_OBJECT_mask_TPMA_OBJECT_decrypt
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_fixedTPM
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_fixedParent
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_sensitiveDataOrigin
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_userWithAuth
            | sys::TPMA_OBJECT_mask_TPMA_OBJECT_noDA) as sys::TPMA_OBJECT;
        // SAFETY: TPMT_PUBLIC is a C POD struct; all-zero is a valid starting state for the ECDH template helper.
        let mut t: sys::TPMT_PUBLIC = unsafe { core::mem::zeroed() };
        // SAFETY: &mut t is a valid, exclusively-borrowed out-param for wolfTPM2_GetKeyTemplate_ECC.
        let rc = unsafe {
            sys::wolfTPM2_GetKeyTemplate_ECC(
                &mut t,
                attrs,
                sys::TPM_ECC_CURVE_T_TPM_ECC_NIST_P256 as sys::TPM_ECC_CURVE,
                sys::TPM_ALG_ID_T_TPM_ALG_ECDH as sys::TPM_ALG_ID,
            )
        };
        check_rc(rc)?;
        t.nameAlg = sys::TPM_ALG_ID_T_TPM_ALG_SHA256 as sys::TPMI_ALG_HASH;
        check_p256(&t, KeyAlg::EccP256)?;
        Ok(Template(t))
    }
}

/// A loaded TPM key. Its handle is unloaded from the TPM when dropped.
///
/// Borrows the [`Device`] it lives on, so it cannot outlive the connection.
pub struct Key<'d> {
    key: UnsafeCell<sys::WOLFTPM2_KEY>,
    dev: *mut sys::WOLFTPM2_DEV,
    _marker: PhantomData<&'d Device>,
}

impl<'d> Key<'d> {
    pub(crate) fn from_raw(dev: *mut sys::WOLFTPM2_DEV, key: sys::WOLFTPM2_KEY) -> Self {
        Key {
            key: UnsafeCell::new(key),
            dev,
            _marker: PhantomData,
        }
    }

    pub(crate) fn kptr(&self) -> *mut sys::WOLFTPM2_KEY {
        self.key.get()
    }

    pub(crate) fn dev(&self) -> *mut sys::WOLFTPM2_DEV {
        self.dev
    }

    pub(crate) fn handle_ptr(&self) -> *mut sys::WOLFTPM2_HANDLE {
        // SAFETY: self.key.get() points into the live, pinned WOLFTPM2_KEY cell for this Key's lifetime.
        unsafe { &mut (*self.key.get()).handle }
    }

    /// The TPM handle value for this key.
    pub fn handle(&self) -> u32 {
        // SAFETY: self.key.get() points into the live, pinned WOLFTPM2_KEY cell for this Key's lifetime.
        unsafe { (*self.key.get()).handle.hndl }
    }

    /// The object's cryptographic Name (the hash of its public area), as
    /// computed by the TPM when the key was loaded. Needed to address the key
    /// in credential activation (see [`Device::make_credential`](crate::Device::make_credential)).
    pub fn name(&self) -> Vec<u8> {
        // SAFETY: self.key.get() is live and n.size, set by the TPM, never exceeds the fixed n.name buffer capacity.
        unsafe {
            let n = &(*self.key.get()).handle.name;
            n.name[..n.size as usize].to_vec()
        }
    }

    /// Set the object's authorization value (used by unseal / authorized ops).
    /// Rejects values larger than the TPM auth buffer rather than truncating.
    pub(crate) fn set_auth(&self, auth: &[u8]) -> Result<()> {
        // SAFETY: self.key.get() is live, and the length check above bounds the copy to h.auth.buffer's fixed size.
        unsafe {
            let h = &mut (*self.key.get()).handle;
            if auth.len() > h.auth.buffer.len() {
                return Err(TpmError(crate::BUFFER_E));
            }
            h.auth.size = auth.len() as u16;
            h.auth.buffer[..auth.len()].copy_from_slice(auth);
        }
        Ok(())
    }

    /// Set the object's auth, zero-padded up to the key's nameAlg digest size
    /// the way `wolfTPM2_CreateKey`/`CreatePrimaryKey` store it. Restoring a
    /// short auth verbatim would not match the padded value the TPM holds.
    pub(crate) fn set_auth_padded(&self, auth: &[u8]) -> Result<()> {
        // SAFETY: self.key.get() points into the live, pinned WOLFTPM2_KEY cell for this Key's lifetime.
        let name_alg = unsafe { (*self.key.get()).pub_.publicArea.nameAlg };
        // SAFETY: name_alg is a valid TPM_ALG_ID read from the loaded key's own public area.
        let dsz = unsafe { sys::TPM2_GetHashDigestSize(name_alg) };
        if dsz > 0 && auth.len() < dsz as usize {
            let mut padded = vec![0u8; dsz as usize];
            padded[..auth.len()].copy_from_slice(auth);
            let r = self.set_auth(&padded);
            for b in padded.iter_mut() {
                // SAFETY: b is a valid &mut u8 into the live padded Vec; the volatile write scrubs it from the compiler's view.
                unsafe { core::ptr::write_volatile(b, 0) };
            }
            r
        } else {
            self.set_auth(auth)
        }
    }

    /// The public key's algorithm id (`TPM_ALG_RSA` or `TPM_ALG_ECC`).
    pub(crate) fn alg(&self) -> sys::TPM_ALG_ID {
        // SAFETY: self.key.get() points into the live, pinned WOLFTPM2_KEY cell for this Key's lifetime.
        unsafe { (*self.key.get()).pub_.publicArea.type_ }
    }

    /// Export this key's public part. `pem` selects PEM, otherwise DER (ASN.1).
    #[cfg(pubexport)]
    pub fn export_public(&self, pem: bool) -> Result<Vec<u8>> {
        let mut out = vec![0u8; 2048];
        let mut out_sz = out.len() as sys::word32;
        let enc = if pem {
            sys::ENCODING_TYPE_PEM
        } else {
            sys::ENCODING_TYPE_ASN1
        } as core::ffi::c_int;
        // SAFETY: self.dev/self.kptr() are live pointers, and out.as_mut_ptr()/out_sz describe the full out Vec capacity.
        let rc = unsafe {
            sys::wolfTPM2_ExportPublicKeyBuffer(self.dev, self.kptr(), enc, out.as_mut_ptr(), &mut out_sz)
        };
        check_rc(rc)?;
        out.truncate(out_sz as usize);
        Ok(out)
    }

    pub(crate) fn create_primary(
        dev: &'d Device,
        hierarchy: Hierarchy,
        alg: KeyAlg,
        auth: Option<&[u8]>,
    ) -> Result<Self> {
        let devp = dev.ptr();
        let mut tmpl = Template::srk(alg)?;
        // SAFETY: WOLFTPM2_KEY is a C POD struct; all-zero is a valid starting state for CreatePrimaryKey to fill.
        let mut key: sys::WOLFTPM2_KEY = unsafe { core::mem::zeroed() };
        let (authp, authsz) = auth_ptr(auth)?;
        // SAFETY: devp is the pinned dev pointer, &mut key/&mut tmpl.0 are valid exclusive out-params, and authp/authsz match (auth's ptr, len) or (null, 0).
        let rc = unsafe {
            sys::wolfTPM2_CreatePrimaryKey(
                devp,
                &mut key,
                hierarchy.handle(),
                &mut tmpl.0,
                authp,
                authsz,
            )
        };
        if rc != 0 {
            // The C call can copy the padded auth into `key` before failing;
            // scrub the stack copy before discarding it.
            unsafe { crate::zeroize_raw(&mut key) };
            return Err(TpmError(rc));
        }
        Ok(Key::from_raw(devp, key))
    }
}

impl<'d> Drop for Key<'d> {
    fn drop(&mut self) {
        // SAFETY: self.dev/self.key.get() are still valid on drop; the key is unloaded before its storage is zeroized.
        unsafe {
            sys::wolfTPM2_UnloadHandle(self.dev, &mut (*self.key.get()).handle);
            crate::zeroize_raw(&mut *self.key.get());
        }
    }
}

/// A created-but-not-loaded key: the wrapped `pub`/`priv` blob that can be
/// serialized for persistence and later [`load`](KeyBlob::load)ed.
pub struct KeyBlob<'d> {
    blob: UnsafeCell<sys::WOLFTPM2_KEYBLOB>,
    dev: *mut sys::WOLFTPM2_DEV,
    _marker: PhantomData<&'d Device>,
}

impl<'d> KeyBlob<'d> {
    pub(crate) fn from_parts(dev: *mut sys::WOLFTPM2_DEV, blob: sys::WOLFTPM2_KEYBLOB) -> Self {
        KeyBlob {
            blob: UnsafeCell::new(blob),
            dev,
            _marker: PhantomData,
        }
    }

    /// Serialize the (public + encrypted-private) blob to bytes for storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; core::mem::size_of::<sys::WOLFTPM2_KEYBLOB>() + 32];
        // SAFETY: buf.as_mut_ptr()/buf.len() describe the full buf Vec capacity, and self.blob.get() is the live blob cell.
        let n = unsafe {
            sys::wolfTPM2_GetKeyBlobAsBuffer(buf.as_mut_ptr(), buf.len() as sys::word32, self.blob.get())
        };
        if n < 0 {
            return Err(TpmError(n));
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    /// Rebuild a blob from [`to_bytes`](KeyBlob::to_bytes) output.
    pub fn from_bytes(dev: &'d Device, bytes: &[u8]) -> Result<Self> {
        // SAFETY: WOLFTPM2_KEYBLOB is a C POD struct; all-zero is a valid starting state for SetKeyBlobFromBuffer to fill.
        let mut blob: sys::WOLFTPM2_KEYBLOB = unsafe { core::mem::zeroed() };
        let mut tmp = bytes.to_vec();
        // SAFETY: &mut blob is a valid out-param, and tmp.as_mut_ptr()/tmp.len() describe the live tmp Vec.
        let rc = unsafe {
            sys::wolfTPM2_SetKeyBlobFromBuffer(&mut blob, tmp.as_mut_ptr(), tmp.len() as sys::word32)
        };
        // Scrub the temporary copy on every path.
        for b in tmp.iter_mut() {
            // SAFETY: b is a valid &mut u8 into the live tmp Vec; the volatile write scrubs it from the compiler's view.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        check_rc(rc)?;
        Ok(KeyBlob {
            blob: UnsafeCell::new(blob),
            dev: dev.ptr(),
            _marker: PhantomData,
        })
    }

    /// Load the blob into the TPM under `parent`, yielding a live [`Key`].
    ///
    /// The object's authorization value is **not** part of the serialized blob,
    /// so pass the original `auth` (or `None`) to restore it; without it, an
    /// auth-protected key would load but fail authorization on first use.
    pub fn load(self, parent: &Key<'d>, auth: Option<&[u8]>) -> Result<Key<'d>> {
        // SAFETY: self.dev/self.blob.get() are live, and parent.handle_ptr() points at parent's own pinned handle.
        let rc = unsafe {
            sys::wolfTPM2_LoadKey(self.dev, self.blob.get(), parent.handle_ptr())
        };
        check_rc(rc)?;
        // The handle now lives in the blob; move handle+public into a Key and
        // hand ownership over so only the Key unloads it.
        // SAFETY: self.blob.get() is the live blob cell LoadKey just populated.
        let blob = unsafe { &*self.blob.get() };
        // SAFETY: WOLFTPM2_KEY is a C POD struct; all-zero is a valid starting state before copying fields from blob.
        let mut key: sys::WOLFTPM2_KEY = unsafe { core::mem::zeroed() };
        key.handle = blob.handle;
        key.pub_ = blob.pub_;
        let out = Key::from_raw(self.dev, key);
        if let Some(a) = auth {
            out.set_auth_padded(a)?;
        }
        Ok(out)
    }
}

impl<'d> Drop for KeyBlob<'d> {
    fn drop(&mut self) {
        // SAFETY: self.blob.get() is still valid on drop, the sole reference to it.
        unsafe { crate::zeroize_raw(&mut *self.blob.get()) };
    }
}

impl Device {
    /// Create the endorsement key (EK) under the endorsement hierarchy.
    pub fn create_ek(&self, alg: KeyAlg) -> Result<Key<'_>> {
        // SAFETY: WOLFTPM2_KEY is a C POD struct; all-zero is a valid starting state for CreateEK to fill.
        let mut key: sys::WOLFTPM2_KEY = unsafe { core::mem::zeroed() };
        // SAFETY: self.ptr() is the pinned dev pointer and &mut key is a valid exclusive out-param.
        let rc = unsafe { sys::wolfTPM2_CreateEK(self.ptr(), &mut key, alg.alg_id()) };
        check_rc(rc)?;
        Ok(Key::from_raw(self.ptr(), key))
    }

    /// Create a child key under `parent` from `template`, returning its blob
    /// (not yet loaded). Persist with [`KeyBlob::to_bytes`].
    pub fn create_key(
        &self,
        parent: &Key<'_>,
        template: &Template,
        auth: Option<&[u8]>,
    ) -> Result<KeyBlob<'_>> {
        // SAFETY: WOLFTPM2_KEYBLOB is a C POD struct; all-zero is a valid starting state for CreateKey to fill.
        let mut blob: sys::WOLFTPM2_KEYBLOB = unsafe { core::mem::zeroed() };
        let mut tmpl = template.0;
        let (authp, authsz) = auth_ptr(auth)?;
        // SAFETY: self.ptr()/parent.handle_ptr() are live, &mut blob/&mut tmpl are valid out-params, authp/authsz match (ptr, len) or (null, 0).
        let rc = unsafe {
            sys::wolfTPM2_CreateKey(
                self.ptr(),
                &mut blob,
                parent.handle_ptr(),
                &mut tmpl,
                authp,
                authsz,
            )
        };
        if rc != 0 {
            unsafe { crate::zeroize_raw(&mut blob) };
            return Err(TpmError(rc));
        }
        Ok(KeyBlob {
            blob: UnsafeCell::new(blob),
            dev: self.ptr(),
            _marker: PhantomData,
        })
    }

    /// Create a child key under `parent` and load it in one step.
    pub fn create_and_load(
        &self,
        parent: &Key<'_>,
        template: &Template,
        auth: Option<&[u8]>,
    ) -> Result<Key<'_>> {
        // SAFETY: WOLFTPM2_KEY is a C POD struct; all-zero is a valid starting state for CreateAndLoadKey to fill.
        let mut key: sys::WOLFTPM2_KEY = unsafe { core::mem::zeroed() };
        let mut tmpl = template.0;
        let (authp, authsz) = auth_ptr(auth)?;
        // SAFETY: self.ptr()/parent.handle_ptr() are live, &mut key/&mut tmpl are valid out-params, authp/authsz match (ptr, len) or (null, 0).
        let rc = unsafe {
            sys::wolfTPM2_CreateAndLoadKey(
                self.ptr(),
                &mut key,
                parent.handle_ptr(),
                &mut tmpl,
                authp,
                authsz,
            )
        };
        if rc != 0 {
            unsafe { crate::zeroize_raw(&mut key) };
            return Err(TpmError(rc));
        }
        Ok(Key::from_raw(self.ptr(), key))
    }

    /// Import an externally generated RSA private key under `parent`, wrapping
    /// it as a TPM key blob. `modulus` is the public modulus, `exponent` the
    /// public exponent (e.g. `0x10001`), and `prime` one private prime — the
    /// TPM derives the rest of the sensitive area. Persist with
    /// [`KeyBlob::to_bytes`], load with [`KeyBlob::load`].
    #[cfg(import)]
    pub fn import_rsa_key(
        &self,
        parent: &Key<'_>,
        modulus: &[u8],
        exponent: u32,
        prime: &[u8],
    ) -> Result<KeyBlob<'_>> {
        // SAFETY: WOLFTPM2_KEYBLOB is a C POD struct; all-zero is a valid starting state for ImportRsaPrivateKey to fill.
        let mut blob: sys::WOLFTPM2_KEYBLOB = unsafe { core::mem::zeroed() };
        // SAFETY: self.ptr()/parent.kptr() are live, &mut blob is a valid out-param, and modulus/prime ptr+len each describe their live slice.
        let rc = unsafe {
            sys::wolfTPM2_ImportRsaPrivateKey(
                self.ptr(),
                parent.kptr() as *const sys::WOLFTPM2_KEY,
                &mut blob,
                modulus.as_ptr(),
                modulus.len() as sys::word32,
                exponent as sys::word32,
                prime.as_ptr(),
                prime.len() as sys::word32,
                sys::TPM_ALG_ID_T_TPM_ALG_NULL as sys::TPMI_ALG_RSA_SCHEME,
                sys::TPM_ALG_ID_T_TPM_ALG_NULL as sys::TPMI_ALG_HASH,
            )
        };
        if rc != 0 {
            // The imported private material may be partly copied into `blob`
            // before a failure; scrub the stack copy before discarding it.
            unsafe { crate::zeroize_raw(&mut blob) };
            return Err(TpmError(rc));
        }
        Ok(KeyBlob::from_parts(self.ptr(), blob))
    }

    /// Import an externally generated NIST P-256 ECC private key under `parent`.
    /// `x`/`y` are the public point coordinates and `d` the private scalar.
    #[cfg(import)]
    pub fn import_ecc_key(
        &self,
        parent: &Key<'_>,
        x: &[u8],
        y: &[u8],
        d: &[u8],
    ) -> Result<KeyBlob<'_>> {
        // SAFETY: WOLFTPM2_KEYBLOB is a C POD struct; all-zero is a valid starting state for ImportEccPrivateKey to fill.
        let mut blob: sys::WOLFTPM2_KEYBLOB = unsafe { core::mem::zeroed() };
        // SAFETY: self.ptr()/parent.kptr() are live, &mut blob is a valid out-param, and x/y/d ptr+len each describe their live slice.
        let rc = unsafe {
            sys::wolfTPM2_ImportEccPrivateKey(
                self.ptr(),
                parent.kptr() as *const sys::WOLFTPM2_KEY,
                &mut blob,
                sys::TPM_ECC_CURVE_T_TPM_ECC_NIST_P256 as c_int,
                x.as_ptr(),
                x.len() as sys::word32,
                y.as_ptr(),
                y.len() as sys::word32,
                d.as_ptr(),
                d.len() as sys::word32,
            )
        };
        if rc != 0 {
            // The imported private material may be partly copied into `blob`
            // before a failure; scrub the stack copy before discarding it.
            unsafe { crate::zeroize_raw(&mut blob) };
            return Err(TpmError(rc));
        }
        Ok(KeyBlob::from_parts(self.ptr(), blob))
    }
}

/// Map an optional auth slice to a `(ptr, len)` pair for the C API.
/// Confirm an ECC template actually resolved to NIST P-256. The C helpers use
/// the build's default ECC curve, which a `NO_ECC256` build makes P-384/P-521
/// (updating name alg, scheme, and coordinate sizes together). Rather than
/// partially rewrite that into an inconsistent template, fail cleanly so
/// `KeyAlg::EccP256` never silently produces another curve.
fn check_p256(t: &sys::TPMT_PUBLIC, alg: KeyAlg) -> Result<()> {
    if alg == KeyAlg::EccP256 {
        // SAFETY: the caller ran an ECC template helper (type = ECC), so
        // eccDetail is the active variant of the parameters union.
        let curve = unsafe { t.parameters.eccDetail.curveID };
        if curve != sys::TPM_ECC_CURVE_T_TPM_ECC_NIST_P256 as sys::TPM_ECC_CURVE {
            return Err(TpmError(crate::BUFFER_E));
        }
    }
    Ok(())
}

pub(crate) fn auth_ptr(auth: Option<&[u8]>) -> Result<(*const sys::byte, c_int)> {
    match auth {
        // A TPM authorization value is at most the largest hash digest (64 bytes
        // for SHA-512). Reject anything longer up front so the length can never
        // wrap when narrowed to c_int and be misread by the C layer as small or
        // negative.
        Some(a) if a.len() > MAX_AUTH_LEN => Err(TpmError(crate::BUFFER_E)),
        Some(a) => Ok((a.as_ptr(), a.len() as c_int)),
        None => Ok((core::ptr::null(), 0)),
    }
}

/// Maximum TPM authorization value length (the SHA-512 digest size).
pub(crate) const MAX_AUTH_LEN: usize = 64;
