//! Parameter-encryption sessions. While a [`Session`] is alive, command and
//! response parameters of the secret-bearing operations (seal/unseal, RSA and
//! AES encrypt/decrypt, HMAC, NV, ECDH, key create/load) travel encrypted over
//! the TPM transport instead of in the clear.

use crate::device::Device;
use crate::key::Key;
use crate::{sys, Result, TpmError, E_SESSION_IN_USE};
use core::ffi::c_int;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};

/// Auth slot the encryption session occupies. It sits at slot 1, immediately
/// after a command's own object authorization at slot 0. wolfTPM's command
/// builder (`TPM2_GetCmdAuthCount`) then includes it as an encrypt/decrypt
/// session for every parameter-encryption-capable command, with no gap that
/// would drop it. The 2-auth attestation commands (certify, quote, activate)
/// need slot 1 for their second handle, so they are refused while a session is
/// live rather than silently displacing it.
const SESSION_SLOT: c_int = 1;

/// Only one encryption session may be live at a time; it holds slot 1 for its
/// whole lifetime so wolfTPM can roll its nonce across commands.
static SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether an encryption session currently holds the auth slot. Used by the
/// attestation commands to refuse rather than clobber it.
pub(crate) fn is_active() -> bool {
    SESSION_ACTIVE.load(Ordering::Acquire)
}

/// A salted HMAC session with AES-CFB parameter encryption, registered at auth
/// slot 1 for its whole lifetime. Once started, the secret-bearing operations
/// have their sensitive command/response parameters encrypted automatically.
/// Only one is allowed at a time; it is closed and its slot released on drop.
pub struct Session<'d> {
    session: sys::WOLFTPM2_SESSION,
    dev: *mut sys::WOLFTPM2_DEV,
    _marker: PhantomData<&'d Device>,
}

impl Device {
    /// Start a salted HMAC session with AES-CFB parameter encryption, keyed by
    /// `salt` (typically the SRK), and register it so the following
    /// secret-bearing commands are encrypted. Returns an error if a session is
    /// already active.
    ///
    /// While it is alive, the attestation commands [`certify`](Device::certify),
    /// [`quote`](Device::quote), and
    /// [`activate_credential`](Device::activate_credential) are refused, since
    /// they need the same auth slot; drop the session before calling them.
    pub fn start_encrypted_session(&self, salt: &Key<'_>) -> Result<Session<'_>> {
        if SESSION_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(TpmError(E_SESSION_IN_USE));
        }
        // SAFETY: WOLFTPM2_SESSION is a C POD struct; all-zero is a valid starting state for StartSession to fill.
        let mut session: sys::WOLFTPM2_SESSION = unsafe { core::mem::zeroed() };
        // SAFETY: self.ptr() is live, &mut session is a valid out-param, and salt.kptr() addresses the live salt key.
        let rc = unsafe {
            sys::wolfTPM2_StartSession(
                self.ptr(),
                &mut session,
                salt.kptr(),
                core::ptr::null_mut(),
                sys::TPM_SE_T_TPM_SE_HMAC as sys::TPM_SE,
                sys::TPM_ALG_ID_T_TPM_ALG_CFB as c_int,
            )
        };
        if rc != 0 {
            SESSION_ACTIVE.store(false, Ordering::Release);
            return Err(TpmError(rc));
        }

        let attrs = (sys::TPMA_SESSION_mask_TPMA_SESSION_continueSession
            | sys::TPMA_SESSION_mask_TPMA_SESSION_decrypt
            | sys::TPMA_SESSION_mask_TPMA_SESSION_encrypt) as sys::TPMA_SESSION;
        // SAFETY: &mut session still refers to the live session opened above.
        let rc =
            unsafe { sys::wolfTPM2_SetAuthSession(self.ptr(), SESSION_SLOT, &mut session, attrs) };
        if rc != 0 {
            // SAFETY: self.ptr() is live; unload the session and scrub its key
            // material before releasing the slot.
            unsafe {
                sys::wolfTPM2_UnloadHandle(self.ptr(), &mut session.handle);
                crate::zeroize_raw(&mut session);
            }
            SESSION_ACTIVE.store(false, Ordering::Release);
            return Err(TpmError(rc));
        }

        Ok(Session {
            session,
            dev: self.ptr(),
            _marker: PhantomData,
        })
    }
}

impl<'d> Drop for Session<'d> {
    fn drop(&mut self) {
        // SAFETY: self.dev is still valid on drop; clear the auth slot, flush the
        // TPM session, then scrub the derived key/nonces left in the struct.
        unsafe {
            sys::wolfTPM2_UnsetAuth(self.dev, SESSION_SLOT);
            sys::wolfTPM2_UnloadHandle(self.dev, &mut self.session.handle);
            crate::zeroize_raw(&mut self.session);
        }
        SESSION_ACTIVE.store(false, Ordering::Release);
    }
}
