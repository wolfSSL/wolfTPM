//! Persistent key handles: move a key into the TPM's non-volatile store so it
//! survives a reboot, read it back, and evict it. This is how a machine key or
//! root storage key is kept across boots.
//!
//! Persisting and evicting run under the given hierarchy assuming it is
//! unauthenticated (empty owner / platform auth), the device-identity case.
//! TPMs with a non-empty hierarchy authorization are not supported here.

use crate::device::Device;
use crate::key::{Hierarchy, Key};
use crate::{check_rc, sys, Result};

impl Device {
    /// Store `key` at `persistent_handle` (a value in the
    /// `0x8100_0000`..`0x81FF_FFFF` range) under `hierarchy`. After this the key
    /// survives a reboot. `key`'s live handle becomes the persistent handle.
    pub fn persist_key(
        &self,
        key: &Key<'_>,
        hierarchy: Hierarchy,
        persistent_handle: u32,
    ) -> Result<()> {
        // SAFETY: self.ptr() is live and key.kptr() addresses the live, loaded key being persisted.
        let rc = unsafe {
            sys::wolfTPM2_NVStoreKey(self.ptr(), hierarchy.handle(), key.kptr(), persistent_handle)
        };
        check_rc(rc)
    }

    /// Read a key already persisted at `persistent_handle`. `auth` restores the
    /// object's authorization value (the same one it was created with) so the
    /// returned key can perform private operations; pass `None` for an
    /// unauthenticated key. Reading recovers only the public area, so the auth
    /// must be supplied here to sign or decrypt with a protected key.
    pub fn read_persistent(&self, persistent_handle: u32, auth: Option<&[u8]>) -> Result<Key<'_>> {
        // SAFETY: WOLFTPM2_KEY is a C POD struct; all-zero is a valid starting state for ReadPublicKey to fill.
        let mut key: sys::WOLFTPM2_KEY = unsafe { core::mem::zeroed() };
        // SAFETY: self.ptr() is live and &mut key is a valid, exclusively-borrowed out-param.
        let rc = unsafe { sys::wolfTPM2_ReadPublicKey(self.ptr(), &mut key, persistent_handle) };
        check_rc(rc)?;
        let k = Key::from_raw(self.ptr(), key);
        if let Some(a) = auth {
            k.set_auth_padded(a)?;
        }
        Ok(k)
    }

    /// Evict (remove) a persistent key from the TPM's non-volatile store. `key`
    /// must refer to the persistent handle (for example from [`persist_key`] or
    /// [`read_persistent`]).
    ///
    /// [`persist_key`]: Device::persist_key
    /// [`read_persistent`]: Device::read_persistent
    pub fn evict_key(&self, key: &Key<'_>, hierarchy: Hierarchy) -> Result<()> {
        // SAFETY: self.ptr() is live and key.kptr() addresses the persistent key handle being evicted.
        let rc =
            unsafe { sys::wolfTPM2_NVDeleteKey(self.ptr(), hierarchy.handle(), key.kptr()) };
        check_rc(rc)
    }
}
