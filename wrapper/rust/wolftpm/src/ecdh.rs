//! ECDH key agreement on a TPM-resident ECC key (NIST P-256).

use crate::key::Key;
use crate::{check_rc, sys, Result, Secret, TpmError};
use core::ffi::c_int;

/// An ephemeral ECDH public point (`x || y`, each the curve's field size) and
/// the derived shared secret Z, from [`Key::ecdh_gen`].
pub struct EcdhResult {
    /// The ephemeral public point as `x || y` bytes; feed to a peer, or back to
    /// [`Key::ecdh_z`] to recover the same secret.
    pub point: Vec<u8>,
    /// The derived shared secret Z.
    pub secret: Secret,
}

impl<'d> Key<'d> {
    /// One-shot ephemeral ECDH: the TPM generates an ephemeral key pair, derives
    /// Z against this key's private part, and returns the ephemeral public point
    /// plus Z. A peer holding this key's private part can recover the same Z from
    /// the point via [`ecdh_z`](Key::ecdh_z).
    pub fn ecdh_gen(&self) -> Result<EcdhResult> {
        // SAFETY: TPM2B_ECC_POINT is a C POD struct; all-zero is a valid starting state for ECDHGen to fill.
        let mut pt: sys::TPM2B_ECC_POINT = unsafe { core::mem::zeroed() };
        let mut secret = vec![0u8; 128];
        let mut secret_sz = secret.len() as c_int;
        // SAFETY: self.dev()/self.kptr() are live, &mut pt is a valid out-param, and secret.as_mut_ptr()/&mut secret_sz describe the full secret capacity.
        let rc = unsafe {
            sys::wolfTPM2_ECDHGen(
                self.dev(),
                self.kptr(),
                &mut pt,
                secret.as_mut_ptr(),
                &mut secret_sz,
            )
        };
        check_rc(rc)?;
        secret.truncate(secret_sz as usize);
        Ok(EcdhResult {
            point: point_bytes(&pt),
            secret: Secret::new(secret),
        })
    }

    /// Recompute the shared secret Z from a peer's public `point` (`x || y`, the
    /// output of [`ecdh_gen`](Key::ecdh_gen)) and this key's private part.
    pub fn ecdh_z(&self, point: &[u8]) -> Result<Secret> {
        let pt = point_from_bytes(point)?;
        let mut secret = vec![0u8; 128];
        let mut secret_sz = secret.len() as c_int;
        // SAFETY: self.dev()/self.kptr() are live, &pt is the caller-built valid peer point, and secret.as_mut_ptr()/&mut secret_sz describe the full secret capacity.
        let rc = unsafe {
            sys::wolfTPM2_ECDHGenZ(
                self.dev(),
                self.kptr(),
                &pt,
                secret.as_mut_ptr(),
                &mut secret_sz,
            )
        };
        check_rc(rc)?;
        secret.truncate(secret_sz as usize);
        Ok(Secret::new(secret))
    }
}

/// Serialize a `TPM2B_ECC_POINT` to `x || y` bytes.
fn point_bytes(pt: &sys::TPM2B_ECC_POINT) -> Vec<u8> {
    let x = &pt.point.x;
    let y = &pt.point.y;
    let (xn, yn) = (x.size as usize, y.size as usize);
    let mut v = Vec::with_capacity(xn + yn);
    v.extend_from_slice(&x.buffer[..xn]);
    v.extend_from_slice(&y.buffer[..yn]);
    v
}

/// Build a `TPM2B_ECC_POINT` from an `x || y` byte string (split in half).
fn point_from_bytes(point: &[u8]) -> Result<sys::TPM2B_ECC_POINT> {
    if point.is_empty() || point.len() % 2 != 0 {
        return Err(TpmError(crate::BUFFER_E));
    }
    let half = point.len() / 2;
    // SAFETY: TPM2B_ECC_POINT is a C POD struct; all-zero is a valid starting state before the checked field copies below.
    let mut pt: sys::TPM2B_ECC_POINT = unsafe { core::mem::zeroed() };
    if half > pt.point.x.buffer.len() {
        return Err(TpmError(crate::BUFFER_E));
    }
    pt.point.x.size = half as u16;
    pt.point.x.buffer[..half].copy_from_slice(&point[..half]);
    pt.point.y.size = half as u16;
    pt.point.y.buffer[..half].copy_from_slice(&point[half..]);
    Ok(pt)
}
