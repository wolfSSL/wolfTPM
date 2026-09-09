//! TPM self-test and capability discovery.

use crate::device::Device;
use crate::{check_rc, sys, Result};

/// A subset of the TPM's reported capabilities.
#[derive(Clone, Debug, Default)]
pub struct Caps {
    /// Manufacturer id string (e.g. `"IBM"`, `"STM"`, `"NTC"`).
    pub manufacturer: String,
    /// Vendor detail string.
    pub vendor: String,
    /// Firmware version, major and minor.
    pub fw_version_major: u16,
    pub fw_version_minor: u16,
    /// TPM operating in a FIPS 140-2 validated mode.
    pub fips_140_2: bool,
    /// TPM operating in a FIPS 140-3 validated mode.
    pub fips_140_3: bool,
    /// Common Criteria EAL4+ certified.
    pub cc_eal4: bool,
}

/// Read a fixed-size C `char` array up to its first NUL into a `String`.
fn c_str(arr: &[core::ffi::c_char]) -> String {
    let bytes: Vec<u8> = arr
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

impl Device {
    /// Run the TPM's self-test of all its algorithms. A common first call to
    /// confirm the TPM is healthy before use.
    #[cfg(caps)]
    pub fn self_test(&self) -> Result<()> {
        // SAFETY: self.ptr() is the pinned dev pointer for the life of this Device.
        let rc = unsafe { sys::wolfTPM2_SelfTest(self.ptr()) };
        check_rc(rc)
    }

    /// Query the TPM's manufacturer, firmware version, and certification flags.
    #[cfg(caps)]
    pub fn capabilities(&self) -> Result<Caps> {
        // SAFETY: WOLFTPM2_CAPS is a C POD struct; all-zero is a valid starting state for GetCapabilities to fill.
        let mut caps: sys::WOLFTPM2_CAPS = unsafe { core::mem::zeroed() };
        // SAFETY: self.ptr() is live and &mut caps is a valid, exclusively-borrowed out-param.
        let rc = unsafe { sys::wolfTPM2_GetCapabilities(self.ptr(), &mut caps) };
        check_rc(rc)?;
        Ok(Caps {
            manufacturer: c_str(&caps.mfgStr),
            vendor: c_str(&caps.vendorStr),
            fw_version_major: caps.fwVerMajor,
            fw_version_minor: caps.fwVerMinor,
            fips_140_2: caps.fips140_2() != 0,
            fips_140_3: caps.fips140_3() != 0,
            cc_eal4: caps.cc_eal4() != 0,
        })
    }
}
