//! Shared test harness. Assumes a software TPM (fwtpm_server / ibmswtpm2) is
//! listening on `TPM2_SWTPM_HOST:TPM2_SWTPM_PORT` (default localhost:2321) —
//! the run script / CI starts one; tests connect to it.

use wolftpm::Device;

/// Open a connection to the software TPM, or fail with a clear message.
pub fn open() -> Device {
    Device::open_swtpm().expect("open swtpm — is fwtpm_server (or ibmswtpm2) on :2321?")
}
