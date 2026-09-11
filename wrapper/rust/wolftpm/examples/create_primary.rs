//! Rust analog of wolfTPM's `examples/keygen/create_primary` against a software
//! TPM. Start a server first, e.g. `ibmswtpm2/src/tpm_server` on :2321.

use wolftpm::{Device, Hierarchy, KeyAlg};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dev = Device::open()?;
    println!("wolfTPM initialized");

    let mut r = [0u8; 16];
    dev.get_random(&mut r)?;
    println!("GetRandom: {}", hex(&r));

    let ecc = dev.create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)?;
    println!("ECC SRK handle: 0x{:08x}", ecc.handle());

    let rsa = dev.create_primary(Hierarchy::Owner, KeyAlg::Rsa, None)?;
    println!("RSA SRK handle: 0x{:08x}", rsa.handle());

    Ok(())
}
