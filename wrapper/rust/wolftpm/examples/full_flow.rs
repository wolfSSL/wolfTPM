//! Full walkthrough of the wolftpm safe API against a software TPM.
//!
//! Start a server first, for example from the repo root:
//!   ./src/fwtpm/fwtpm_server --clear --port 2321 --platform-port 2322 &
//! then:
//!   cargo run --example full_flow

use wolftpm::{Device, HashAlg, Hierarchy, KeyAlg, KeyBlob, Template};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() -> Result<(), wolftpm::TpmError> {
    let dev = Device::open()?;
    println!("device            connected to TPM");

    let mut nonce = [0u8; 16];
    dev.get_random(&mut nonce)?;
    println!("get_random        {}", hex(&nonce));

    let srk = dev.create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)?;
    println!("create_primary    ECC SRK handle 0x{:08x}", srk.handle());

    let signer = dev.create_and_load(&srk, &Template::signing(KeyAlg::EccP256)?, None)?;
    println!("create_and_load   signing key handle 0x{:08x}", signer.handle());

    let digest = [0x11u8; 32];
    let sig = signer.sign_hash(&digest)?;
    signer.verify_hash(&digest, &sig)?;
    println!("sign/verify       {} byte signature, verified", sig.len());

    let sealed = dev.seal(&srk, b"my secret", None)?;
    let secret = dev.unseal(sealed, &srk, None)?;
    println!(
        "seal/unseal       recovered \"{}\"",
        core::str::from_utf8(&secret).unwrap_or("<bytes>")
    );

    // Scope the reloaded key so its handle is freed before the attestation
    // step below. A TPM only holds a few transient objects at once (often 3),
    // so keep the number of simultaneously-loaded keys small.
    {
        let blob = dev.create_key(&srk, &Template::signing(KeyAlg::EccP256)?, None)?;
        let bytes = blob.to_bytes()?;
        let restored = KeyBlob::from_bytes(&dev, &bytes)?;
        let loaded = restored.load(&srk, None)?;
        println!(
            "key blob          {} bytes, reloaded as handle 0x{:08x}",
            bytes.len(),
            loaded.handle()
        );
    }

    let before = dev.pcr_read(16, HashAlg::Sha256)?;
    dev.pcr_extend(16, HashAlg::Sha256, &[0xAB; 32])?;
    let after = dev.pcr_read(16, HashAlg::Sha256)?;
    println!(
        "pcr read/extend   PCR16 {}.. -> {}..",
        hex(&before[..6]),
        hex(&after[..6])
    );

    let index = 0x0150_0100;
    let _ = dev.nv_delete(index);
    let mut slot = dev.nv_create(index, 32, None)?;
    dev.nv_write(&mut slot, b"metadata", 0)?;
    let mut buf = [0u8; 32];
    let n = dev.nv_read(&mut slot, &mut buf, 0)?;
    dev.nv_delete(index)?;
    println!("nv define/rw      {} bytes at index 0x{:08x}", n, index);

    let aik = dev.create_and_load(&srk, &Template::attestation(KeyAlg::EccP256)?, None)?;
    let att = dev.certify(&signer, &aik, &nonce)?;
    println!("certify           {} byte attestation", att.attest.len());

    println!("done              all operations succeeded");
    Ok(())
}
