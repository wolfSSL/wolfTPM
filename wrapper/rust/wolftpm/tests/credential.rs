//! EK-based credential activation (MakeCredential / ActivateCredential).
#![cfg(feature = "swtpm-tests")]

mod common;

use wolftpm::{Hierarchy, KeyAlg, Template};

#[test]
fn make_and_activate_credential() {
    let dev = common::open();

    // Attestation key under an SRK, then free the SRK so only the EK and AIK
    // occupy transient object slots for the activation.
    let aik_name;
    let aik;
    {
        let srk = dev
            .create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)
            .unwrap();
        aik = dev
            .create_and_load(
                &srk,
                &Template::attestation(KeyAlg::EccP256).unwrap(),
                Some(b"aik-auth"),
            )
            .unwrap();
        aik_name = aik.name();
    }
    assert!(!aik_name.is_empty(), "AIK must have a computed Name");

    let ek = dev.create_ek(KeyAlg::Rsa).unwrap();

    // Verifier side: seal a secret to this TPM's EK, bound to the AIK's Name.
    let secret = b"credential-secret-0123456789abcd";
    let cred = dev.make_credential(&ek, &aik_name, secret).unwrap();
    assert!(!cred.credential_blob.is_empty());
    assert!(!cred.secret.is_empty());

    // TPM side: recover it, proving the AIK and EK share this TPM.
    let recovered = dev.activate_credential(&aik, &ek, &cred).unwrap();
    assert_eq!(
        recovered.as_bytes(),
        &secret[..],
        "activated credential must recover the original secret"
    );
}
