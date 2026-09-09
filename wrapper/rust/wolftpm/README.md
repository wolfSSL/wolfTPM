# wolftpm

Safe Rust bindings for wolfTPM, the portable TPM 2.0 library.

The raw FFI is generated with bindgen and kept in the `sys` module. The rest of
the crate is a safe API: functions return `Result`, TPM handles are released when
they go out of scope, and all `unsafe` stays inside the crate.

## Requirements

- Rust and Cargo, stable, rustc 1.80 or newer.
- A built wolfTPM C library (`libwolftpm`) and its wolfSSL dependency
  (`libwolfssl`). The crate links a prebuilt library. It does not build the C
  code itself.
- For the tests, a software TPM. wolfTPM's own `fwtpm_server` works or any other
  TPM emulator/software TPM.

## Step 1: build the C library

Run these from the wolfTPM repository root:

    ./autogen.sh
    ./configure --enable-swtpm --enable-fwtpm
    make

This produces `src/.libs/libwolftpm`. With `--enable-fwtpm` it also builds the
software TPM server at `src/fwtpm/fwtpm_server`.

## Step 2: build the crate

    cd wrapper/rust/wolftpm
    cargo build

The build finds the libraries in this order:

1. If `WOLFTPM_PREFIX` or `WOLFSSL_PREFIX` are set, it uses `$PREFIX/include` and
   `$PREFIX/lib` of an installed copy.
2. Otherwise it uses the in-tree build: headers from the repo root, libraries
   from `src/.libs`. wolfSSL is located with `pkg-config`, then a local
   `./wolfssl` or a sibling `../wolfssl` checkout.

Shared libraries are preferred. Static is used when no shared library is present.

## Step 3: run the tests

The integration tests talk to a software TPM over a socket. They are behind the
`swtpm-tests` feature, so a plain `cargo test` does not need a running server.

Start a server on port 2321 (from the repo root):

    ./src/fwtpm/fwtpm_server --clear --port 2321 --platform-port 2322 &

Run the tests against it:

    cd wrapper/rust/wolftpm
    TPM2_SWTPM_HOST=localhost TPM2_SWTPM_PORT=2321 \
        cargo test --features swtpm-tests -- --test-threads=1

Use `--test-threads=1` because the software TPM serves one client at a time.

Run a single test file, for example the signing tests:

    cargo test --features swtpm-tests --test sign -- --test-threads=1

The default host and port are `localhost:2321`, so the environment variables can
be omitted when the server is on that address.

## What the tests check

Each file under `tests/` exercises one area against the software TPM:

- `tests/smoke.rs`: random bytes differ across draws, and a primary key loads.
- `tests/keys.rs`: create and load a child key, blob round-trip, short-auth blob
  round-trip, and an auth-protected parent.
- `tests/sign.rs`: sign a digest and verify it, and reject a tampered signature.
- `tests/seal.rs`: seal a secret and unseal it, and fail with the wrong auth.
- `tests/seal_pcr.rs`: PCR-bound seal/unseal, unseal fails after a PCR changes,
  and an invalid PCR selection is rejected.
- `tests/nv.rs`: define an NV index, write and read it, then delete it.
- `tests/pcr.rs`: read a PCR, extend it, and confirm the value changed.
- `tests/certify.rs`: an attestation key (ECC and RSA) certifies another key.
- `tests/quote.rs`: quote PCRs with an ECC and RSA AIK, and reject a bad
  PCR selection.
- `tests/credential.rs`: MakeCredential then ActivateCredential round-trip.
- `tests/ek.rs`: create the endorsement key and export its public part.
- `tests/persist.rs`: persist a key, read it back, and evict it.
- `tests/rsa.rs`: RSA-OAEP encrypt/decrypt, and an explicit OAEP-SHA1 round-trip.
- `tests/hmac.rs`: raw-key HMAC and a TPM-resident keyed-hash key HMAC.
- `tests/caps.rs`: self-test and capability query.
- `tests/ecdh.rs`: ECDH generate then recover the same shared secret.
- `tests/symmetric.rs`: AES-CFB encrypt/decrypt round-trip.
- `tests/import.rs`: import an external RSA and ECC private key.

## Example test output

    running 2 tests
    test certify_with_ecc_aik ... ok
    test certify_with_rsa_aik ... ok
    test result: ok. 2 passed; 0 failed; 0 ignored

    running 4 tests
    test create_and_load_child ... ok
    test key_blob_roundtrip_then_load ... ok
    test key_blob_roundtrip_preserves_short_auth ... ok
    test auth_protected_parent_loads_child ... ok
    test result: ok. 4 passed; 0 failed; 0 ignored

    running 2 tests
    test sign_then_verify ... ok
    test verify_rejects_tampered_signature ... ok
    test result: ok. 2 passed; 0 failed; 0 ignored

    running 2 tests
    test rsa_oaep_roundtrip ... ok
    test rsa_oaep_sha1_roundtrip ... ok
    test result: ok. 2 passed; 0 failed; 0 ignored

    running 1 test
    test make_and_activate_credential ... ok
    test result: ok. 1 passed; 0 failed; 0 ignored

## Step 4: run the examples

There are two examples. The first is minimal:

    cargo run --example create_primary

It opens the software TPM, reads random bytes, and creates an RSA and an ECC
storage root key.

The second runs the whole API in one pass:

    cargo run --example full_flow

Expected output. The random bytes and handle values differ between runs:

    device            connected to software TPM
    get_random        a91b37b1838d002453f1632ba2c0adbc
    create_primary    ECC SRK handle 0x80000000
    create_and_load   signing key handle 0x80000001
    sign/verify       64 byte signature, verified
    seal/unseal       recovered "my secret"
    key blob          257 bytes, reloaded as handle 0x80000002
    pcr read/extend   PCR16 000000000000.. -> debb3e7acfff..
    nv define/rw      32 bytes at index 0x01500100
    certify           157 byte attestation
    done              all operations succeeded

If the wolfTPM C library was built with debug output, you will also see verbose
TPM2_* traces from the library. A normal build prints only the lines above.

## Using the wrapper

```rust
use wolftpm::{Device, HashAlg, Hierarchy, KeyAlg, KeyBlob, Template};

fn main() -> Result<(), wolftpm::TpmError> {
    // Connect to a software TPM. Use Device::open() for the platform default.
    let dev = Device::open_swtpm()?;

    // Random bytes from the TPM.
    let mut nonce = [0u8; 32];
    dev.get_random(&mut nonce)?;

    // Storage root key under the owner hierarchy.
    let srk = dev.create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)?;

    // Signing key under the SRK, then sign and verify a digest.
    let signer = dev.create_and_load(&srk, &Template::signing(KeyAlg::EccP256)?, None)?;
    let digest = [0x11u8; 32];
    let sig = signer.sign_hash(&digest)?;
    signer.verify_hash(&digest, &sig)?;

    // Seal a secret to the TPM and read it back.
    let sealed = dev.seal(&srk, b"my secret", None)?;
    let _secret = dev.unseal(sealed, &srk, None)?;

    // Persist a key as bytes, then load it again. Scope the reloaded key so it
    // releases its TPM handle before more transient objects are created below
    // (many TPMs allow only three transient objects at once).
    let bytes = {
        let blob = dev.create_key(&srk, &Template::signing(KeyAlg::EccP256)?, None)?;
        blob.to_bytes()?
    };
    {
        let restored = KeyBlob::from_bytes(&dev, &bytes)?;
        let _loaded = restored.load(&srk, None)?;
    }

    // Read and extend a PCR.
    let _value = dev.pcr_read(16, HashAlg::Sha256)?;
    dev.pcr_extend(16, HashAlg::Sha256, &[0xAB; 32])?;

    // Define, write, read, and delete an NV index.
    let mut slot = dev.nv_create(0x0150_0100, 32, None)?;
    dev.nv_write(&mut slot, b"metadata", 0)?;
    let mut buf = [0u8; 32];
    dev.nv_read(&mut slot, &mut buf, 0)?;
    dev.nv_delete(0x0150_0100)?;

    // Attest that a key lives in this TPM, signed by an attestation key.
    let aik = dev.create_and_load(&srk, &Template::attestation(KeyAlg::EccP256)?, None)?;
    let _attestation = dev.certify(&signer, &aik, &nonce)?;

    Ok(())
}
```

Keys and the device release their TPM handles automatically when they drop.

## What the crate covers

- Device open and cleanup, TPM random numbers, self-test, and capability query.
- Primary and child keys. Templates for storage, signing, attestation, EK, RSA
  decrypt, keyed-hash HMAC, symmetric AES, and ECDH keys.
- Key blob serialize and load for persistence; external RSA and ECC key import.
- Persistent key handles: store, read back, and evict.
- Sign and verify.
- RSA-OAEP encrypt and decrypt, including an explicit label hash (SHA-1 for
  Microsoft enrollment interop).
- Symmetric AES-CFB encrypt and decrypt.
- ECDH key agreement.
- HMAC, both raw-key and with a TPM-resident keyed-hash key.
- Seal and unseal, plain and bound to a PCR policy.
- PCR read and extend.
- NV define, write, read, delete, and certificate read (EK certificate).
- Attestation: certify a key, and quote PCRs.
- Credential activation: MakeCredential and ActivateCredential.

Recovered secrets (unseal, RSA decrypt, ECDH, AES decrypt, credential
activation) are returned in a `Secret` that zeroizes its buffer on drop.

## Transport security

For confidentiality on the TPM transport, start a parameter-encryption session
with [`Device::start_encrypted_session`] before the secret-bearing operations:

```rust
let srk = dev.create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)?;
let _session = dev.start_encrypted_session(&srk)?;  // salted HMAC + AES-CFB
let sealed = dev.seal(&srk, b"secret", None)?;      // command param encrypted
let plain = dev.unseal(sealed, &srk, None)?;        // response param encrypted
```

While the session is alive its salted HMAC session occupies auth slot 1, so
wolfTPM encrypts the sensitive command and response parameters of seal/unseal,
RSA and AES encrypt/decrypt, HMAC, NV, ECDH, and key create/load. Only one
session is allowed at a time. The attestation commands (certify, quote,
activate_credential) need the same auth slot and are refused while a session is
active; drop the session before calling them. Without a session, parameters
cross the transport in the clear, so either use a session or run over a trusted
local transport (the Linux kernel device or a local socket) rather than a remote
`TPM2_SWTPM_HOST` or an observable physical bus.

## License

GPLv3, or a commercial wolfSSL license, matching wolfTPM.
