# wolftpm Change Log

## v1.0.0

**Summary**

Initial stable release of the official `wolftpm` Rust crate. The crate provides
a safe `no_std` API over the wolfTPM C library, with RAII-managed TPM resources,
zeroization of secret material, parameter-encrypted sessions, and support for
software, operating-system, and embedded TPM transports.

**Detail**

* Safe API and resource management
  - `Device` owns the TPM connection and cleans it up on drop
  - `Key` unloads transient handles on drop, while `KeyBlob` supports wrapped
    key serialization and reloading
  - `Session` manages a salted AES-CFB parameter-encryption session and clears
    its authorization slot on drop
  - `Secret` owns sensitive output and zeroizes its buffer on drop
  - `TpmError` preserves wolfTPM and TPM return codes with `Display`, `Debug`,
    and `core::error::Error` support
* Key creation and lifecycle
  - Create RSA or ECC primary, endorsement, attestation, signing, decryption,
    HMAC, symmetric, and ECDH keys
  - Create, load, serialize, restore, persist, read, and evict TPM keys
  - Import external RSA and ECC private keys
  - Export public keys in DER or PEM form
* Cryptographic operations
  - Sign and verify message digests with TPM-resident RSA and ECC keys
  - RSA-OAEP encryption and decryption with SHA-256 or SHA-1 label hashing
  - AES-CFB encryption and decryption with TPM-resident symmetric keys
  - HMAC with raw key material or TPM-resident keyed-hash keys
  - ECDH ephemeral-key generation and shared-secret derivation
* Protected data and TPM state
  - Seal and unseal data with optional object authorization
  - Seal and unseal data against PCR policies
  - Define, write, read, and delete authorization-protected NV indices
  - Read EK certificates from NV storage
  - Read and extend PCRs, query TPM capabilities, run self-tests, and obtain
    TPM-generated random data
* Attestation and provisioning
  - Certify TPM objects and produce signed PCR quotes
  - Create and activate credentials using endorsement-key policy sessions
  - Start salted parameter-encryption sessions for protected command and
    response data
* Portability and build integration
  - Support `no_std` targets with an application-provided allocator
  - Generate `core`-based FFI bindings for the linked wolfTPM configuration
  - Discover in-tree or installed wolfTPM and wolfSSL headers and libraries
  - Translate Rust target triples for clang and discover bare-metal sysroots
    when cross-compiling, including RISC-V targets
  - Support configured swtpm/fwTPM sockets, Linux TPM devices, MMIO, Windows
    TBS, and caller-provided hardware I/O callbacks
* Examples and validation
  - Add primary-key and full API walkthrough examples
  - Add serialized fwTPM integration coverage for keys, sealing, sessions,
    attestation, credentials, PCRs, NV storage, persistence, RSA, AES, HMAC,
    ECDH, capabilities, and error paths
  - Add compile coverage for the Linux kernel-device transport
  - Add build, Clippy, formatting, documentation, and integration-test CI
