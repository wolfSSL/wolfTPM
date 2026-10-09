# wolfTPM

Portable TPM 2.0 project designed for embedded use. This manual covers building wolfTPM, configuring it for your hardware, using the native and wrapper APIs, and running the firmware TPM (fwTPM) and the post-quantum and SPDM features.

## Project Features

* This implementation provides all TPM 2.0 API's in compliance with the specification.
* Wrappers provided to simplify Key Generation/Loading, RSA encrypt/decrypt, ECC sign/verify, ECDH, NV, Hashing/HACM, AES, Sealing/Unsealing, Attestation, PCR Extend/Quote and Secure Root of Trust.
* Any TPM 2.0 compliant module is supported. Tested modules include Infineon SLB9670, SLB9672, SLB9673, STMicroelectronics ST33KTPM2XSPI, ST33KTPM2I, ST33TPHF2XSPI, ST33TPHF2XI2C, Microchip ATTPM20, Nations Technologies/NSING Z32H330, NS350, Nuvoton NPCT650, NPCT750, and SealSQ QVault TPM (first TPM with post-quantum ML-DSA/ML-KEM in silicon).
* wolfTPM uses the TPM Interface Specification (TIS) to communicate either over SPI, or using a memory mapped I/O range.
* On Linux, wolfTPM can auto-detect between the kernel TPM driver (`/dev/tpmX`) and direct SPI access at runtime. Enable it with `--enable-autodetect` (a bare `./configure` on a common host defaults to the software TPM instead).
* wolfTPM can also use the Linux TPM kernel interface (`/dev/tpmX`) to talk with any physical TPM on SPI, I2C and even LPC bus.
* Platform support for Raspberry Pi (Linux), MMIO, STM32 with CubeMX, Atmel ASF, Xilinx, QNX, Infineon TriCore, wolfHAL and Barebox.
* The design allows for easy portability to different platforms:
    * Native C code designed for embedded use.
    * Single IO callback for hardware SPI interface.
    * No external dependencies.
    * Compact code size and minimal memory use.
* Includes example code for:
    * Most TPM2 native API's
    * All TPM2 wrapper API's
    * PKCS 7
    * Certificate Signing Request (CSR)
    * TLS Client
    * TLS Server
    * Use of the TPM's Non-volatile memory
    * Attestation (activate and make credential)
    * Benchmarking TPM algorithms and TLS
    * Key Generation (primary, RSA/ECC and symmetric), loading and storing to flash (NV memory)
    * Sealing and Unsealing data with an RSA key or externally signed policy.
    * Time signed or set
    * PCR read/reset
    * GPIO configure, read and write.
    * Endorsement Key/Cert retrieval and validation.
* Parameter encryption support using AES-CFB or XOR.
* Support for salted unbound authenticated sessions.
* Support for HMAC Sessions.
* Support for reading Endorsement certificates (EK Credential Profile).
* Includes a portable firmware TPM 2.0 implementation (fwTPM, also known as fTPM / swtpm) for embedded platforms without a discrete TPM chip. See [fwTPM Overview](fwtpm/overview.md).
* **Post-quantum cryptography support** via TPM 2.0 Library Specification v1.85: ML-DSA (FIPS 204) signing and ML-KEM (FIPS 203) key encapsulation, enabled with `--enable-v185` (full v1.85) or the leaner `--enable-pqc` (ML-DSA / ML-KEM only), with per-operation trimming via `--enable-mldsa`/`--enable-mlkem`. Auto-detected when `--enable-fwtpm` is built against a wolfCrypt that has ML-DSA + ML-KEM. Both the client library and the fwTPM server implement the eight new v1.85 PQC commands. See [Post-Quantum Cryptography](post-quantum.md).
* **SPDM attestation support** (DMTF DSP0274) over the TCG SPDM-over-TPM binding, with a TCG certificate handshake and a DSP0274 pre-shared-key (PSK) handshake, enabled with `--enable-spdm`. The fwTPM server includes an SPDM 1.3 responder so the stack can be exercised end-to-end in CI without discrete silicon. See [SPDM Attestation](spdm.md).

## Standards and Features

| Area | Status | Enable flag | Page |
| --- | --- | --- | --- |
| TPM 2.0 specification | Native API for the TPM 2.0 command set, with wrappers for common operations | Always built | [API Reference](api-reference.md) |
| TCG TPM 2.0 Library Specification revision 1.85 | Post-quantum commands implemented in the client library and fwTPM server | `--enable-v185` (full v1.85) | [Build Options](build-options.md) |
| Post-quantum: ML-DSA (FIPS 204) and ML-KEM (FIPS 203) | Client library and fwTPM server; SealSQ QVault in silicon | `--enable-pqc` (ML-DSA / ML-KEM only), `--enable-mldsa`, `--enable-mlkem` | [Post-Quantum Cryptography](post-quantum.md) |
| SPDM attestation (TCG certificate handshake and DSP0274 PSK handshake) | Client library, plus an SPDM 1.3 responder in fwTPM | `--enable-spdm` | [SPDM Attestation](spdm.md) |
| Parameter encryption (AES-CFB or XOR) | Supported, along with salted unbound and HMAC sessions | Set up per session at run time | [API Reference](api-reference.md) |
| EK Credential Profile | Endorsement certificate reading (`examples/endorsement/get_ek_certs`) | Always built | [Getting Started](getting-started.md) |
| Device Identity (IAK / IDevID) | Tested with the ST33KTPM; default keys are ECDSA SECP384R1 with SHA2-384 in NV | `WOLFTPM_MFG_IDENTITY` | [Supported Hardware](supported-hardware.md) |
| Firmware TPM (fwTPM / fTPM / swtpm) | Portable TPM 2.0 server built on wolfCrypt | `--enable-fwtpm` | [fwTPM Overview](fwtpm/overview.md) |

## Documentation map

* [Getting Started](getting-started.md): first steps after installing.
* [Building](building.md): build wolfTPM from source.
* [Build Options](build-options.md): configure flags and the defines they set.
* [Supported Hardware](supported-hardware.md): tested TPM modules and platforms.
* [TPM 2.0 Overview](tpm2-overview.md): hierarchies, PCRs and device identification.
* [Project Structure](project-structure.md): source tree layout.
* [Post-Quantum Cryptography](post-quantum.md): ML-DSA and ML-KEM support.
* [SPDM Attestation](spdm.md): SPDM handshakes and the responder.
* [fwTPM Overview](fwtpm/overview.md): the firmware TPM server.
* [API Reference](api-reference.md): native and wrapper APIs.

## See Also

* [Getting Started](getting-started.md)
* [Build Options](build-options.md)
* [Supported Hardware](supported-hardware.md)
* [fwTPM Overview](fwtpm/overview.md)
