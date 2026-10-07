# wolfTPM (TPM 2.0)

Portable TPM 2.0 project designed for embedded use.

## Project Features

* Full TPM 2.0 API in compliance with the TCG TPM 2.0 Library Specification, including the revision 1.59 (CertifyX509), 1.84, and 1.85 additions. Revision 1.85 adds the post-quantum ML-DSA (FIPS 204) and ML-KEM (FIPS 203) commands.
* Wrappers that simplify Key Generation and Loading, RSA encrypt and decrypt, ECC sign and verify, ECDH, NV, Hashing and HMAC, AES, Sealing and Unsealing, Attestation, PCR Extend and Quote, and Secure Root of Trust.
* TPM Interface Specification (TIS) communication over SPI or a memory mapped I/O range, with I2C and LPC available through the Linux kernel driver.
* Runtime module auto-detection on Linux between the kernel TPM driver (`/dev/tpmX`) and direct SPI access.
* Easy portability: native C for embedded use, a single IO callback for the hardware SPI interface, no external dependencies, and a compact code size.
* Parameter encryption using AES-CFB or XOR, salted unbound authenticated sessions, HMAC sessions, and Endorsement certificate reading (EK Credential Profile).
* A portable firmware TPM 2.0 (fwTPM / fTPM / swtpm) for platforms with no discrete TPM, post-quantum cryptography (TPM 2.0 v1.85), and SPDM attestation (see the sections below).
* Example code for the native and wrapper API's, PKCS 7, CSR, TLS client and server, NV storage, attestation, benchmarking, key generation and storage, sealing and unsealing, timestamps, PCR, GPIO, and endorsement key and certificate retrieval.

## Supported Hardware

wolfTPM works with any TPM 2.0 compliant module. Tested parts:

* Infineon OPTIGA SLB9670 (SPI), SLB9672 (SPI), SLB9673 (I2C)
* STMicroelectronics ST33KTPM2XSPI, ST33KTPM2I, ST33TPHF2XSPI, ST33TPHF2XI2C
* Microchip ATTPM20
* Nuvoton NPCT650, NPCT750
* Nations Technologies / NSING Z32H330, NS350
* SealSQ QVault TPM (SPI, the first TPM with post-quantum ML-DSA and ML-KEM in silicon)
* NVIDIA Jetson Orin (Tegra234) firmware TPM, reached through the Linux kernel driver
* The wolfCrypt firmware TPM (fwTPM), for platforms with no discrete TPM chip

Platform support: Raspberry Pi (Linux), Linux `/dev/tpmX`, MMIO, STM32 with CubeMX,
Atmel ASF, Xilinx, QNX, Infineon TriCore, Espressif ESP-IDF, Zephyr, wolfHAL, and
Barebox. See the [Supported Hardware manual](https://www.wolfssl.com/documentation/manuals/wolftpm/supported-hardware.html)
for how to build and wire each part.

## Firmware TPM (fwTPM / fTPM / swtpm)

wolfTPM includes a portable firmware TPM 2.0 implementation (`fwtpm_server`) built
entirely on wolfCrypt. It provides a standards-compliant TPM 2.0 command processor
that can replace a hardware TPM on embedded platforms without a discrete TPM chip,
or serve as a drop-in development and CI/CD replacement for external simulators
like swtpm or the Microsoft TPM simulator.

Features:

* 105 TPM 2.0 commands implemented (93% of the v1.38 spec) with wolfCrypt cryptography (RSA, ECC, SHA, AES, HMAC)
* Socket transport (Microsoft TPM simulator protocol) compatible with tpm2-tools and the wolfTPM examples
* TIS register-level transport over shared memory or SPI/I2C for bare-metal integration
* HAL abstractions for IO transport and NV storage portability
* File-based or custom NV storage via HAL callbacks
* Compile-time algorithm and per-command-group feature selection (for example `NO_RSA`, `FWTPM_NO_NV`, and independent per-command-group gates you pick to shrink the fTPM footprint)
* `WOLFTPM_SMALL_STACK` support for constrained environments

See the [firmware TPM manual](https://www.wolfssl.com/documentation/manuals/wolftpm/fwtpm/overview.html)
for build instructions, configuration, and API reference.

## Post-Quantum Cryptography (v1.85)

wolfTPM implements the TPM 2.0 Library Specification v1.85 post-quantum algorithms:
ML-DSA (FIPS 204) signing and ML-KEM (FIPS 203) key encapsulation. Both the client
library and the firmware TPM server implement the eight new v1.85 PQC commands, and
the SealSQ QVault is supported as the first TPM with ML-DSA and ML-KEM in silicon.

Build with `--enable-pqc` (the leaner ML-DSA and ML-KEM subset) or `--enable-v185`
(the full v1.85 feature set), against a wolfCrypt built with ML-DSA and ML-KEM.
Per-operation trimming is available with `--enable-mldsa` and `--enable-mlkem`, and
`make check` runs the PQC tests.

See the [post-quantum manual](https://www.wolfssl.com/documentation/manuals/wolftpm/post-quantum.html)
and the [firmware TPM post-quantum manual](https://www.wolfssl.com/documentation/manuals/wolftpm/fwtpm/post-quantum.html).

## SPDM Attestation

wolfTPM implements SPDM (Security Protocol and Data Model, DMTF DSP0274) for TPM 2.0
attestation over the TCG SPDM-over-TPM binding. Both the TCG certificate handshake
and the DSP0274 pre-shared-key (PSK) handshake are supported, negotiating SPDM
protocol version 1.3.

For testing without discrete silicon, the `fwtpm_server` ships an SPDM 1.3 responder
that drives the same handshake the real Nuvoton and Nations parts use, so the SPDM
stack can be exercised end-to-end in CI.

Build with `--enable-spdm` plus at least one handshake mode (`--enable-tcg` for the
certificate handshake, `--enable-psk` for the PSK handshake). Vendor wire-format
adapters are optional (`--enable-nuvoton`, `--enable-nations`).

See the [SPDM manual](https://www.wolfssl.com/documentation/manuals/wolftpm/spdm.html)
for build instructions, responder modes, and the end-to-end test scripts.

## Building

### wolfSSL

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm
make
sudo make install
sudo ldconfig
```

`autogen.sh` requires automake and libtool: `sudo apt-get install automake libtool`.

### wolfTPM

```bash
./autogen.sh
./configure
make
make check
```

On Linux x86_64 and aarch64 a bare `./configure` auto-enables the software TPM
backends, so `make check` runs without hardware.

### CMake

```bash
mkdir build
cd build
# use an installed wolfSSL (library and headers)
cmake .. -DWITH_WOLFSSL=/prefix/to/wolfssl/install/
# OR use a wolfSSL source tree
cmake .. -DWITH_WOLFSSL_TREE=/path/to/wolfssl/
cmake --build .
```

For the full list of configure flags and defines see the
[Build Options manual](https://www.wolfssl.com/documentation/manuals/wolftpm/build-options.html).
To build for a specific TPM, see the
[Supported Hardware manual](https://www.wolfssl.com/documentation/manuals/wolftpm/supported-hardware.html).

## Documentation

The full wolfTPM manual is published at
<https://www.wolfssl.com/documentation/manuals/wolftpm/>. The sources are kept in
[`docs/`](docs/), with a Japanese translation under [`docs/ja/`](docs/ja/).

**Overview**

* [Introduction](https://www.wolfssl.com/documentation/manuals/wolftpm/index.html): what wolfTPM is, with a map of the manual
* [TPM 2.0 Overview](https://www.wolfssl.com/documentation/manuals/wolftpm/tpm2-overview.html): protocol, hierarchies, PCRs, and device identification
* [Project Structure](https://www.wolfssl.com/documentation/manuals/wolftpm/project-structure.html): the source layout

**Getting started**

* [Getting Started](https://www.wolfssl.com/documentation/manuals/wolftpm/getting-started.html): install, build, and run your first example
* [Building](https://www.wolfssl.com/documentation/manuals/wolftpm/building.html): autotools, CMake, out-of-tree wolfSSL, and bare-metal
* [Build Options](https://www.wolfssl.com/documentation/manuals/wolftpm/build-options.html): every configure flag and define
* [System Interfaces](https://www.wolfssl.com/documentation/manuals/wolftpm/system-interfaces.html): the software simulator (SWTPM), Linux `/dev/tpmX`, and Windows TBS

**Hardware**

* [Supported Hardware](https://www.wolfssl.com/documentation/manuals/wolftpm/supported-hardware.html): every supported TPM and how to build for it
* [HAL IO Callback](https://www.wolfssl.com/documentation/manuals/wolftpm/hal-io-callback.html): the single IO callback porting model and wolfHAL

**Usage**

* [Examples Overview](https://www.wolfssl.com/documentation/manuals/wolftpm/examples-overview.html), [Key Management](https://www.wolfssl.com/documentation/manuals/wolftpm/key-management.html), [Attestation](https://www.wolfssl.com/documentation/manuals/wolftpm/attestation.html), [Sealing and NVRAM](https://www.wolfssl.com/documentation/manuals/wolftpm/sealing-and-nvram.html), [TLS and Certificates](https://www.wolfssl.com/documentation/manuals/wolftpm/tls-and-certificates.html), [Firmware Update](https://www.wolfssl.com/documentation/manuals/wolftpm/firmware-update.html), [Management and GPIO](https://www.wolfssl.com/documentation/manuals/wolftpm/management-and-gpio.html)

**Features**

* [Post-Quantum](https://www.wolfssl.com/documentation/manuals/wolftpm/post-quantum.html): ML-DSA, ML-KEM, PQC TLS 1.3, and the SealSQ QVault
* [SPDM](https://www.wolfssl.com/documentation/manuals/wolftpm/spdm.html): encrypted TPM sessions over the TCG SPDM binding
* [Firmware TPM](https://www.wolfssl.com/documentation/manuals/wolftpm/fwtpm/overview.html): the wolfCrypt firmware TPM (overview, building, usage, HAL and porting, post-quantum, and SPDM)

**Wrappers and integrations**

* [Rust Wrapper](https://www.wolfssl.com/documentation/manuals/wolftpm/rust-wrapper.html), [C# Wrapper](https://www.wolfssl.com/documentation/manuals/wolftpm/csharp-wrapper.html), [STM32Cube](https://www.wolfssl.com/documentation/manuals/wolftpm/stm32cube.html), [Embedded Integrations](https://www.wolfssl.com/documentation/manuals/wolftpm/embedded-integrations.html)

**Reference**

* [API Reference](https://www.wolfssl.com/documentation/manuals/wolftpm/api-reference.html), [Testing](https://www.wolfssl.com/documentation/manuals/wolftpm/testing.html), [Benchmarks](https://www.wolfssl.com/documentation/manuals/wolftpm/benchmarks.html), [SBOM and Compliance](https://www.wolfssl.com/documentation/manuals/wolftpm/sbom-and-compliance.html), [Release Notes](https://www.wolfssl.com/documentation/manuals/wolftpm/release-notes.html)

## SBOM / EU CRA Compliance

wolfTPM generates a Software Bill of Materials (CycloneDX 1.6 and SPDX 2.3) for EU
Cyber Resilience Act (CRA) compliance, with `make sbom` or the CMake `sbom` target.
See the [SBOM and Compliance manual](https://www.wolfssl.com/documentation/manuals/wolftpm/sbom-and-compliance.html)
and [wolfssl/doc/CRA.md](https://github.com/wolfSSL/wolfssl/blob/master/doc/CRA.md).

## Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).
