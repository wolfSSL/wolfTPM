# wolfTPM User Manual

## Introduction

wolfTPM is a portable TPM 2.0 project, designed for embedded use. It is highly portable, due to having been written in native C, having a single IO callback for SPI hardware interface, no external dependencies, and its compacted code with low resource usage.

### Protocol Overview

Trusted Platform Module (TPM, also known as ISO/IEC 11889) is an international standard for a secure crypto processor, a dedicated micro-controller designed to secure hardware through integrated cryptographic keys. Computer programs can use a TPM to authenticate hardware devices, since each TPM chip has a unique and secret RSA key burned in as it is produced.

According to Wikipedia, a TPM provides the following:

* A random number generator
* Facilities for the secure generation of cryptographic keys for limited uses.
* Remote attestation: Creates a nearly unforgettable hash key summary of the hardware and software configuration. The software in charge of hashing the configuration data determines the extent of the summary. This allows a third party to verify that the software has not been changed.
* Binding: Encrypts data using the TPM bind key, a unique RSA key descended from a storage key.
* Sealing: Similar to binding, but in addition, specifies the TPM state for the data to be decrypted (unsealed).

In addition, TPM can also be used for various applications such as platform integrity, disk encryption, password protection, and software license protection.

### Hierarchies

* Platform: `TPM_RH_PLATFORM`
* Owner: `PM_RH_OWNER`
* Endorsement: `TPM_RH_ENDORSEMENT`

Each hierarchy has their own manufacture generated seed. The arguments used on `TPM2_Create` or `TPM2_CreatePrimary` create a template, which is fed into a KDF to produce the same key based hierarchy used. The key generated is the same each time; even after reboot. The generation of a new RSA 2048 bit key takes about 15 seconds. Typically these are created and then stored in NV using TPM2_EvictControl. Each TPM generates their own keys uniquely based on the seed.

There is also an Ephemeral hierarchy (TPM_RH_NULL), which can be used to create ephemeral keys.

### Platform Configuration Registers (PCRs)

Platform Configuration Registers (PCRs) are one of the essential features of a TPM. Their prime use case is to provide a method to cryptographically record (measure) software state: both the software running on a platform and configuration data used by that software.

wolfTPM contains hash digests for SHA-1 and SHA-256 with an index 0-23. These hash digests can be extended to prove the integrity of a boot sequence (secure boot).

## Building wolfTPM

To build the wolfTPM library, it's required to first build and install the wolfSSL library. This can be downloaded from the download page, or through a "git clone" command, shown below:

```sh
git clone https://github.com/wolfssl/wolfssl
```

Once the wolfSSL library has been downloaded, it needs to be built with the following options being passed to the configure script:

```sh
./configure --enable-wolftpm && make && sudo make install
```

Then the wolfSSL library just needs to be built and installed however the user prefers.

The next step is to download and install the wolfTPM library. At the time this documentation was written, the wolfTPM library does not have a stable release yet and needs to be cloned from GitHub. The following commands show how to clone and install wolfTPM:

```sh
git clone https://github.com/wolfssl/wolftpm
cd wolftpm
./autogen.sh
./configure
make
```

For detailed build instructions see [/README.md](/README.md#building).

## Getting Started

The wolfTPM library has TPM 2.0 wrapper tests, native tests, and a sample benchmark application that come ready-to-use after a successful installation of wolfTPM. Below are some instructions on how to run the sample applications yourself.

To interface with the hardware platform that is running these applications, please see the function `TPM2_IoCb` inside of `hal/tpm_io.c`.

### Examples

See [/examples/README.md](/examples/README.md)

### Benchmarks

See [/README.md](/README.md#tpm2-benchmarks)

## wolfTPM Library Design

### Library Headers

wolfTPM header files are located in [/wolftpm](/wolftpm).

The general header files that should be included from wolfTPM is shown below:

```c
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h> /* If using wrappers */
```

### Example Design

Every example application that is included with wolfTPM includes the `tpm_io.h` header file, located in `/hal`.

The `tpm_io.c` file sets up the example HAL IO callback necessary for testing and running the example applications with a Linux Kernel, STM32 CubeMX HAL or Atmel/Microchip ASF. The reference is easily modified, such that custom IO callbacks or different callbacks may be added or removed as desired.

## API Reference

See [https://www.wolfssl.com/docs/wolftpm-manual/](https://www.wolfssl.com/docs/wolftpm-manual/).

### TPM 2.0 TCG API's

See [/wolftpm/tpm2.h](/wolftpm/tpm2.h) for inline doxygen style API documentation.

### wolfTPM Wrapper API's

See [/wolftpm/tpm2_wrap.h](/wolftpm/tpm2_wrap.h) for inline doxygen style API documentation.

## Support

For questions please email support@wolfssl.com
