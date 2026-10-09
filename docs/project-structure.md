# Project Structure

This page lists the top-level directories of the wolfTPM source tree and the purpose of each, with notes on the firmware TPM and SPDM subdirectories and the library headers.

## Source tree

```
wolfTPM/
  src/            TPM 2.0 core library and wrappers
    fwtpm/        firmware TPM (fwTPM) server
    spdm/         SPDM responder and vendor adapters
  wolftpm/        public headers
    fwtpm/        fwTPM headers
    spdm/         SPDM headers
  examples/       example applications
  hal/            tpm_io_* IO callback backends
  tests/          unit and API tests
  IDE/            IDE and board projects
  docs/           this manual and the Doxyfile
  certs/          example keys and certificates
  cmake/          CMake support files
  m4/             autoconf macros
  scripts/        test and helper scripts
  tools/          documentation and SBOM tooling
  wrapper/        language wrappers
  zephyr/         Zephyr module
```

## Directory purposes

| Directory | Purpose |
| --- | --- |
| `src/` | TPM 2.0 core (`tpm2.c`, `tpm2_packet.c`, `tpm2_tis.c`, `tpm2_param_enc.c`, `tpm2_crypto.c`, `tpm2_asn.c`) and the wrapper API (`tpm2_wrap.c`). |
| `src/fwtpm/` | The firmware TPM server (`fwtpm_server`): command handling, crypto, NV storage and IO. |
| `src/spdm/` | The SPDM responder and the vendor adapters. |
| `wolftpm/` | Public headers, including `tpm2.h`, `tpm2_wrap.h` and `tpm2_types.h`. |
| `wolftpm/fwtpm/` | Public headers for the fwTPM server. |
| `wolftpm/spdm/` | Public headers for SPDM (`spdm.h`, `spdm_tcg.h`, `spdm_psk.h`, `spdm_responder.h` and the vendor headers). |
| `examples/` | Example applications for the native and wrapper APIs. |
| `hal/` | IO callback backends (`tpm_io_*`) for Atmel, Barebox, Espressif, Infineon, Linux, Microchip, MMIO, QNX, ST, U-Boot, wolfHAL, Xilinx, Zephyr and fwTPM. |
| `tests/` | Unit tests and API tests. |
| `IDE/` | Projects for STM32CUBE, Espressif, QNX, IAR-EWARM and VisualStudio. |
| `docs/` | This manual and the Doxygen configuration (`Doxyfile`). |
| `certs/` | Example keys and certificates used by the examples and tests. |
| `cmake/` | CMake support files. |
| `m4/` | Autoconf macros. |
| `scripts/` | Test and helper scripts. |
| `tools/` | Documentation tooling and the SBOM generator (`tools/sbom`). |
| `wrapper/` | Language wrappers: `rust` and `CSharp`. |
| `zephyr/` | Zephyr integration. |

## Library layout

wolfTPM header files are located in the following locations:

| Library | Header location |
| --- | --- |
| wolfTPM | `wolftpm/` |
| wolfSSL | `wolfssl/` |
| wolfCrypt | `wolfssl/wolfcrypt` |

The general header file that should be included from wolfTPM is shown below:

```c
#include <wolftpm/tpm2.h>
```

Every example application that is included with wolfTPM includes the `tpm_io.h` header file, located in `hal/`. The `tpm_io.c` file sets up the example HAL IO callback necessary for testing and running the example applications with a Linux Kernel, STM32 CubeMX HAL or Atmel/Microchip ASF. The reference is easily modified, such that custom IO callbacks or different callbacks may be added or removed as desired.

## See Also

* [Building](building.md)
* [Build Options](build-options.md)
* [fwTPM Overview](fwtpm/overview.md)
* [SPDM Attestation](spdm.md)
