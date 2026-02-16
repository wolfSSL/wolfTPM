# SPDM Examples

This directory contains examples demonstrating SPDM (Security Protocol and Data Model)
functionality with wolfTPM.

## Overview

The SPDM demo (`spdm_demo`) shows how to establish an SPDM secure session between
the host and a TPM using the wolfSPDM library backend. It supports both the standard
spdm-emu emulator and Nuvoton hardware TPMs.

For real SPDM support on hardware TPMs, contact **support@wolfssl.com**

## Example

### `spdm_demo.c` - SPDM Secure Session Demo

**Emulator mode (spdm-emu responder):**

```bash
# Terminal 1: Start the emulator (from spdm-emu/build/bin directory)
# Must specify Algorithm Set B algorithms to match wolfSPDM
cd spdm-emu/build/bin
./spdm_responder_emu --ver 1.2 --hash SHA_384 --asym ECDSA_P384 \
    --dhe SECP_384_R1 --aead AES_256_GCM

# Terminal 2: Run wolfTPM SPDM demo
./spdm_demo --emu
```

**Nuvoton hardware mode:**

```bash
./spdm_demo --enable               # Enable SPDM on TPM (one-time, requires reset)
./spdm_demo --connect --status     # Connect + get SPDM status
./spdm_demo --connect --lock       # Connect + lock SPDM-only mode
./spdm_demo --connect --caps       # Connect + run TPM commands over SPDM
./spdm_demo --connect --unlock     # Connect + unlock SPDM-only mode
```

## Building

### Prerequisites

Build wolfSSL with full crypto support and wolfSPDM:

```bash
# wolfSSL (needs --enable-all for P-384/ECDH)
cd wolfssl && ./configure --enable-wolftpm --enable-all && make && sudo make install

# wolfSPDM
cd wolfspdm && ./autogen.sh && ./configure && make && sudo make install

# wolfTPM with SPDM
./configure --enable-spdm --with-wolfspdm=/path/to/wolfspdm
make
```

## Support

For production use with hardware TPMs and full SPDM protocol support, contact:

**support@wolfssl.com**
