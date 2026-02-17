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

**Quick test (emulator — starts/stops automatically):**

```bash
./examples/spdm/spdm_test.sh --emu
```

Runs session establishment, signed measurements, unsigned measurements,
challenge authentication, heartbeat, and key update.

**Quick test (Nuvoton hardware):**

```bash
./examples/spdm/spdm_test.sh --nuvoton
```

Runs connect, lock, caps-over-SPDM, unlock, and cleartext verification.

**Manual commands:**

```bash
# Emulator (start spdm_responder_emu first, see docs/SPDM.md)
./spdm_demo --emu                  # Session only
./spdm_demo --meas                 # Session + signed measurements
./spdm_demo --meas --no-sig        # Session + unsigned measurements
./spdm_demo --challenge            # Sessionless challenge authentication
./spdm_demo --emu --heartbeat      # Session + heartbeat keep-alive
./spdm_demo --emu --key-update     # Session + key rotation

# Nuvoton hardware
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
