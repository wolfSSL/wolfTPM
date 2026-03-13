# TPM SPDM Examples

This directory contains the SPDM demo for Nuvoton NPCT75x TPMs with wolfTPM.

## Overview

The `spdm_demo` establishes an SPDM secure session between the host and a
Nuvoton TPM over SPI, enabling AES-256-GCM encrypted bus communication. Once
active, all TPM commands are automatically encrypted with no application changes.

For standard SPDM protocol support (spdm-emu, measurements, challenge, etc.),
see the [wolfSPDM](https://github.com/aidangarske/wolfSPDM) standalone library.

## Building

### Prerequisites

wolfSSL with crypto algorithms required for SPDM Algorithm Set B:

```bash
cd wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp
make && sudo make install && sudo ldconfig
```

### wolfTPM with Nuvoton SPDM

```bash
cd wolfTPM
./autogen.sh
./configure --enable-spdm --enable-nuvoton
make
```

## Demo Commands

| Option | Description |
|--------|-------------|
| `--enable` | Enable SPDM on TPM via NTC2_PreConfig (one-time, requires reset) |
| `--disable` | Disable SPDM on TPM via NTC2_PreConfig (requires reset) |
| `--status` | Query SPDM status from TPM |
| `--get-pubkey` | Get TPM's SPDM-Identity P-384 public key |
| `--connect` | Establish SPDM session (ECDH P-384 handshake) |
| `--lock` | Lock SPDM-only mode (use with `--connect`) |
| `--unlock` | Unlock SPDM-only mode (use with `--connect`) |

## Usage Examples

```bash
# One-time setup: enable SPDM + GPIO reset
./examples/spdm/spdm_demo --enable
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2

# Query SPDM status
./examples/spdm/spdm_demo --status

# Get TPM identity key
./examples/spdm/spdm_demo --get-pubkey

# Establish SPDM session
./examples/spdm/spdm_demo --connect

# Lock SPDM-only mode (connect + lock in one session)
./examples/spdm/spdm_demo --connect --lock
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2

# All commands now auto-encrypt:
./examples/wrap/caps          # auto-SPDM, AES-256-GCM encrypted
./tests/unit.test             # full test suite over encrypted bus

# Unlock SPDM-only mode
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
./examples/spdm/spdm_demo --connect --unlock
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

## Automated Test Suite

Runs 6 tests: status, connect, lock, unit test over SPDM, unlock, cleartext caps setup lifecycle on hardware.

```bash
./examples/spdm/spdm_test.sh
```

## Support

For production use with hardware TPMs and SPDM support, contact **support@wolfssl.com**.
