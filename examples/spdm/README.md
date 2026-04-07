# TPM SPDM Setup/Control

This directory contains the SPDM setup and control tool for Nuvoton NPCT75x
and Nations NS350 TPMs with wolfTPM.

## Overview

The `spdm_ctrl` tool establishes SPDM secure sessions between the host and a
TPM over SPI, enabling AES-256-GCM encrypted bus communication. Once active,
all TPM commands are automatically encrypted with no application changes.

Supported hardware:
- **Nuvoton NPCT75x** — Identity key mode (ECDHE P-384)
- **Nations NS350** — Identity key mode + PSK mode

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

### wolfTPM with Nations SPDM

```bash
cd wolfTPM
./autogen.sh
./configure --enable-spdm --enable-nations
make
```

## Setup/Control Commands

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
# One-time setup: enable SPDM + reset TPM
./examples/spdm/spdm_ctrl --enable
# Reset the TPM (see "TPM Reset Pin Control" below)

# Query SPDM status
./examples/spdm/spdm_ctrl --status

# Get TPM identity key
./examples/spdm/spdm_ctrl --get-pubkey

# Establish SPDM session
./examples/spdm/spdm_ctrl --connect

# Lock SPDM-only mode (connect + lock in one session)
./examples/spdm/spdm_ctrl --connect --lock
# Reset the TPM

# All commands now auto-encrypt:
./examples/wrap/caps          # auto-SPDM, AES-256-GCM encrypted
./tests/unit.test             # full test suite over encrypted bus

# Unlock SPDM-only mode
# Reset the TPM
./examples/spdm/spdm_ctrl --connect --unlock
# Reset the TPM
```

## TPM Reset Pin Control

SPDM enable/disable and SPDM-only mode changes require a TPM reset to take
effect. The reset pin must be connected and controllable by the host.

**Important for custom hardware designs:** Ensure the TPM reset pin is routed
to a host-controllable GPIO. Without reset pin control, SPDM mode changes
cannot be applied and recovery from SPDM-only mode is not possible.

### Raspberry Pi Example (GPIO 4)

```bash
# Assert reset low, wait, release high, wait for TPM startup
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

Other platforms will use their own GPIO control mechanism. The key requirement
is toggling the TPM reset line (active low) with sufficient hold time.

## Automated Test Suite

Runs the full SPDM setup lifecycle on hardware:

```bash
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nuvoton
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nations
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nations-psk
```

## Support

For production use with hardware TPMs and SPDM support, contact **support@wolfssl.com**.
