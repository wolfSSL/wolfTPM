# TPM SPDM Setup/Control

This directory contains the SPDM setup and control tool for Nuvoton NPCT75x
and Nations NS350 TPMs with wolfTPM.

## Overview

The `spdm_ctrl` tool establishes SPDM secure sessions between the host and a
TPM over SPI, enabling AES-256-GCM encrypted bus communication. Identity mode
requires the responder key from a trusted provisioning source.

`spdm_ctrl` is the only example that accepts SPDM credentials. Other wolfTPM
examples use uncredentialed `wolfTPM2_Init()` and intentionally return
`WOLFSPDM_E_BAD_STATE` while a TPM is locked in SPDM-only mode; unlock it with
`spdm_ctrl` before running those examples.

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
| `--vendor=nuvoton\|nations` | Select the identity/vendor adapter explicitly |
| `--enable` | Enable SPDM on TPM via NTC2_PreConfig (one-time, requires reset) |
| `--disable` | Disable SPDM on TPM via NTC2_PreConfig (requires reset) |
| `--status` | Query SPDM status from TPM |
| `--get-pubkey` | Get TPM's SPDM-Identity P-384 public key |
| `--responder-pubkey <hex>` | Pin a trusted raw P-384 X\|\|Y key (192 hex characters) |
| `--connect` | Establish SPDM session (ECDH P-384 handshake) |
| `--caps` | Read TPM capabilities over the current transport |
| `--psk <hex>` | Start a PSK session |
| `--psk-set <psk> <clearauth>` | Provision a 64-byte PSK and 32-byte ClearAuth |
| `--psk-clear <clearauth>` | Clear a provisioned PSK |
| `--lock` | Lock SPDM-only mode (use with `--connect`) |
| `--unlock` | Unlock SPDM-only mode (use with `--connect`) |
| `--tpm-clear` | Send `TPM2_Clear` over the current transport |

## Usage Examples

```bash
# One-time setup: enable SPDM + reset TPM
./examples/spdm/spdm_ctrl --enable
# Reset the TPM (see "TPM Reset Pin Control" below)

# Query SPDM status
./examples/spdm/spdm_ctrl --status

# Discover TPM identity key (unauthenticated; do not use as its own trust source)
./examples/spdm/spdm_ctrl --get-pubkey

# Establish SPDM session with a key from trusted provisioning records
./examples/spdm/spdm_ctrl \
    --vendor=nuvoton --responder-pubkey <trusted_p384_x_y_hex> --connect

# Lock SPDM-only mode (connect + lock in one session)
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --lock
# Reset the TPM

# Unlock SPDM-only mode
# Reset the TPM
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --unlock
# Reset the TPM
```

## TPM Reset Pin Control

SPDM enable/disable and SPDM-only mode changes require a TPM reset to take
effect. The reset pin must be connected and controllable by the host.

**Important for custom hardware designs:** Ensure the TPM reset pin is routed
to a host-controllable GPIO. Without reset pin control, SPDM mode changes
cannot be applied and recovery from SPDM-only mode is not possible.

The reset line is board specific. On a Raspberry Pi, Nuvoton uses GPIO4 and the
ST33KTPM uses GPIO24 (pin 18); confirm your wiring before toggling.

```bash
# Assert reset low, release high, wait for TPM startup (Nuvoton GPIO4 shown)
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
# ST33: use line 24 instead of 4
```

wolfTPM can also drive this from code: build with `--enable-hal-reset` and call
`TPM2_IoCb_Reset()` (default line: ST33 GPIO24, Nuvoton GPIO4). See `hal/README.md`.

## Automated Test Suite

Runs the full SPDM setup lifecycle on hardware:

```bash
export SPDM_RESPONDER_PUBKEY=<trusted_p384_x_y_hex>
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nuvoton
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nations
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nations-psk
```

The identity-mode hardware runs require `SPDM_RESPONDER_PUBKEY` from a trusted
provisioning source. The PSK run does not use it. The `fwtpm-tcg` test obtains
the freshly generated public key from the local server's protected startup log
and passes it through the same pinning interface.

## Support

For production use with hardware TPMs and SPDM support, contact **support@wolfssl.com**.
