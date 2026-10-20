# TPM SPDM Setup/Control

This directory contains the SPDM setup and control tool for Nuvoton NPCT75x
Nations NS350, and Infineon SLB9678 TPMs with wolfTPM.

## Overview

The `spdm_ctrl` tool establishes SPDM secure sessions between the host and a
TPM over SPI, enabling AES-256-GCM encrypted bus communication. Identity mode
requires the responder key from a trusted provisioning source.

`spdm_ctrl` and `nv_bind` are the examples that accept SPDM credentials. Other
wolfTPM examples use uncredentialed `wolfTPM2_Init()` and intentionally return
`WOLFSPDM_E_BAD_STATE` while a TPM is locked in SPDM-only mode; unlock it with
`spdm_ctrl` before running those examples.

Supported hardware:
- **Nuvoton NPCT75x** — Identity key mode (ECDHE P-384)
- **Nations NS350** — Identity key mode + PSK mode
- **Infineon SLB9678** - TCG identity key mode

For standard SPDM protocol support (spdm-emu, measurements, challenge, etc.),
see the [wolfSPDM](https://github.com/aidangarske/wolfSPDM) standalone library.

## Building

### Prerequisites

wolfSSL with crypto algorithms required for SPDM Algorithm Set B. wolfSSL is bundled as the `lib/wolfssl` submodule; initialize it with `git submodule update --init lib/wolfssl` and build it from there.

```bash
cd lib/wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp
make && sudo make install && sudo ldconfig
cd ../..
```

### wolfTPM with Nuvoton SPDM

```bash
./autogen.sh
./configure --enable-spdm --enable-nuvoton
make
```

### wolfTPM with Nations SPDM

```bash
./autogen.sh
./configure --enable-spdm --enable-nations
make
```

### wolfTPM with Infineon SLB9678 SPDM

```bash
cd wolfTPM
./autogen.sh
./configure --enable-spdm --enable-infineon=slb9678
make
```

TCG asymmetric mode is the only mode this part is supported in here.

## Setup/Control Commands

| Option | Description |
|--------|-------------|
| `--vendor=nuvoton\|nations\|slb9678` | Select the identity/vendor adapter explicitly |
| `--enable` | Enable SPDM on TPM via NTC2_PreConfig (one-time, requires reset) |
| `--disable` | Disable SPDM on TPM via NTC2_PreConfig (requires reset) |
| `--status` | Query SPDM status from TPM |
| `--get-pubkey` | Get TPM's SPDM-Identity P-384 public key |
| `--responder-pubkey <hex>` | Pin a trusted raw P-384 X\|\|Y key (192 hex characters) |
| `--connect` | Establish SPDM session (ECDH P-384 handshake) |
| `--caps` | Read TPM capabilities over the current transport |
| `--session-info` | Show the TPM's view of the SPDM session (`TPM_CAP_SPDM_SESSION_INFO`) |
| `--policy-nv` | Define an NV index guarded by `TPM2_PolicyTransportSPDM`, then write and read it over the session |
| `--psk <hex>` | Start a PSK session |
| `--psk-set <psk> <clearauth>` | Provision a 64-byte PSK and 32-byte ClearAuth |
| `--psk-clear <clearauth>` | Clear a provisioned PSK |
| `--lock` | Lock SPDM-only mode (use with `--connect`) |
| `--unlock` | Unlock SPDM-only mode (use with `--connect`) |
| `--tpm-clear` | Send `TPM2_Clear` over the current transport |

The `nv_bind` example is a focused, self-contained version of the same idea: it
provisions an NV index whose `authPolicy` is `TPM2_PolicyTransportSPDM`, stores a
secret over an SPDM-PSK session, then shows that the identical read over a plain
(non-SPDM) connection is refused with `TPM_RC_CHANNEL`.

```sh
./src/fwtpm/fwtpm_server --spdm-psk --spdm-psk-hex <psk> --clear &
./examples/spdm/nv_bind --psk <psk>
```

The fwTPM generates a fresh SPDM identity key each time it starts, so on the
fwTPM a policy bound to `tpmKeyName` is only valid for that server lifetime; a
hardware TPM holds a persistent identity key, where such a binding is durable.
PSK sessions report empty key names, since no asymmetric key authenticated them.

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

### Infineon SLB9678

Use one command to connect and run the encrypted TPM and policy checks:

```bash
./examples/spdm/spdm_ctrl --vendor=slb9678 \
    --responder-pubkey <trusted_p384_x_y_hex> --connect \
    --caps --session-info --policy-nv
```

The responder key is a trusted P-384 X||Y point (192 hex characters).
`--get-pubkey` retrieves it for diagnostics; that query alone does not
establish trust. The `infineon` vendor selector is an alias for `slb9678`.

`--policy-nv` creates a temporary NV index protected by
`TPM2_PolicyTransportSPDM`. It checks successful write/read, TPM key-name
binding, and requester key-name binding when available. Mismatched names
must return `TPM_RC_CHANNEL_KEY`. The command preserves an existing demo
index and removes the index it creates. `--session-info` reads the session
key names without modifying NV.

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
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl slb9678
```

The identity-mode hardware runs require `SPDM_RESPONDER_PUBKEY` from a trusted
provisioning source. The PSK run does not use it. The `fwtpm-tcg` test obtains
the freshly generated public key from the local server's protected startup log
and passes it through the same pinning interface.

The SLB9678 suite preserves GPIO straps and tests TCG connection, encrypted
commands, session key names, policy binding, and cleanup. Optional reversible
PSK configuration checks require `SPDM_TEST_PSK_CONFIG=1`; PSK provisioning
is not part of this suite.

Mock regression tests run without hardware:

```bash
./tests/spdm_ctrl.test
./tests/spdm_config.test # SLB9678 builds
```

## Support

For production use with hardware TPMs and SPDM support, contact **support@wolfssl.com**.
