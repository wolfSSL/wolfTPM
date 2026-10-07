# SPDM Attestation and Secure Sessions

wolfTPM includes built-in SPDM (Security Protocol and Data Model, DMTF DSP0274) support for Nuvoton NPCT75x and Nations NS350 TPMs, using wolfSSL/wolfCrypt. SPDM negotiates protocol version 1.3 over the TCG SPDM-over-TPM binding. Both vendors support identity key mode (ECDHE P-384) for session establishment. The Nations NS350 additionally supports PSK (pre-shared key) mode. Once a session is established, all TPM commands and responses are encrypted with AES-256-GCM over the existing SPI or I2C bus. Identity key mode requires the responder's P-384 public key from a trusted provisioning source.

The SPDM code lives in the [wolfSPDM](https://github.com/wolfSSL/wolfSPDM) library, included as the `lib/wolfSPDM` submodule and compiled into libwolftpm in its TPM profile. Any wolfTPM checkout that will use SPDM must be cloned with `--recursive`. Without the submodule, `./configure --enable-spdm` stops with: `--enable-spdm needs the wolfSPDM submodule: run git submodule update --init lib/wolfSPDM`.

## Quick start

Clone recursively, because SPDM lives in the `lib/wolfSPDM` submodule:

```sh
git clone --recursive https://github.com/wolfSSL/wolfTPM.git
git clone https://github.com/wolfSSL/wolfssl.git   # sibling checkout
cd wolfTPM
```

Already cloned without `--recursive`? Run `git submodule update --init lib/wolfSPDM` once inside the checkout.

### Nuvoton NPCT75x

```sh
# Build wolfSSL (in the sibling checkout, then return here)
cd ../wolfssl && ./autogen.sh && \
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp && \
make && sudo make install && sudo ldconfig && cd -

# Build wolfTPM (submodule already present from the recursive clone)
./autogen.sh && ./configure --enable-spdm --enable-nuvoton && make

# Enable SPDM (one-time), reset, connect
./examples/spdm/spdm_ctrl --enable
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
./examples/spdm/spdm_ctrl --responder-pubkey <trusted_p384_x_y_hex> --connect
```

### Nations NS350

```sh
# Build wolfSSL (in the sibling checkout, then return here)
cd ../wolfssl && ./autogen.sh && \
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp && \
make && sudo make install && sudo ldconfig && cd -

# Build wolfTPM (submodule already present from the recursive clone)
./autogen.sh && ./configure --enable-spdm --enable-nations && make

# Connect (identity key is factory default)
./examples/spdm/spdm_ctrl --responder-pubkey <trusted_p384_x_y_hex> --connect
```

## Overview and how it works

The `spdm_ctrl` tool establishes SPDM secure sessions between the host and a TPM over SPI, enabling AES-256-GCM encrypted bus communication. The implementation uses Algorithm Set B: ECDH P-384, SHA-384, and AES-256-GCM. Two session establishment modes are supported.

`spdm_ctrl` and `nv_bind` are the examples that accept SPDM credentials. Other wolfTPM examples use uncredentialed `wolfTPM2_Init()` and intentionally return `WOLFSPDM_E_BAD_STATE` while a TPM is locked in SPDM-only mode. Unlock it with `spdm_ctrl` before running those examples.

Supported hardware:

- Nuvoton NPCT75x: identity key mode (ECDHE P-384)
- Nations NS350: identity key mode and PSK mode

### Identity key mode (Nuvoton and Nations)

```
Host                                TPM (Nuvoton NPCT75x / Nations NS350)
  |                                   |
  |--- GET_VERSION ------------------>|  (negotiate SPDM version)
  |<-- VERSION -----------------------|
  |                                   |
  |--- GET_PUB_KEY ------------------>|  (get TPM's P-384 identity key)
  |<-- PUB_KEY_RSP -------------------|
  |                                   |
  |--- KEY_EXCHANGE ----------------->|  (ECDHE P-384 key agreement)
  |<-- KEY_EXCHANGE_RSP --------------|  (+ HMAC proof of shared secret)
  |                                   |
  |    --- Handshake keys derived --- |
  |                                   |
  |=== GIVE_PUB_KEY =================>|  (encrypted: host's P-384 key)
  |<== GIVE_PUB_KEY_RSP ==============|
  |                                   |
  |=== FINISH =======================>|  (encrypted: signature + HMAC)
  |<== FINISH_RSP ====================|
  |                                   |
  |    --- App data keys derived ---  |
  |                                   |
  |=== TPM2_CMD (AES-256-GCM) =======>|  (every command encrypted)
  |<== TPM2_RSP (AES-256-GCM) ========|
```

The handshake uses ECDH P-384 for key agreement and HMAC-SHA384 for authentication. After the handshake, all TPM commands are wrapped in SPDM `VENDOR_DEFINED_REQUEST("TPM2_CMD")` messages and encrypted with AES-256-GCM. A sequence number increments with each message to prevent replay attacks.

### PSK mode (Nations only)

PSK mode replaces the ECDHE key exchange with a symmetric pre-shared key. The same AES-256-GCM encryption is used for data transport.

```
Host                                TPM (Nations NS350)
  |                                   |
  |--- GET_VERSION ------------------>| (negotiate SPDM version)
  |<-- VERSION -----------------------|
  |                                   |
  |--- GET_CAPABILITIES ------------->| (capability exchange)
  |<-- CAPABILITIES ------------------|
  |                                   |
  |--- NEGOTIATE_ALGORITHMS --------->| (Algorithm Set B: P-384/SHA-384)
  |<-- ALGORITHMS --------------------|
  |                                   |
  |--- PSK_EXCHANGE ----------------->| (session key from PSK)
  |<-- PSK_EXCHANGE_RSP --------------| (+ HMAC proof)
  |                                   |
  |    --- Handshake keys derived --- | (Salt_0 = 0xFF * H for PSK mode)
  |                                   |
  |=== PSK_FINISH ===================>| (encrypted: requester HMAC)
  |<== PSK_FINISH_RSP ================|
  |                                   |
  |    --- App data keys derived ---  |
  |                                   |
  |=== TPM2_CMD (AES-256-GCM) =======>| (every command encrypted)
  |<== TPM2_RSP (AES-256-GCM) ========|
```

PSK and identity key modes are mutually exclusive on the NS350. The identity key is provisioned by factory default and must be unset before PSK can be used. See [PSK lifecycle](#psk-lifecycle-nations).

### SPDM-only mode (encrypted bus enforcement)

SPDM-only mode forces all TPM commands through the encrypted SPDM channel. Both vendors support it. The typical lifecycle:

```
1. Enable SPDM        (one-time, persists across resets)
2. Connect            (handshake, derives session keys)
3. Lock SPDM-only     (TPM rejects all cleartext commands)
4. Reset              (TPM enters SPDM-only enforcement)
5. Initialize with the trusted key or PSK and run commands (all encrypted)
6. Unlock             (connect + unlock in one session)
7. Reset              (TPM back to normal cleartext mode)
```

After an application supplies the responder key through `wolfTPM2_InitWithSpdmKey()`, wolfTPM authenticates the responder and establishes the encrypted session regardless of the cleartext startup result. See [Auto-SPDM](#auto-spdm) for details.

The reset method differs by vendor:

- Nuvoton: GPIO reset, `gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2`
- Nations: full power cycle required (GPIO 4 is not wired to TPM_RST on NS350 daughter boards)

## Building

### 1. Clone with the wolfSPDM submodule

See [Quick start](#quick-start). SPDM is built from the `lib/wolfSPDM` submodule, so clone wolfTPM recursively, or run `git submodule update --init lib/wolfSPDM` in an existing checkout.

### 2. wolfSSL

Both Nuvoton and Nations use the same wolfSSL flags, which provide the crypto for SPDM Algorithm Set B:

```sh
cd ../wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-ecc --enable-sha384 \
    --enable-aesgcm --enable-hkdf --enable-sp
make
sudo make install && sudo ldconfig
cd -   # back to the wolfTPM checkout
```

### 3. wolfTPM

```sh
./autogen.sh
./configure --enable-spdm --enable-nuvoton   # Nuvoton
# or
./configure --enable-spdm --enable-nations    # Nations
make
```

Build with `--enable-spdm` plus at least one handshake mode: `--enable-tcg` for the certificate handshake, `--enable-psk` for the PSK handshake. Vendor wire-format adapters are optional (`--enable-nuvoton`, `--enable-nations`).

### The wolfTPM SPDM profile

`--enable-spdm` defines `WOLFTPM_SPDM`, which auto-selects wolfSPDM's `WOLFSPDM_PROFILE_TPM`. A TPM speaks only the TCG SPDM Binding, so this profile is a lean, TCG-focused build. These are compiled out automatically:

- the DMTF standard requester: `GET_CAPABILITIES`, `NEGOTIATE_ALGORITHMS`, `GET_DIGESTS`, `GET_CERTIFICATE`, and certificate-chain validation
- measurements, challenge, and chunking (they ride the cert flow)
- heartbeat and key update
- the MCTP application-data API (secured messages use the TCG 16-byte pad)

There is no `--disable-mctp` option on wolfTPM's `configure`, and you should not try to add one. The lean profile is automatic with `--enable-spdm`, and wolfSPDM's downstream CI asserts the standard-requester symbols above are absent from `libwolftpm`.

The profile does not define `WOLFSPDM_NO_MCTP`, so the MCTP secured-message framing stays compiled, though a TCG-only TPM never exercises it. Building wolfSPDM standalone with `--disable-mctp` (which requires `--enable-tcg`) additionally strips that path for a pure-TCG requester. That flag belongs to wolfSPDM's own `configure`, never wolfTPM's.

### Configure options

| Option | Description |
|--------|-------------|
| `--enable-spdm` | Enable SPDM support (required) |
| `--enable-tcg` | TCG SPDM Binding spec handshake (auto when fwtpm/nuvoton/nations on) |
| `--enable-psk` | DSP0274 PSK handshake (auto with `--enable-nations`; requires `--enable-tcg`) |
| `--enable-fwtpm` | Build fwtpm_server with the SPDM responder (no silicon needed) |
| `--enable-nuvoton` | Enable Nuvoton TPM hardware support (auto-enables `--enable-tcg`) |
| `--enable-nations` | Enable Nations NS350 hardware support (auto-enables `--enable-tcg --enable-psk`) |
| `--enable-debug` | Debug output with verbose SPDM tracing |
| `--enable-smallstack` | Heap-allocated SPDM context (default: static, about 32 KB) |

`configure` rejects these incompatible combinations:

- `--enable-nuvoton --disable-tcg` (Nuvoton uses the TCG SPDM Binding)
- `--enable-nations --disable-tcg` or `--enable-nations --disable-psk`
- `--enable-psk --disable-tcg` (PSK rides on TCG framing)

### fwTPM SPDM responder (no silicon required)

`fwtpm_server` ships an SPDM 1.3 responder that drives the same handshake the real Nuvoton and Nations parts use, so the full TCG and PSK stack can be exercised in CI without real hardware:

```sh
./src/fwtpm/fwtpm_server --spdm-tcg          # TCG cert handshake
./src/fwtpm/fwtpm_server --spdm-psk \
    --spdm-psk-hex dbc2192291d807742441b963f6712841...   # PSK handshake
```

Test it end-to-end:

```sh
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl fwtpm-tcg
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl fwtpm-psk
```

See [fwtpm/spdm.md](fwtpm/spdm.md) for the responder modes and the end-to-end test scripts.

### Vendor selection in dual-vendor builds

When both `--enable-nuvoton` and `--enable-nations` are compiled in, `spdm_ctrl` selects the vendor adapter with an optional runtime flag:

```sh
./examples/spdm/spdm_ctrl --vendor=nuvoton \
    --responder-pubkey <trusted_p384_x_y_hex> --connect
./examples/spdm/spdm_ctrl --vendor=nations \
    --responder-pubkey <trusted_p384_x_y_hex> --connect
```

Single-vendor builds accept only the adapter compiled into the binary and reject an unavailable `--vendor=` value.

## Usage and control commands

### One-time setup

Nuvoton:

```sh
# Enable SPDM on the TPM (persists across resets)
./examples/spdm/spdm_ctrl --enable

# GPIO reset
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2

# Verify SPDM is enabled
./examples/spdm/spdm_ctrl --status
```

Nations: identity key mode is the factory default, so no setup is required. If it was previously unset, restore it with:

```sh
./examples/spdm/spdm_ctrl --identity-key-set
```

### Establishing a session

Identity key mode (both vendors):

```sh
# Establish SPDM session (VERSION, GET_PUBK, KEY_EXCHANGE, GIVE_PUB, FINISH)
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect

# Query SPDM status
./examples/spdm/spdm_ctrl --status
```

`--responder-pubkey` takes the trusted raw P-384 X||Y point as 192 hex characters. Obtain it from device provisioning records or another authenticated manufacturer channel.

!!! warning
    `--get-pubkey` is unauthenticated discovery and must not be used by itself to establish trust.

PSK mode (Nations) requires the PSK to be provisioned first. See [PSK lifecycle](#psk-lifecycle-nations).

```sh
# Establish PSK session (VERSION, CAPS, ALGO, PSK_EXCHANGE, PSK_FINISH)
./examples/spdm/spdm_ctrl --psk <psk_hex_128chars>
```

### Lock and unlock SPDM-only mode

Lock requires an active SPDM session. After locking, a reset is required for enforcement to take effect.

Nuvoton (identity key):

```sh
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --lock
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2

# Unlock
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --unlock
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

Nations (identity key):

```sh
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --lock
# Power cycle required (unplug and re-plug Raspberry Pi)

./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --unlock
# Power cycle again
```

Nations (PSK mode):

```sh
./examples/spdm/spdm_ctrl --psk <hex> --lock
# Power cycle required

./examples/spdm/spdm_ctrl --psk <hex> --unlock
# Power cycle again
```

### PSK lifecycle (Nations)

PSK and identity key modes are mutually exclusive on the NS350. The identity key is provisioned by default and must be unset before PSK can be used.

```sh
# 1. Unset identity key (enables PSK mode)
./examples/spdm/spdm_ctrl --identity-key-unset

# 2. Provision PSK (64-byte PSK + 32-byte ClearAuth)
#    The demo computes SHA-384(ClearAuth) and sends PSK(64)+Digest(48) = 112 bytes
./examples/spdm/spdm_ctrl --psk-set <psk_hex_128chars> <clearauth_hex_64chars>

# 3. Establish PSK session
./examples/spdm/spdm_ctrl --psk <psk_hex_128chars>

# 4. Clear PSK (sends raw 32-byte ClearAuth; TPM verifies SHA-384 internally)
./examples/spdm/spdm_ctrl --psk-clear <clearauth_hex_64chars>

# 5. Restore identity key (factory default)
./examples/spdm/spdm_ctrl --identity-key-set
```

!!! warning
    The ClearAuth must be exactly 32 bytes. PSK_SET stores its SHA-384 digest (48 bytes). PSK_CLEAR sends the raw 32 bytes and the TPM computes SHA-384 to verify. Using the wrong size makes PSK_CLEAR impossible.

### Command reference

All `spdm_ctrl` options:

| Option | Vendor | Description |
|--------|--------|-------------|
| `--enable` | Nuvoton | Enable SPDM via NTC2_PreConfig (one-time, persists, requires reset) |
| `--disable` | Nuvoton | Disable SPDM via NTC2_PreConfig (requires reset) |
| `--identity-key-set` | Nations | Provision SPDM identity key (factory default) |
| `--identity-key-unset` | Nations | Un-provision identity key (required before PSK) |
| `--vendor=nuvoton\|nations` | Both | Select the identity/vendor adapter explicitly |
| `--get-pubkey` | Both | Discover the TPM identity key without authenticating it |
| `--responder-pubkey <hex>` | Both | Pin a trusted raw P-384 X\|\|Y responder key (192 hex characters) |
| `--connect` | Both | Establish identity key SPDM session (ECDH P-384 handshake) |
| `--caps` | Both | Read TPM capabilities over the current transport |
| `--status` | Both | Query SPDM status |
| `--session-info` | Both | Show the TPM's view of the SPDM session (`TPM_CAP_SPDM_SESSION_INFO`) |
| `--policy-nv` | Both | Define an NV index guarded by `TPM2_PolicyTransportSPDM`, then write and read it over the session |
| `--lock` | Both | Lock SPDM-only mode (use with `--connect`; requires active session) |
| `--unlock` | Both | Unlock SPDM-only mode (use with `--connect`; requires active session) |
| `--psk <psk>` | Nations | Establish PSK session (64-byte PSK) |
| `--psk-set <psk> <clearauth>` | Nations | Provision PSK (64-byte PSK, 32-byte ClearAuth) |
| `--psk-clear <clearauth>` | Nations | Clear PSK (32-byte ClearAuth) |
| `--caps184` | Nations | Query TPM 184 vendor properties and SPDM session info |
| `--tpm-clear` | Nations | Send `TPM2_Clear` over the current transport (platform auth) |

### Usage example

```sh
# One-time setup: enable SPDM + reset TPM
./examples/spdm/spdm_ctrl --enable
# Reset the TPM (see "TPM reset pin control" below)

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

### nv_bind

The `nv_bind` example is a focused, self-contained version of the `--policy-nv` idea. It provisions an NV index whose `authPolicy` is `TPM2_PolicyTransportSPDM`, stores a secret over an SPDM-PSK session, then shows that the identical read over a plain (non-SPDM) connection is refused with `TPM_RC_CHANNEL`.

```sh
./src/fwtpm/fwtpm_server --spdm-psk --spdm-psk-hex <psk> --clear &
./examples/spdm/nv_bind --psk <psk>
```

The fwTPM generates a fresh SPDM identity key each time it starts, so on the fwTPM a policy bound to `tpmKeyName` is only valid for that server lifetime. A hardware TPM holds a persistent identity key, where such a binding is durable. PSK sessions report empty key names, since no asymmetric key authenticated them.

### TPM reset pin control

SPDM enable/disable and SPDM-only mode changes require a TPM reset to take effect. The reset pin must be connected and controllable by the host.

!!! warning
    For custom hardware designs, route the TPM reset pin to a host-controllable GPIO. Without reset pin control, SPDM mode changes cannot be applied and recovery from SPDM-only mode is not possible.

The reset line is board specific. On a Raspberry Pi, Nuvoton uses GPIO4 and the ST33KTPM uses GPIO24 (pin 18). Confirm your wiring before toggling.

```sh
# Assert reset low, release high, wait for TPM startup (Nuvoton GPIO4 shown)
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
# ST33: use line 24 instead of 4
```

wolfTPM can also drive this from code: build with `--enable-hal-reset` and call `TPM2_IoCb_Reset()` (default line: ST33 GPIO24, Nuvoton GPIO4). See `hal/README.md` in the source tree.

## TCG SPDM vendor commands

Both Nuvoton and Nations TPMs implement the TCG "TPM Communication over SPDM Secure Session" specification. These commands use 8-byte ASCII vendor codes in SPDM `VENDOR_DEFINED_REQUEST` messages with `StandardID=0x0001` (TCG).

| VdCode | Command | Vendor | Description |
|--------|---------|--------|-------------|
| `GET_PUBK` | Get Public Key | Both | Get TPM's SPDM-Identity P-384 public key |
| `GIVE_PUB` | Give Public Key | Both | Send host's P-384 public key to TPM |
| `TPM2_CMD` | TPM Command | Both | Wrap TPM command in SPDM secured message |
| `GET_STS_` | Get Status | Both | Query SPDM status |
| `SPDMONLY` | SPDM-Only Mode | Both | Lock/unlock SPDM-only enforcement |
| `PSK_SET_` | PSK Set | Nations | Provision pre-shared key (64-byte PSK + SHA-384 digest) |
| `PSK_CLR_` | PSK Clear | Nations | Clear provisioned PSK (requires ClearAuth) |

## Vendor specifics

### Nuvoton NPCT75x

- Enable/disable: SPDM is enabled via the `NTC2_PreConfig` vendor command (`--enable` / `--disable`). This persists across resets.
- GPIO reset: GPIO 4 is wired to TPM_RST on the Nuvoton daughter board. A GPIO reset clears stale SPDM state:

```sh
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

### Nations NS350

- Mode switching: identity key and PSK modes are mutually exclusive. The identity key is provisioned by factory default. Use `--identity-key-unset` before provisioning PSK, and `--identity-key-set` to restore.
- No GPIO reset: GPIO 4 is NOT wired to TPM_RST on the NS350 daughter board. A full power cycle (unplug and re-plug the Raspberry Pi) is required to reset the TPM. `sudo reboot` is not sufficient because the 3.3V rail stays powered.
- Capabilities query: use `--caps184` to query TPM 184 vendor properties including SPDM session info.
- ClearAuth: must be exactly 32 bytes. `PSK_SET` stores its SHA-384 digest (48 bytes). `PSK_CLEAR` sends the raw 32 bytes and the TPM computes SHA-384 to verify.

!!! note
    On some NS350 firmware versions, `--status` may report "Identity Key: not provisioned" even when the key is present. The `--connect` command is the definitive test: if the ECDHE handshake succeeds, the identity key is provisioned.

PSK vendor error codes:

| Code | Name | Description |
|------|------|-------------|
| 0xA1 | Vd_PSKAlreadySet | PSK already provisioned (must PSK_CLEAR first) |
| 0xA2 | Vd_InternalFailure | SPDM session layer internal error |
| 0xA3 | Vd_PSKNotSet | No PSK provisioned |
| 0xA5 | Vd_AuthFail | ClearAuth SHA-384 doesn't match stored digest |

### Auto-SPDM

Call `wolfTPM2_InitWithSpdmKey()` with the trusted responder key for identity mode, or `wolfTPM2_InitWithSpdmPsk()` with the provisioned PSK for PSK mode. Both entry points recover a TPM that is already locked in SPDM-only mode. The identity-mode initialization sequence is:

1. `TPM2_Startup` probes whether the TPM is already in SPDM-only mode.
2. The caller-provided responder key is installed as the trust anchor.
3. The discovered responder key is compared with that trusted key.
4. An SPDM session is always established (P-384 keygen and handshake).
5. If the probe returned `TPM_RC_DISABLED`, `TPM2_Startup` is retried securely.
6. All subsequent commands go through the SPDM encrypted channel.

In a dual-vendor build, `wolfTPM2_InitWithSpdmKey()` selects the identity adapter from the TPM DID/VID. A transport that does not expose DID/VID must call `wolfTPM2_InitWithSpdmKey_ex()` with `WOLFSPDM_MODE_NUVOTON` or `WOLFSPDM_MODE_NATIONS`. Automatic mode fails closed rather than guessing.

`wolfTPM2_Init()` without a credential fails closed if it detects any SPDM-only mode. For a normal-mode TPM that does not require an immediate secure channel, identity-mode applications may instead call `wolfTPM2_SpdmInit()`, `wolfTPM2_SpdmSetResponderPubKey()`, and then the vendor-specific connect function.

Both `TPM2_SendCommand` (non-auth commands) and `TPM2_SendCommandAuth` (auth-session commands such as PCR operations, key creation, and signing) are intercepted and routed through SPDM when a session is active.

### Memory modes

- Static (default): zero heap allocation. The SPDM context uses about 32 KB of static memory, which suits embedded environments.
- Small stack (`--enable-smallstack`): the context is heap-allocated. Useful on platforms with small stacks.

## wolfSPDM API

| Function | Description |
|----------|-------------|
| `wolfSPDM_InitStatic()` | Initialize context in caller-provided buffer (static mode) |
| `wolfSPDM_New()` | Allocate and initialize context on heap (dynamic mode) |
| `wolfSPDM_Init()` | Initialize a pre-allocated context |
| `wolfSPDM_Free()` | Free context (releases resources; frees heap only if dynamic) |
| `wolfSPDM_GetCtxSize()` | Return `sizeof(WOLFSPDM_CTX)` at runtime |
| `wolfSPDM_SetIO()` | Set transport I/O callback |
| `wolfSPDM_SetResponderPubKey()` | Pin the trusted responder P-384 key |
| `wolfSPDM_SetDebug()` | Enable/disable debug output |
| `wolfSPDM_Connect()` | Full SPDM handshake |
| `wolfSPDM_IsConnected()` | Check session status |
| `wolfSPDM_Disconnect()` | End session |
| `wolfSPDM_SecuredExchange()` | Encrypt/send/receive/decrypt in one call |

## Troubleshooting

### Handshake fails after an interrupted session

Stale SPDM state on the TPM can make the next handshake fail. Reset the TPM.

- Nuvoton: GPIO 4 is wired to TPM_RST on the Nuvoton daughter board, so a GPIO reset clears the state:

```sh
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

- Nations NS350: GPIO 4 is NOT wired to TPM_RST on the NS350 daughter board. A full power cycle (unplug and re-plug the Raspberry Pi) is required. `sudo reboot` is not sufficient because the 3.3V rail stays powered.

### SPDM error codes

| Code | Name | Description |
|------|------|-------------|
| 0x01 | InvalidRequest | Message format incorrect |
| 0x04 | UnexpectedRequest | Message out of sequence |
| 0x05 | DecryptError | Decryption or MAC verification failed |
| 0x06 | UnsupportedRequest | Request not supported or format rejected |
| 0x41 | VersionMismatch | SPDM version mismatch |

## Standard SPDM support

The in-tree TPM profile covers only the TCG SPDM binding. For standard SPDM protocol support, including sessions with the DMTF spdm-emu emulator, measurements, challenge authentication, heartbeat, and key update, use the standalone [wolfSPDM](https://github.com/wolfSSL/wolfSPDM) library. Those features are out of scope in wolfTPM.

## Automated tests

`spdm_test.sh` runs the full SPDM setup lifecycle:

```sh
# Nuvoton (identity key, includes GPIO resets between tests)
export SPDM_RESPONDER_PUBKEY=<trusted_p384_x_y_hex>
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nuvoton

# Nations (identity key, no GPIO resets)
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nations

# Nations (PSK, full lifecycle: provision, connect, clear, restore)
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nations-psk
```

The identity-mode hardware runs require `SPDM_RESPONDER_PUBKEY` from a trusted provisioning source (device provisioning records). The PSK run does not use it. The `fwtpm-tcg` test instead reads the freshly generated public key from the owner-only server log created by the test harness and passes it through the same pinning interface. This local bootstrap is not a hardware provisioning mechanism.

For production use with hardware TPMs and SPDM support, contact support@wolfssl.com.

## See Also

- [fwtpm/spdm.md](fwtpm/spdm.md)
- [post-quantum.md](post-quantum.md)
- [FWTPM.md](fwtpm/overview.md)
- [DEVTPM.md](system-interfaces.md)
