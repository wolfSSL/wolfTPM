# SPDM Attestation and Secure Sessions

wolfTPM includes built-in SPDM (Security Protocol and Data Model, DMTF DSP0274) support for Nuvoton NPCT75x and Nations NS350 TPMs, using wolfSSL/wolfCrypt. SPDM negotiates protocol version 1.3 over the TCG SPDM-over-TPM binding. Both vendors support identity key mode (ECDHE P-384) for session establishment. The Nations NS350 additionally supports PSK (pre-shared key) mode. Once a session is established, all TPM commands and responses are encrypted with AES-256-GCM over the existing SPI or I2C bus. Identity key mode requires the responder's P-384 public key from a trusted provisioning source. The TCG exchange is a raw public key exchange (GET_PUBK and GIVE_PUB); no certificates are exchanged.

The SPDM code lives in the [wolfSPDM](https://github.com/wolfSSL/wolfSPDM) library, included as the `lib/wolfSPDM` submodule and compiled into libwolftpm in its TPM profile. A checkout that will use SPDM needs the submodule present, either from a recursive clone or from initializing it afterward. Without it, `./configure --enable-spdm` stops with: `--enable-spdm needs the wolfSPDM submodule: run git submodule update --init lib/wolfSPDM`.

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

# Enable SPDM (one-time), reset (see TPM reset pin control), connect
./examples/spdm/spdm_ctrl --enable
timeout 0.1 gpioset --chip gpiochip0 4=0; gpioset --chip gpiochip0 --daemonize 4=1; sleep 2
RESPONDER_PUBKEY="$(cat responder_pubkey.hex)"
./examples/spdm/spdm_ctrl --responder-pubkey "$RESPONDER_PUBKEY" --connect
```

The GPIO line above is the libgpiod 2.x form. See the TPM reset pin control section for the libgpiod 1.x form and caveats. `responder_pubkey.hex` holds the trusted raw P-384 X||Y point (192 hex characters) from your provisioning records.

### Nations NS350

```sh
# Build wolfSSL (in the sibling checkout, then return here)
cd ../wolfssl && ./autogen.sh && \
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp && \
make && sudo make install && sudo ldconfig && cd -

# Build wolfTPM (submodule already present from the recursive clone)
./autogen.sh && ./configure --enable-spdm --enable-nations && make

# Connect (identity key is factory default)
RESPONDER_PUBKEY="$(cat responder_pubkey.hex)"
./examples/spdm/spdm_ctrl --responder-pubkey "$RESPONDER_PUBKEY" --connect
```

## Overview and how it works

The `spdm_ctrl` tool establishes SPDM secure sessions between the host and a TPM over SPI or I2C, enabling AES-256-GCM encrypted bus communication. The implementation uses Algorithm Set B: SHA-384 and AES-256-GCM, with ECDH P-384, ECDSA P-384, and HKDF-SHA384 added in identity key mode. Two session establishment modes are supported.

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
  |--- GET_CAPABILITIES ------------->|  (Nations only)
  |<-- CAPABILITIES ------------------|
  |--- NEGOTIATE_ALGORITHMS --------->|  (Nations only)
  |<-- ALGORITHMS --------------------|
  |                                   |
  |--- GET_PUBK --------------------->|  (get TPM's P-384 identity key)
  |<-- GET_PUBK response -------------|
  |                                   |
  |--- KEY_EXCHANGE ----------------->|  (ECDHE P-384 key agreement)
  |<-- KEY_EXCHANGE_RSP --------------|  (+ ECDSA signature and HMAC)
  |                                   |
  |    --- Handshake keys derived --- |
  |                                   |
  |=== GIVE_PUB =====================>|  (encrypted: host's P-384 key)
  |<== GIVE_PUB response =============|
  |                                   |
  |=== FINISH =======================>|  (encrypted: signature + HMAC)
  |<== FINISH_RSP ====================|
  |                                   |
  |    --- App data keys derived ---  |
  |                                   |
  |=== TPM2_CMD (AES-256-GCM) =======>|  (every command encrypted)
  |<== TPM2_RSP (AES-256-GCM) ========|
```

The Nuvoton adapter skips GET_CAPABILITIES and NEGOTIATE_ALGORITHMS; the Nations adapter sends them after VERSION. The handshake uses ECDH P-384 for key agreement, ECDSA P-384 signatures, HKDF-SHA384 for key derivation, and HMAC-SHA384 for authentication. P-384 is not part of the PSK key agreement. After the handshake, all TPM commands are wrapped in SPDM `VENDOR_DEFINED_REQUEST("TPM2_CMD")` messages and encrypted with AES-256-GCM. TPM responses arrive in `VENDOR_DEFINED_RESPONSE` messages. Secured records keep independent 64-bit request and response sequence numbers that increment with each message to prevent replay.

### PSK mode (Nations only)

PSK mode replaces the ECDHE key exchange with a symmetric pre-shared key. The same AES-256-GCM encryption is used for data transport. The requester goes straight from GET_VERSION to PSK_EXCHANGE; capability and algorithm negotiation are not required for this flow.

```
Host                                TPM (Nations NS350)
  |                                   |
  |--- GET_VERSION ------------------>| (negotiate SPDM version)
  |<-- VERSION -----------------------|
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

PSK and identity key modes are mutually exclusive on the NS350. The identity key is provisioned by factory default and must be unset before PSK can be used. See the PSK lifecycle section.

### SPDM-only mode (encrypted bus enforcement)

SPDM-only mode forces TPM commands through the encrypted SPDM channel. The one exception is plaintext `TPM2_GetCapability`, which the fwTPM responder deliberately allows while locked to match the supported silicon. Both vendors support SPDM-only mode. The typical lifecycle:

```
1. Enable SPDM        (one-time, persists across resets)
2. Connect            (handshake, derives session keys)
3. Lock SPDM-only     (TPM rejects cleartext commands except GetCapability)
4. Reset              (TPM enters SPDM-only enforcement)
5. Initialize with the trusted key or PSK and run commands (all encrypted)
6. Unlock             (connect + unlock in one session)
7. Reset              (TPM back to normal cleartext mode)
```

After an application supplies the responder key through `wolfTPM2_InitWithSpdmKey()`, wolfTPM authenticates the responder and establishes the encrypted session. It continues after a successful or already-initialized startup probe and after the expected `TPM_RC_DISABLED` result. Other startup failures, such as a firmware-upgrade state, are returned before any SPDM connection is attempted. See the Auto-SPDM section for details.

The reset method differs by vendor:

- Nuvoton: GPIO 4 reset (see TPM reset pin control)
- Nations: GPIO 4 is wired to TPM_RST on the NS350 daughter board used by the test harness, so the same GPIO reset applies there. If your board does not wire it, use a full power cycle.

## Building

### 1. Clone with the wolfSPDM submodule

See the Quick start section. SPDM is built from the `lib/wolfSPDM` submodule, so clone wolfTPM recursively, or run `git submodule update --init lib/wolfSPDM` in an existing checkout.

### 2. wolfSSL

Both Nuvoton and Nations use the same wolfSSL flags, which provide the crypto for SPDM Algorithm Set B. wolfSSL 5.8.0 or later is required; the wolfSPDM configure check in the `lib/wolfSPDM` submodule enforces this.

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

Build with `--enable-spdm` plus at least one handshake mode: `--enable-tcg` for the TCG raw public key handshake, `--enable-psk` for the PSK handshake. Vendor wire-format adapters are optional (`--enable-nuvoton`, `--enable-nations`).

### The wolfTPM SPDM profile

`--enable-spdm` defines `WOLFTPM_SPDM`, which auto-selects wolfSPDM's `WOLFSPDM_PROFILE_TPM`. The TPM binding is the TCG SPDM Binding, so this profile is a lean, TCG-focused build. The generic DSP0274 requester functions below are compiled out automatically. The Nations adapter still uses its own TCG-specific GET_CAPABILITIES and NEGOTIATE_ALGORITHMS implementations in `spdm_tcg.c`.

- the DMTF standard requester functions: `GET_CAPABILITIES`, `NEGOTIATE_ALGORITHMS`, `GET_DIGESTS`, `GET_CERTIFICATE`, and certificate-chain validation
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
| `--enable-fwtpm` | Build fwtpm_server with the SPDM responder (needs `--enable-spdm` and a handshake mode; no silicon needed) |
| `--enable-nuvoton` | Enable Nuvoton TPM hardware support (auto-enables `--enable-tcg`) |
| `--enable-nations` | Enable Nations NS350 hardware support (auto-enables `--enable-tcg --enable-psk`) |
| `--enable-debug` | Debug output with verbose SPDM tracing |
| `--enable-smallstack` | Heap-allocate the SPDM context and the SPDM request and response buffers, and lower the public message-size limits (default: caller-owned inline context, about 32 KB) |

`configure` rejects these incompatible combinations:

- `--enable-nuvoton --disable-tcg` (Nuvoton uses the TCG SPDM Binding)
- `--enable-nations --disable-tcg` or `--enable-nations --disable-psk`
- `--enable-psk --disable-tcg` (PSK rides on TCG framing)

### fwTPM SPDM responder (no silicon required)

`fwtpm_server` ships an SPDM 1.3 responder that drives the same handshake the real Nuvoton and Nations parts use, so the full TCG and PSK stack can be exercised in CI without real hardware:

Build it with the socket responder enabled:

```sh
./configure --enable-fwtpm --enable-swtpm --enable-spdm --enable-tcg --enable-psk
make
```

Then start it in one of the SPDM modes. The fwTPM responder accepts a PSK of up to 64 bytes (128 hex characters) and rejects only an empty PSK or one longer than that; the exact 64-byte requirement applies to Nations hardware provisioning, not to this responder. The value below is the test PSK used by `spdm_test.sh`:

```sh
SPDM_PSK=dbc2192291d807742441b963f6712841f7697e2e39c45931f3abc53658c8b9338bd3561cab5d90cf9e493295bb5bd6b2c455e0fd19392e0ce4f3433cbcfc7047
./src/fwtpm/fwtpm_server --spdm-tcg                              # TCG raw public key handshake
./src/fwtpm/fwtpm_server --spdm-psk --spdm-psk-hex "$SPDM_PSK"   # PSK handshake
```

For a manual PSK test, supply the same `SPDM_PSK` value to the requester, for example `spdm_ctrl --psk "$SPDM_PSK"`.

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
    --responder-pubkey "$RESPONDER_PUBKEY" --connect
./examples/spdm/spdm_ctrl --vendor=nations \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect
```

Single-vendor builds accept only the adapter compiled into the binary and reject an unavailable `--vendor=` value.

## Usage and control commands

### One-time setup

The administrative commands (enable, disable, identity key set and unset) use an empty platform authorization, and `--tpm-clear` uses the default empty lockout authorization. `spdm_ctrl` has no option to supply different hierarchy secrets, so these commands do not work on a TPM provisioned with non-empty authorizations.

Nuvoton:

```sh
# Enable SPDM on the TPM (persists across resets)
./examples/spdm/spdm_ctrl --enable

# Reset the TPM (see TPM reset pin control)

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
# Establish SPDM session (VERSION, GET_PUBK, KEY_EXCHANGE, GIVE_PUB, FINISH;
# Nations also sends GET_CAPABILITIES and NEGOTIATE_ALGORITHMS)
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect

# Query SPDM status
./examples/spdm/spdm_ctrl --status
```

`--responder-pubkey` takes the trusted raw P-384 X||Y point as 192 hex characters. Obtain it from device provisioning records or another authenticated manufacturer channel. The examples here read these values into shell variables, for instance `RESPONDER_PUBKEY="$(cat responder_pubkey.hex)"`. The responder public key is not secret, but it is a trust anchor, so protect it from tampering. The PSK and ClearAuth are secrets: keep those files readable only by their owner (`chmod 600`).

!!! warning
    `--get-pubkey` is unauthenticated discovery and must not be used by itself to establish trust.

PSK mode (Nations) requires the PSK to be provisioned first. See the PSK lifecycle section. In the commands below, `PSK_HEX` holds the 64-byte PSK as 128 hex characters and `CLEARAUTH_HEX` holds the 32-byte ClearAuth as 64 hex characters, each read from a file only you can read.

```sh
# Establish PSK session (VERSION, PSK_EXCHANGE, PSK_FINISH)
./examples/spdm/spdm_ctrl --psk "$PSK_HEX"
```

### Lock and unlock SPDM-only mode

Lock requires an active SPDM session. After locking, a reset is required for enforcement to take effect.

Nuvoton (identity key):

```sh
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --lock
# Reset the TPM (see TPM reset pin control)

# Unlock
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --unlock
# Reset the TPM again
```

Nations (identity key):

```sh
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --lock
# Reset the TPM (GPIO 4 on the tested board, otherwise a power cycle)

./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --unlock
# Reset the TPM again
```

Nations (PSK mode):

```sh
./examples/spdm/spdm_ctrl --psk "$PSK_HEX" --lock
# Reset the TPM

./examples/spdm/spdm_ctrl --psk "$PSK_HEX" --unlock
# Reset the TPM again
```

### PSK lifecycle (Nations)

PSK and identity key modes are mutually exclusive on the NS350. The identity key is provisioned by default and must be unset before PSK can be used.

```sh
# 1. Unset identity key (enables PSK mode)
./examples/spdm/spdm_ctrl --identity-key-unset

# 2. Provision PSK (64-byte PSK + 32-byte ClearAuth)
#    The demo computes SHA-384(ClearAuth) and sends PSK(64)+Digest(48) = 112 bytes
./examples/spdm/spdm_ctrl --psk-set "$PSK_HEX" "$CLEARAUTH_HEX"

# 3. Establish PSK session
./examples/spdm/spdm_ctrl --psk "$PSK_HEX"

# 4. Clear PSK (sends raw 32-byte ClearAuth; TPM verifies SHA-384 internally)
./examples/spdm/spdm_ctrl --psk-clear "$CLEARAUTH_HEX"

# 5. Restore identity key (factory default)
./examples/spdm/spdm_ctrl --identity-key-set
```

!!! warning
    The ClearAuth must be exactly 32 bytes. PSK_SET stores its SHA-384 digest (48 bytes). PSK_CLEAR sends the raw 32 bytes and the TPM computes SHA-384 to verify. `spdm_ctrl` rejects a ClearAuth of the wrong length.

### Command reference

All `spdm_ctrl` options (the set accepted depends on the vendor adapters compiled in):

| Option | Vendor | Description |
|--------|--------|-------------|
| `--enable` | Nuvoton | Enable SPDM via NTC2_PreConfig (one-time, persists, requires reset) |
| `--disable` | Nuvoton | Disable SPDM via NTC2_PreConfig (requires reset) |
| `--identity-key-set` | Nations | Provision SPDM identity key (factory default) |
| `--identity-key-unset` | Nations | Remove the provisioned identity key (required before PSK) |
| `--vendor=nuvoton\|nations` | Both | Select the identity/vendor adapter explicitly |
| `--get-pubkey` | Both | Discover the TPM identity key without authenticating it |
| `--responder-pubkey` *hex* | Both | Pin a trusted raw P-384 X\|\|Y responder key (192 hex characters) |
| `--connect` | Both | Establish identity key SPDM session (ECDH P-384 handshake) |
| `--caps` | Both | Read TPM capabilities over the current transport |
| `--status` | Both | Query SPDM status |
| `--session-info` | Both | Show the TPM's view of the SPDM session (`TPM_CAP_SPDM_SESSION_INFO`) |
| `--policy-nv` | Both | Define an NV index guarded by `TPM2_PolicyTransportSPDM`, then write and read it over the session |
| `--lock` | Both | Lock SPDM-only mode (needs an active session: `--connect`, or `--psk` for Nations PSK) |
| `--unlock` | Both | Unlock SPDM-only mode (needs an active session: `--connect`, or `--psk` for Nations PSK) |
| `--psk` *hex* | Nations | Establish PSK session (64-byte PSK) |
| `--psk-set` *psk* *clearauth* | Nations | Provision PSK (64-byte PSK, 32-byte ClearAuth) |
| `--psk-clear` *clearauth* | Nations | Clear PSK (32-byte ClearAuth) |
| `--caps184` | Nations | Query TPM 184 vendor properties and SPDM session info |
| `--tpm-clear` | Both | Send `TPM2_Clear` over the current transport (authorized with `TPM_RH_LOCKOUT`, default empty lockout auth) |

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
    --vendor=nuvoton --responder-pubkey "$RESPONDER_PUBKEY" --connect

# Lock SPDM-only mode (connect + lock in one session)
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --lock
# Reset the TPM

# Unlock SPDM-only mode
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --unlock
# Reset the TPM
```

### nv_bind

The `nv_bind` example is a focused, self-contained version of the `--policy-nv` idea. It provisions an NV index whose `authPolicy` is `TPM2_PolicyTransportSPDM`, stores a secret over an SPDM-PSK session, then shows that the identical read over a plain (non-SPDM) connection is refused with `TPM_RC_CHANNEL`.

```sh
./src/fwtpm/fwtpm_server --spdm-psk --spdm-psk-hex "$SPDM_PSK" --clear &
./examples/spdm/nv_bind --psk "$SPDM_PSK"
```

The fwTPM generates a fresh SPDM identity key each time it starts, so on the fwTPM a policy bound to `tpmKeyName` is only valid for that server lifetime. A hardware TPM holds a persistent identity key, where such a binding is durable. PSK sessions report empty key names, since no asymmetric key authenticated them.

### TPM reset pin control

SPDM enable/disable and SPDM-only mode changes require a TPM reset to take effect. A host-controllable reset pin is the easiest way to do that, but cycling the TPM power rail also works.

!!! warning
    For custom hardware designs, route the TPM reset pin to a host-controllable GPIO or make the TPM power rail switchable. Without a way to reset or power cycle the TPM, SPDM mode changes cannot be applied and recovery from SPDM-only mode is not possible.

The reset line is board specific. On a Raspberry Pi, Nuvoton uses GPIO4 and the ST33KTPM uses GPIO24 (pin 18). The tested NS350 daughter board also wires GPIO4 to TPM_RST. Confirm your wiring before toggling.

With libgpiod 1.x, `gpioset` drives the line and then, in its default mode, releases the request when it exits (the chip is a positional argument). The pulse below holds each level only while the board's pull resistor does, which is what `spdm_test.sh` relies on on the tested boards:

```sh
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

With libgpiod 2.x, the chip is given with `--chip`, and `gpioset` holds the line until the process exits, so a plain `&&` chain never reaches the release step. One way to pulse the line:

```sh
timeout 0.1 gpioset --chip gpiochip0 4=0
gpioset --chip gpiochip0 --daemonize 4=1
sleep 2
```

The 2.x form above was not run against the test harness, which uses the 1.x syntax. After `gpioset` exits, libgpiod does not guarantee the line state, so verify the reset line has a pull-up. For ST33 use line 24 instead of 4. For repeatable automation, prefer the wolfTPM reset HAL.

wolfTPM can also drive the reset from code: build with `--enable-hal-reset` and call `TPM2_IoCb_Reset(ctx, userCtx)`, which takes a `TPM2_CTX*` and a `void*`. The default line is ST33 GPIO24 and Nuvoton GPIO4. A Nations build also defaults to GPIO24 unless line 4 is supplied explicitly. See `hal/README.md` in the source tree.

## TCG SPDM vendor commands

Both Nuvoton and Nations TPMs implement the TCG "TPM Communication over SPDM Secure Session" binding. It carries each message as an SPDM `VENDOR_DEFINED_REQUEST` (request code `0xFE`) answered by a `VENDOR_DEFINED_RESPONSE` (response code `0x7E`), with `StandardID=0x0001` (TCG). The vendor code (VdCode) inside the message is an 8-byte ASCII string.

The published TCG table defines `GET_PUBK`, `GIVE_PUB`, `TPM2_CMD`, and optional locality-specific `TPM2CMD0` through `TPM2CMD4` values. `GET_STS_`, `SPDMONLY`, `PSK_SET_`, and `PSK_CLR_` are implementation or vendor extensions, not TCG-defined commands. The exact vendor-extension wire details for the two vendor adapters live in the `lib/wolfSPDM` submodule.

| VdCode | Command | Defined by | Vendor | Description |
|--------|---------|------------|--------|-------------|
| `GET_PUBK` | Get Public Key | TCG | Both | Get TPM's SPDM-Identity P-384 public key |
| `GIVE_PUB` | Give Public Key | TCG | Both | Send host's P-384 public key to TPM |
| `TPM2_CMD` | TPM Command | TCG | Both | Wrap TPM command in SPDM secured message |
| `GET_STS_` | Get Status | Vendor extension | Both | Query SPDM status |
| `SPDMONLY` | SPDM-Only Mode | Vendor extension | Both | Lock/unlock SPDM-only enforcement |
| `PSK_SET_` | PSK Set | Vendor extension | Nations | Provision pre-shared key (64-byte PSK + SHA-384 digest) |
| `PSK_CLR_` | PSK Clear | Vendor extension | Nations | Clear provisioned PSK (requires ClearAuth) |

## Vendor specifics

### Nuvoton NPCT75x

- Enable/disable: SPDM is enabled via the `NTC2_PreConfig` vendor command (`--enable` / `--disable`). This persists across resets.
- GPIO reset: GPIO 4 is wired to TPM_RST on the Nuvoton daughter board. A GPIO reset clears stale SPDM state. See TPM reset pin control for the commands.

### Nations NS350

- Mode switching: identity key and PSK modes are mutually exclusive. The identity key is provisioned by factory default. Use `--identity-key-unset` before provisioning PSK, and `--identity-key-set` to restore.
- Reset: the hardware-tested harness (`spdm_test.sh`) treats GPIO 4 as wired to TPM_RST on the NS350 daughter board and uses it when normalizing Nations state. The identity key and PSK are stored in NV and survive a reset. If your board does not wire the line, a full power cycle is needed, because `sudo reboot` leaves the 3.3V rail powered.
- Capabilities query: use `--caps184` to query TPM 184 vendor properties including SPDM session info.
- ClearAuth: must be exactly 32 bytes. `PSK_SET` stores its SHA-384 digest (48 bytes). `PSK_CLEAR` sends the raw 32 bytes and the TPM computes SHA-384 to verify.

!!! note
    On some NS350 firmware versions, `--status` may report "Identity Key: not provisioned" even when the key is present. The `--connect` command is the definitive test: if the ECDHE handshake succeeds, the identity key is provisioned.

Nations PSK operations can return vendor-specific error codes, for example PSK already provisioned, no PSK provisioned, an internal SPDM session error, or a ClearAuth that does not match the stored digest. The exact numeric values are firmware specific; they are not defined in public Nations material or in the source tree, so take them from the Nations integration guide for your firmware revision rather than from a fixed table here.

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

- Default: zero heap allocation. The SPDM context is a caller-owned inline context of about 32 KB. It is not necessarily static-duration storage; it lives wherever the caller places it.
- Small stack (`--enable-smallstack`): the wolfSPDM context and the SPDM request and response buffers are allocated with `XMALLOC`; some per-command buffers, such as the TPM response buffer and the TIS I/O buffer, stay on the stack. It also lowers three public message-size limits, so an oversized command or response can return `BUFFER_E`. Useful on platforms with small stacks; size payloads to the reduced limits.

`wolfSPDM_New()` exists only when wolfSPDM is built with `WOLFSPDM_DYNAMIC_MEMORY`. Without it, use `wolfSPDM_InitStatic()` or `wolfSPDM_Init()` on caller-provided storage.

## wolfSPDM API

| Function | Description |
|----------|-------------|
| `wolfSPDM_InitStatic()` | Initialize context in caller-provided buffer (static mode) |
| `wolfSPDM_New()` | Allocate and initialize context on heap (only with `WOLFSPDM_DYNAMIC_MEMORY`) |
| `wolfSPDM_Init()` | Initialize a pre-allocated context |
| `wolfSPDM_Free()` | Free context (releases resources; frees heap only if dynamic) |
| `wolfSPDM_GetCtxSize()` | Return `sizeof(WOLFSPDM_CTX)` at runtime |
| `wolfSPDM_SetIO()` | Set transport I/O callback |
| `wolfSPDM_SetResponderPubKey()` | Pin the trusted responder P-384 key (identity mode) |
| `wolfSPDM_SetPSK()` | Set the pre-shared key (PSK mode) |
| `wolfSPDM_SetMode()` | Select the vendor/handshake mode |
| `wolfSPDM_SetRequesterKeyPair()` | Set the host's P-384 key pair used for GIVE_PUB and FINISH |
| `wolfSPDM_SetDebug()` | Enable/disable debug output |
| `wolfSPDM_Connect()` | Full SPDM handshake |
| `wolfSPDM_IsConnected()` | Check session status |
| `wolfSPDM_Disconnect()` | End session |
| `wolfSPDM_SecuredExchange()` | Encrypt/send/receive/decrypt in one call |

## Troubleshooting

### Handshake fails after an interrupted session

Stale SPDM state on the TPM can make the next handshake fail. Reset the TPM.

- Nuvoton: GPIO 4 is wired to TPM_RST on the Nuvoton daughter board, so a GPIO reset clears the state. See TPM reset pin control for the commands.
- Nations NS350: the tested daughter board also wires GPIO 4 to TPM_RST, so the same GPIO reset applies. If your board does not wire it, do a full power cycle. `sudo reboot` is not sufficient because the 3.3V rail stays powered.

### SPDM error codes

| Code | Name | Description |
|------|------|-------------|
| 0x01 | InvalidRequest | Message format incorrect |
| 0x04 | UnexpectedRequest | Message out of sequence |
| 0x05 | Unspecified | Unspecified error |
| 0x06 | DecryptError | Decryption or MAC verification failed |
| 0x07 | UnsupportedRequest | Request not supported or format rejected |
| 0x41 | MajorVersionMismatch | SPDM major version mismatch |

## Standard SPDM support

The in-tree TPM profile covers only the TCG SPDM binding. For standard SPDM protocol support, including sessions with the DMTF spdm-emu emulator, measurements, challenge authentication, heartbeat, and key update, use the standalone [wolfSPDM](https://github.com/wolfSSL/wolfSPDM) library. Those features are out of scope in wolfTPM.

## Automated tests

`spdm_test.sh` runs the full SPDM setup lifecycle:

```sh
# Nuvoton (identity key, includes GPIO resets between tests)
SPDM_RESPONDER_PUBKEY="$(cat responder_pubkey.hex)"
export SPDM_RESPONDER_PUBKEY
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nuvoton

# Nations (identity key; the harness also uses GPIO 4 to normalize state)
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
