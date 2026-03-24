# wolfTPM SPDM

wolfTPM includes built-in SPDM support for Nuvoton NPCT75x and Nations NS350
TPMs using wolfSSL/wolfCrypt. Both vendors support identity key mode (ECDHE
P-384) for session establishment. The Nations NS350 additionally supports PSK
(pre-shared key) mode. Once a session is established, all TPM commands and
responses are encrypted with AES-256-GCM over the existing SPI/I2C bus — no
application code changes needed.

For standard SPDM protocol testing with the DMTF spdm-emu emulator, see the
[wolfSPDM](https://github.com/aidangarske/wolfSPDM) standalone library.

## Quick Start

### Nuvoton NPCT75x

```bash
# Build wolfSSL
pushd ../wolfssl && ./autogen.sh && \
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp && \
make && sudo make install && sudo ldconfig && popd

# Build wolfTPM
./autogen.sh && ./configure --enable-spdm --enable-nuvoton && make

# Enable SPDM (one-time), reset, connect
./examples/spdm/spdm_demo --enable
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
./examples/spdm/spdm_demo --connect
```

See [Building](#building) and [Nuvoton NPCT75x Details](#nuvoton-npct75x) for
full instructions.

### Nations NS350

```bash
# Build wolfSSL
pushd ../wolfssl && ./autogen.sh && \
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp && \
make && sudo make install && sudo ldconfig && popd

# Build wolfTPM
./autogen.sh && ./configure --enable-spdm --enable-nations && make

# Connect (identity key is factory default)
./examples/spdm/spdm_demo --connect
```

See [Building](#building) and [Nations NS350 Details](#nations-ns350) for full
instructions.

## How It Works

SPDM (Security Protocol and Data Model) establishes an authenticated encrypted
channel over the existing SPI/I2C bus. The implementation uses Algorithm Set B:
ECDH P-384 / SHA-384 / AES-256-GCM. Two session establishment modes are
supported.

### Protocol Flow: Identity Key Mode (Nuvoton + Nations)

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

The handshake uses ECDH P-384 for key agreement and HMAC-SHA384 for
authentication. After the handshake, all TPM commands are wrapped in SPDM
`VENDOR_DEFINED_REQUEST("TPM2_CMD")` messages and encrypted with AES-256-GCM.
A sequence number increments with each message to prevent replay attacks.

### Protocol Flow: PSK Mode (Nations Only)

PSK mode replaces the ECDHE key exchange with a symmetric pre-shared key.
The same AES-256-GCM encryption is used for data transport.

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

PSK and identity key modes are mutually exclusive on the NS350. The identity
key is provisioned by factory default; it must be unset before PSK can be used.
See [PSK Lifecycle (Nations)](#psk-lifecycle-nations).

### SPDM-Only Mode (Encrypted Bus Enforcement)

SPDM-only mode forces all TPM commands through the encrypted SPDM channel.
Both vendors support this. The typical lifecycle:

```
1. Enable SPDM        (one-time, persists across resets)
2. Connect            (handshake, derives session keys)
3. Lock SPDM-only     (TPM rejects all cleartext commands)
4. Reset              (TPM enters SPDM-only enforcement)
5. Run any commands   (each auto-establishes SPDM, all AES-256-GCM encrypted)
6. Unlock             (connect + unlock in one session)
7. Reset              (TPM back to normal cleartext mode)
```

Step 5 is fully automatic. When wolfTPM detects SPDM-only mode (TPM2_Startup
returns `TPM_RC_DISABLED`), it transparently establishes an SPDM session.
Existing applications like `caps`, `wrap_test`, and `unit.test` work without
modification — all commands are encrypted over the bus. See
[How Auto-SPDM Works](#how-auto-spdm-works) for details.

**Reset method differs by vendor:**
- **Nuvoton:** GPIO reset — `gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2`
- **Nations:** Full power cycle required (GPIO 4 is not wired to TPM_RST on NS350 daughter boards)

## Building

### wolfSSL

```bash
pushd ../wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-ecc --enable-sha384 \
    --enable-aesgcm --enable-hkdf --enable-sp
make
sudo make install && sudo ldconfig
popd
```

Both Nuvoton and Nations use the same wolfSSL flags above.

### wolfTPM

```bash
./autogen.sh
./configure --enable-spdm --enable-nuvoton   # Nuvoton
# or
./configure --enable-spdm --enable-nations    # Nations
make
```

### Configure Options

| Option                      | Description |
|-----------------------------|-------------|
| `--enable-spdm`             | Enable SPDM support (required) |
| `--enable-nuvoton`          | Enable Nuvoton TPM hardware support |
| `--enable-nations`          | Enable Nations NS350 hardware support |
| `--enable-debug`            | Debug output with verbose SPDM tracing |
| `--enable-smallstack`       | Heap-allocated SPDM context (default: static ~32 KB) |

## Usage

### One-Time Setup

#### Nuvoton

```bash
# Enable SPDM on the TPM (persists across resets)
./examples/spdm/spdm_demo --enable

# GPIO reset
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2

# Verify SPDM is enabled
./examples/spdm/spdm_demo --status
```

#### Nations

Identity key mode is the factory default — no setup required. If previously
unset, restore with:

```bash
./examples/spdm/spdm_demo --identity-key-set
```

### Establishing a Session

#### Identity Key Mode (Both Vendors)

```bash
# Establish SPDM session (VERSION → GET_PUBK → KEY_EXCHANGE → GIVE_PUB → FINISH)
./examples/spdm/spdm_demo --connect

# Query SPDM status
./examples/spdm/spdm_demo --status
```

**Note:** `--get-pubkey` retrieves the TPM's identity key as part of the full
handshake within `--connect`. It is not intended as a standalone command.

#### PSK Mode (Nations)

Requires PSK to be provisioned first. See
[PSK Lifecycle (Nations)](#psk-lifecycle-nations).

```bash
# Establish PSK session (VERSION → CAPS → ALGO → PSK_EXCHANGE → PSK_FINISH)
./examples/spdm/spdm_demo --psk <psk_hex_128chars>
```

### Lock/Unlock SPDM-Only Mode

Lock requires an active SPDM session. After locking, a reset is required for
enforcement to take effect.

**Nuvoton (identity key):**

```bash
./examples/spdm/spdm_demo --connect --lock
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2

# TPM now requires SPDM — all commands auto-encrypted:
./examples/wrap/caps          # auto-SPDM session, all AES-256-GCM
./tests/unit.test             # full test suite over encrypted bus

# Unlock
./examples/spdm/spdm_demo --connect --unlock
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

**Nations (identity key):**

```bash
./examples/spdm/spdm_demo --connect --lock
# Power cycle required (unplug and re-plug Raspberry Pi)

./examples/spdm/spdm_demo --connect --unlock
# Power cycle again
```

**Nations (PSK mode):**

```bash
./examples/spdm/spdm_demo --psk <hex> --lock
# Power cycle required

./examples/spdm/spdm_demo --psk <hex> --unlock
# Power cycle again
```

### PSK Lifecycle (Nations)

PSK and identity key modes are mutually exclusive on the NS350. The identity key
is provisioned by default; it must be unset before PSK can be used.

```bash
# 1. Unset identity key (enables PSK mode)
./examples/spdm/spdm_demo --identity-key-unset

# 2. Provision PSK (64-byte PSK + 32-byte ClearAuth)
#    The demo computes SHA-384(ClearAuth) and sends PSK(64)+Digest(48) = 112 bytes
./examples/spdm/spdm_demo --psk-set <psk_hex_128chars> <clearauth_hex_64chars>

# 3. Establish PSK session
./examples/spdm/spdm_demo --psk <psk_hex_128chars>

# 4. Clear PSK (sends raw 32-byte ClearAuth; TPM verifies SHA-384 internally)
./examples/spdm/spdm_demo --psk-clear <clearauth_hex_64chars>

# 5. Restore identity key (factory default)
./examples/spdm/spdm_demo --identity-key-set
```

**Important:** The ClearAuth must be exactly 32 bytes. PSK_SET stores its SHA-384
digest (48 bytes). PSK_CLEAR sends the raw 32 bytes and the TPM computes SHA-384
to verify. Using the wrong size makes PSK_CLEAR impossible.

### Running the Test Suite

```bash
# Nuvoton (identity key — includes GPIO resets between tests)
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_demo nuvoton

# Nations (identity key — no GPIO resets)
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_demo nations

# Nations (PSK — full lifecycle: provision → connect → clear → restore)
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_demo nations-psk
```

## TCG SPDM Vendor Commands

Both Nuvoton and Nations TPMs implement the TCG "TPM Communication over SPDM
Secure Session" specification. These commands use 8-byte ASCII vendor codes in
SPDM `VENDOR_DEFINED_REQUEST` messages with `StandardID=0x0001` (TCG).

| VdCode      | Command         | Vendor  | Description |
|-------------|-----------------|---------|-------------|
| `GET_PUBK`  | Get Public Key  | Both    | Get TPM's SPDM-Identity P-384 public key |
| `GIVE_PUB`  | Give Public Key | Both    | Send host's P-384 public key to TPM |
| `TPM2_CMD`  | TPM Command     | Both    | Wrap TPM command in SPDM secured message |
| `GET_STS_`  | Get Status      | Both    | Query SPDM status |
| `SPDMONLY`  | SPDM-Only Mode  | Both    | Lock/unlock SPDM-only enforcement |
| `PSK_SET_`  | PSK Set         | Nations | Provision pre-shared key (64-byte PSK + SHA-384 digest) |
| `PSK_CLR_`  | PSK Clear       | Nations | Clear provisioned PSK (requires ClearAuth) |

## Command Reference

All `spdm_demo` options in one table:

| Option                        | Vendor  | Description |
|-------------------------------|---------|-------------|
| `--enable`                    | Nuvoton | Enable SPDM via NTC2_PreConfig (one-time, persists) |
| `--disable`                   | Nuvoton | Disable SPDM via NTC2_PreConfig |
| `--identity-key-set`          | Nations | Provision SPDM identity key (factory default) |
| `--identity-key-unset`        | Nations | Un-provision identity key (required before PSK) |
| `--get-pubkey`                | Both    | Get TPM's SPDM-Identity P-384 public key (used within `--connect`) |
| `--connect`                   | Both    | Establish identity key SPDM session |
| `--status`                    | Both    | Query SPDM status |
| `--lock`                      | Both    | Lock SPDM-only mode (requires active session) |
| `--unlock`                    | Both    | Unlock SPDM-only mode (requires active session) |
| `--psk <psk>`                 | Nations | Establish PSK session (64-byte PSK) |
| `--psk-set <psk> <clearauth>` | Nations | Provision PSK (64-byte PSK, 32-byte ClearAuth) |
| `--psk-clear <clearauth>`     | Nations | Clear PSK (32-byte ClearAuth) |
| `--caps184`                   | Nations | Query TPM 184 vendor properties and SPDM session info |
| `--tpm-clear`                 | Nations | Send TPM2_Clear (platform auth) |

## Vendor-Specific Details

### Nuvoton NPCT75x

**Enable/Disable:** SPDM is enabled via the `NTC2_PreConfig` vendor command
(`--enable` / `--disable`). This persists across resets.

**GPIO Reset:** GPIO 4 is wired to TPM_RST on the Nuvoton daughter board.
A GPIO reset clears stale SPDM state:

```bash
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

### Nations NS350

**Mode Switching:** Identity key and PSK modes are mutually exclusive. The
identity key is provisioned by factory default. Use `--identity-key-unset`
before provisioning PSK, and `--identity-key-set` to restore.

**No GPIO Reset:** GPIO 4 is NOT wired to TPM_RST on the NS350 daughter board.
A full power cycle (unplug and re-plug the Raspberry Pi) is required to reset
the TPM. `sudo reboot` is not sufficient as the 3.3V rail stays powered.

**Capabilities Query:** Use `--caps184` to query TPM 184 vendor properties
including SPDM session info.

**Status Caveat:** On some NS350 firmware versions, `--status` may report
"Identity Key: not provisioned" even when the key is present. The `--connect`
command is the definitive test — if the ECDHE handshake succeeds, the identity
key is provisioned.

**ClearAuth:** Must be exactly 32 bytes. `PSK_SET` stores its SHA-384 digest
(48 bytes). `PSK_CLEAR` sends the raw 32 bytes and the TPM computes SHA-384
to verify.

**PSK Vendor Error Codes:**

| Code | Name | Description |
|------|------|-------------|
| 0xA1 | Vd_PSKAlreadySet | PSK already provisioned (must PSK_CLEAR first) |
| 0xA2 | Vd_InternalFailure | SPDM session layer internal error |
| 0xA3 | Vd_PSKNotSet | No PSK provisioned |
| 0xA5 | Vd_AuthFail | ClearAuth SHA-384 doesn't match stored digest |

## How Auto-SPDM Works

When the TPM is in SPDM-only mode, `wolfTPM2_Init()` handles everything:

1. `TPM2_Startup` is sent in cleartext — TPM returns `TPM_RC_DISABLED`
2. wolfTPM detects this and sets `spdmOnlyDetected`
3. An SPDM session is automatically established (P-384 keygen + handshake)
4. `TPM2_Startup` is retried over the encrypted channel — succeeds
5. All subsequent commands go through the SPDM encrypted channel

Both `TPM2_SendCommand` (non-auth commands) and `TPM2_SendCommandAuth`
(auth-session commands like PCR operations, key creation, signing) are
intercepted and routed through SPDM when a session is active.

## Memory Modes

**Static (default):** Zero heap allocation. SPDM context uses ~32 KB of
static memory, ideal for embedded environments.

**Small stack (`--enable-smallstack`):** Context is heap-allocated.
Useful on platforms with small stacks.

## wolfSPDM API

| Function                     | Description |
|------------------------------|-------------|
| `wolfSPDM_InitStatic()`      | Initialize context in caller-provided buffer (static mode) |
| `wolfSPDM_New()`             | Allocate and initialize context on heap (dynamic mode) |
| `wolfSPDM_Init()`            | Initialize a pre-allocated context |
| `wolfSPDM_Free()`            | Free context (releases resources; frees heap only if dynamic) |
| `wolfSPDM_GetCtxSize()`      | Return `sizeof(WOLFSPDM_CTX)` at runtime |
| `wolfSPDM_SetIO()`           | Set transport I/O callback |
| `wolfSPDM_SetDebug()`        | Enable/disable debug output |
| `wolfSPDM_Connect()`         | Full SPDM handshake |
| `wolfSPDM_IsConnected()`     | Check session status |
| `wolfSPDM_Disconnect()`      | End session |
| `wolfSPDM_SecuredExchange()` | Encrypt/send/receive/decrypt in one call |

## Troubleshooting

### SPDM handshake fails after interrupted session

**Nuvoton:** GPIO 4 is wired to TPM_RST on the Nuvoton daughter board.
A GPIO reset clears stale SPDM state:

```bash
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

**Nations NS350:** GPIO 4 is NOT wired to TPM_RST on the NS350 daughter board.
A full power cycle (unplug and re-plug the Raspberry Pi) is required to reset
the TPM. `sudo reboot` is not sufficient as the 3.3V rail stays powered.

### SPDM Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x01 | InvalidRequest | Message format incorrect |
| 0x04 | UnexpectedRequest | Message out of sequence |
| 0x05 | DecryptError | Decryption or MAC verification failed |
| 0x06 | UnsupportedRequest | Request not supported or format rejected |
| 0x41 | VersionMismatch | SPDM version mismatch |

## Standard SPDM Support

For standard SPDM protocol support including session establishment with the
DMTF spdm-emu emulator, measurements, challenge authentication, heartbeat,
and key update, see the [wolfSPDM](https://github.com/aidangarske/wolfSPDM)
standalone library.

## License

GPLv3 — see LICENSE file. Copyright (C) 2006-2025 wolfSSL Inc.
