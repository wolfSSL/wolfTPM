# wolfTPM SPDM

wolfTPM includes built-in SPDM support for Nuvoton NPCT75x TPMs using
wolfSSL/wolfCrypt. This provides encrypted bus communication between the host
and TPM, ensuring all commands and responses are protected with AES-256-GCM.

For standard SPDM protocol testing with the DMTF spdm-emu emulator, see the
[wolfSPDM](https://github.com/aidangarske/wolfSPDM) standalone library.

## How It Works

SPDM (Security Protocol and Data Model) establishes an authenticated encrypted
channel over the existing SPI/I2C bus. Once active, every TPM command is
automatically encrypted — no application code changes needed.

### Protocol Flow

```
Host                                TPM (Nuvoton NPCT75x)
  |                                    |
  |--- GET_VERSION ------------------>|  (negotiate SPDM version)
  |<-- VERSION -----------------------|
  |                                    |
  |--- GET_PUB_KEY ------------------>|  (get TPM's P-384 identity key)
  |<-- PUB_KEY_RSP -------------------|
  |                                    |
  |--- KEY_EXCHANGE ----------------->|  (ECDHE P-384 key agreement)
  |<-- KEY_EXCHANGE_RSP --------------|  (+ HMAC proof of shared secret)
  |                                    |
  |    --- Handshake keys derived ---  |
  |                                    |
  |=== GIVE_PUB_KEY ================>|  (encrypted: host's P-384 key)
  |<== GIVE_PUB_KEY_RSP =============|
  |                                    |
  |=== FINISH ========================>|  (encrypted: signature + HMAC)
  |<== FINISH_RSP ====================|
  |                                    |
  |    --- App data keys derived ---   |
  |                                    |
  |=== TPM2_CMD (AES-256-GCM) ======>|  (every command encrypted)
  |<== TPM2_RSP (AES-256-GCM) =======|
```

The handshake uses ECDH P-384 for key agreement and HMAC-SHA384 for
authentication. After the handshake, all TPM commands are wrapped in SPDM
`VENDOR_DEFINED_REQUEST("TPM2_CMD")` messages and encrypted with AES-256-GCM.
A sequence number increments with each message to prevent replay attacks.

### Command Flow

The typical usage flow for SPDM-only mode:

```
1. Enable SPDM       (one-time, persists across resets)
2. Connect            (ECDH handshake, derives session keys)
3. Lock SPDM-only     (TPM rejects all cleartext commands)
4. GPIO reset         (TPM enters SPDM-only enforcement)
5. Run any commands   (each auto-establishes SPDM, all AES-256-GCM encrypted)
6. Unlock             (connect + unlock in one session)
7. GPIO reset         (TPM back to normal cleartext mode)
```

Step 5 is fully automatic. When wolfTPM detects SPDM-only mode (TPM2_Startup
returns `TPM_RC_DISABLED`), it transparently establishes an SPDM session.
Existing applications like `caps`, `wrap_test`, and `unit.test` work without
modification — all commands are encrypted over the bus.

## Building

### Prerequisites

wolfSSL with the crypto algorithms required for SPDM Algorithm Set B:

```bash
cd wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp
make
sudo make install
sudo ldconfig
```

The `--enable-sp` flag enables Single Precision math with optimized ECC P-384
support. For a broader feature set, `--enable-all` can be used instead.

### wolfTPM with Nuvoton SPDM

```bash
cd wolfTPM
./autogen.sh
./configure --enable-spdm --enable-nuvoton
make
```

### Configure Options

| Option | Description |
|---|---|
| `--enable-spdm` | Enable SPDM support (required) |
| `--enable-nuvoton` | Enable Nuvoton TPM hardware support |
| `--enable-debug` | Debug output with verbose SPDM tracing |
| `--enable-spdm-dynamic-mem` | Heap-allocated SPDM context (default: static ~32 KB) |

## Nuvoton NPCT75x Usage

### One-Time Setup

```bash
# Enable SPDM on the TPM (persists across resets)
./examples/spdm/spdm_demo --enable

# GPIO reset to apply
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2

# Verify SPDM is enabled
./examples/spdm/spdm_demo --status
```

### Lock SPDM-Only Mode

```bash
# Establish session and lock
./examples/spdm/spdm_demo --connect --lock

# GPIO reset — TPM now requires SPDM for all commands
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2

# All commands are now automatically encrypted:
./examples/wrap/caps          # auto-SPDM session, all AES-256-GCM
./tests/unit.test             # full test suite over encrypted bus
```

### Unlock SPDM-Only Mode

```bash
# GPIO reset + unlock (auto-connects since TPM is in SPDM-only mode)
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
./examples/spdm/spdm_demo --connect --unlock

# GPIO reset — TPM back to normal
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2

# Verify cleartext works
./examples/wrap/caps
```

### Running the Test Suite

```bash
# Run all Nuvoton SPDM tests (status, connect, lock, unit test, unlock, caps)
./examples/spdm/spdm_test.sh
```

### Demo Options

| Option | Description |
|--------|-------------|
| `--enable` | Enable SPDM on Nuvoton TPM (one-time) |
| `--disable` | Disable SPDM on Nuvoton TPM |
| `--status` | Query SPDM status from TPM |
| `--get-pubkey` | Get TPM's SPDM-Identity public key |
| `--connect` | Establish SPDM session |
| `--lock` | Lock SPDM-only mode (use with `--connect`) |
| `--unlock` | Unlock SPDM-only mode (use with `--connect`) |

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

**Dynamic (`--enable-spdm-dynamic-mem`):** Context is heap-allocated.
Useful on platforms with small stacks.

## wolfSPDM API

| Function | Description |
|---|---|
| `wolfSPDM_InitStatic()` | Initialize context in caller-provided buffer (static mode) |
| `wolfSPDM_New()` | Allocate and initialize context on heap (dynamic mode) |
| `wolfSPDM_Init()` | Initialize a pre-allocated context |
| `wolfSPDM_Free()` | Free context (releases resources; frees heap only if dynamic) |
| `wolfSPDM_GetCtxSize()` | Return `sizeof(WOLFSPDM_CTX)` at runtime |
| `wolfSPDM_SetIO()` | Set transport I/O callback |
| `wolfSPDM_SetDebug()` | Enable/disable debug output |
| `wolfSPDM_Connect()` | Full SPDM handshake |
| `wolfSPDM_IsConnected()` | Check session status |
| `wolfSPDM_Disconnect()` | End session |
| `wolfSPDM_SecuredExchange()` | Encrypt/send/receive/decrypt in one call |

## Troubleshooting

### TPM returns TPM_RC_DISABLED (0x120)

The TPM is in SPDM-only mode. Either establish an SPDM session first,
or unlock SPDM-only mode:

```bash
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
./examples/spdm/spdm_demo --connect --unlock
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

### SPDM handshake fails after interrupted session

GPIO reset clears stale SPDM state on the TPM:

```bash
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

If GPIO is not wired, a full power cycle is required.

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
