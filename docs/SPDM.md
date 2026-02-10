# wolfTPM SPDM Support

wolfTPM supports SPDM (Security Protocol and Data Model) for establishing authenticated and encrypted communication channels. SPDM is defined by DMTF specification DSP0274.

## Overview

SPDM provides:
- Device authentication using certificates
- Secure session establishment with key exchange (ECDHE P-384)
- Encrypted and authenticated messaging (AES-256-GCM)

wolfTPM's SPDM implementation supports:
- **Emulator Mode**: Testing with libspdm responder emulator via TCP
- **Nuvoton Hardware Mode**: Nuvoton TPMs with SPDM AC (Authenticated Channel) support

## Building wolfTPM with SPDM Support

### Prerequisites

1. **wolfSSL** with cryptographic algorithms needed for SPDM:

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-all
make && sudo make install && sudo ldconfig
```

**Note:** The `--enable-all` flag is required because SPDM Algorithm Set B uses:
- P-384 (secp384r1) for ECDSA signatures and ECDH key exchange
- SHA-384 for hashing
- HKDF for key derivation
- AES-256-GCM for authenticated encryption

2. **wolfSPDM** library (for emulator testing):

```bash
git clone https://github.com/wolfSSL/wolfspdm.git
cd wolfspdm
./autogen.sh
./configure
make
```

### Building wolfTPM

For **emulator testing** (libspdm responder):
```bash
cd wolfTPM
./autogen.sh
./configure --enable-spdm --with-wolfspdm=/path/to/wolfspdm
make
```

For **Nuvoton TPM hardware**:
```bash
./configure --enable-spdm --enable-nuvoton
make
```

## Emulator Mode (--emu)

For testing SPDM protocol flow without hardware, use the DMTF libspdm emulator.

### Building spdm-emu

```bash
git clone https://github.com/DMTF/spdm-emu.git
cd spdm-emu
mkdir build && cd build

# For x86_64:
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls ..

# For ARM64 (Raspberry Pi, etc.):
cmake -DARCH=arm64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls ..

make copy_sample_key
make -j4
```

### Running the Test

```bash
# Terminal 1: Start the emulator (from spdm-emu/build/bin directory)
cd spdm-emu/build/bin
./spdm_responder_emu --ver 1.2

# Terminal 2: Run wolfTPM SPDM demo
cd wolfTPM
./examples/spdm/spdm_demo --emu

# With specific host/port:
./examples/spdm/spdm_demo --emu --host 192.168.1.100 --port 2323
```

### Expected Output

A successful run shows:
```
=== SPDM Emulator Test (wolfSPDM -> libspdm) ===
Connecting to 127.0.0.1:2323...

Establishing SPDM session...
[wolfSPDM] Step 1: GET_VERSION
[wolfSPDM] Negotiated SPDM version: 0x12
[wolfSPDM] Step 2: GET_CAPABILITIES
[wolfSPDM] Responder caps: 0x001afbf7
[wolfSPDM] Step 3: NEGOTIATE_ALGORITHMS
[wolfSPDM] Step 4: GET_DIGESTS
[wolfSPDM] Step 5: GET_CERTIFICATE
[wolfSPDM] Step 6: KEY_EXCHANGE
[wolfSPDM] ResponderVerifyData VERIFIED
[wolfSPDM] Step 7: FINISH
[wolfSPDM] FINISH_RSP received - session established

=============================================
 SUCCESS: SPDM Session Established!
 Session ID: 0xffffffff
 SPDM Version: 0x12
=============================================
```

## Nuvoton Hardware Mode

For Nuvoton NPCT75x TPMs with SPDM AC support (Firmware 7.2+).

### Building for Nuvoton Hardware

wolfTPM with Nuvoton SPDM requires both wolfSSL and wolfSPDM:

```bash
# 1. Build and install wolfSSL (--enable-all required for P-384/HKDF/AES-GCM)
cd wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-all
make && sudo make install && sudo ldconfig

# 2. Build and install wolfSPDM
cd wolfspdm
./autogen.sh
./configure
make && sudo make install && sudo ldconfig

# 3. Build wolfTPM with Nuvoton SPDM support
cd wolfTPM
./autogen.sh
./configure --enable-debug --enable-nuvoton --enable-spdm --with-wolfspdm=/path/to/wolfspdm
make
```

**Important:** After making changes to wolfSPDM, you must reinstall the library
(`sudo make install && sudo ldconfig`) so wolfTPM links against the updated version.
Alternatively, use `LD_LIBRARY_PATH` to point to the local build:

```bash
LD_LIBRARY_PATH=/path/to/wolfspdm/.libs ./examples/spdm/spdm_demo --status
```

### Verifying TPM State

Before running SPDM commands, verify the TPM is in a clean state:

```bash
./examples/wrap/caps
```

A healthy TPM shows `TPM2_Startup pass`. If you see `TPM_RC_DISABLED`, the TPM is
stuck in SPDM-only mode (see [TPM Recovery](#tpm-recovery-from-spdm-only-mode) below).

### Running Nuvoton SPDM Demo

```bash
# Step 1: Enable SPDM on the TPM (only needed once, persists across resets)
./examples/spdm/spdm_demo --enable

# Step 2: Reset the TPM (required after --enable for NTC2_PreConfig to take effect)
#         Use GPIO reset or power cycle (see TPM Recovery section)

# Step 3: Verify SPDM status
./examples/spdm/spdm_demo --status

# Step 4: Get TPM's SPDM-Identity public key
./examples/spdm/spdm_demo --get-pubkey

# Step 5: Establish SPDM session
./examples/spdm/spdm_demo --connect

# Or run the full demo sequence (steps 1-5 combined)
./examples/spdm/spdm_demo --all
```

### SPDM-Only Provisioning Flow

The full SPDM-only provisioning flow locks the TPM so all communication
is encrypted. After provisioning, all TPM commands are automatically routed
through the SPDM secure channel using AES-256-GCM encryption.

**Step 1: Enable SPDM (one-time)**
```bash
./examples/spdm/spdm_demo --enable
# Reset TPM for NTC2_PreConfig to take effect:
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

**Step 2: Establish session and lock SPDM-only mode**
```bash
./examples/spdm/spdm_demo --connect --lock
```
This performs the full SPDM handshake (GET_VERSION, GET_PUB_KEY, KEY_EXCHANGE,
GIVE_PUB_KEY, FINISH) and then sends the SPDM_ONLY(LOCK=YES) vendor command.
After locking, the TPM will only accept commands over SPDM.

**Step 3: Reset the TPM**
```bash
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```
After reset with SPDM-only locked, the TPM requires a new SPDM session before
it will accept any TPM commands (except GetCapability and GetTestResult which
are excluded from the SPDM-only restriction per Nuvoton spec).

**Step 4: Reconnect and run TPM commands over SPDM**
```bash
./examples/spdm/spdm_demo --connect --caps
```
This establishes a new SPDM session and then runs TPM2_Startup and
wolfTPM2_GetCapabilities over the encrypted channel. All TPM commands
are automatically wrapped in SPDM VENDOR_DEFINED("TPM2_CMD") messages
and encrypted with AES-256-GCM.

Expected output:
```
  SUCCESS: SPDM session established!
  TPM2_Startup: PASS
  Mfg 0x4 (NTC), Vendor NPCT75x, Fw 7.2 (0x50001)
  SUCCESS: TPM commands working over SPDM encrypted channel!
```

**Step 5: Unlock (when needed)**
```bash
# Reset and reconnect first
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
./examples/spdm/spdm_demo --connect --unlock
```

### How TPM Commands Work Over SPDM

When an SPDM session is active, wolfTPM automatically intercepts all TPM
commands and routes them through the SPDM encrypted channel. The process is:

1. Application calls a wolfTPM API (e.g., `wolfTPM2_GetCapabilities()`)
2. wolfTPM serializes the TPM command packet
3. The SPDM transport layer wraps the TPM command in an SPDM
   VENDOR_DEFINED_REQUEST message with the "TPM2_CMD" vendor code
4. wolfSPDM encrypts the message using AES-256-GCM with the session keys
5. The encrypted record is wrapped in a TCG binding header (tag 0x8201)
   and sent to the TPM via SPI
6. The TPM's SPDM layer decrypts the record, extracts the TPM command,
   and executes it
7. The TPM response is encrypted and sent back through the same path
8. wolfTPM receives the decrypted TPM response transparently

This is completely transparent to the application. Any wolfTPM API call
works identically whether SPDM is active or not.

### Nuvoton SPDM Protocol Flow

The Nuvoton NPCT75x uses a simplified SPDM flow compared to standard SPDM:

```
GET_VERSION          (cleartext, SPDM 1.0 request)
  VERSION            (cleartext, negotiates SPDM 1.3)
GET_PUB_KEY          (cleartext, Nuvoton vendor-defined)
  PUB_KEY_RSP        (cleartext, returns TPM's P-384 public key)
KEY_EXCHANGE         (cleartext, ECDHE P-384 key agreement)
  KEY_EXCHANGE_RSP   (cleartext, includes ResponderVerifyData HMAC)
  --- Session keys derived (handshake phase) ---
GIVE_PUB_KEY         (encrypted, sends host's P-384 public key)
  GIVE_PUB_KEY_RSP   (encrypted)
FINISH               (encrypted, includes signature + RequesterVerifyData)
  FINISH_RSP         (encrypted)
  --- App data keys derived (application phase) ---
SPDM_ONLY/TPM2_CMD  (encrypted, application data)
```

Notable differences from standard SPDM 1.2:
- No GET_CAPABILITIES or NEGOTIATE_ALGORITHMS (Algorithm Set B is fixed)
- Vendor-defined commands for identity key exchange (GET_PUB_KEY, GIVE_PUB_KEY)
- Mutual authentication is mandatory
- VCA (Version/Capabilities/Algorithms transcript) = GET_VERSION + VERSION only

### TPM Recovery from SPDM-Only Mode

If an SPDM session fails mid-handshake (e.g., during GIVE_PUB_KEY or FINISH), the
Nuvoton TPM can enter SPDM-only mode with a stale session. In this state, all
standard TPM commands return `TPM_RC_DISABLED (0x120)`.

**Symptoms:**
```
TPM2_Startup: TPM_RC_DISABLED (SPDM-only mode active, this is expected)
TPM2_Shutdown failed 0x120: TPM_RC_DISABLED
```

**Recovery via GPIO4 hardware reset** (Raspberry Pi with GPIO4 wired to TPM reset):
```bash
# Toggle GPIO4 low for 100ms then high to reset the TPM
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1
sleep 2  # Wait for TPM to reinitialize

# Verify clean state
./examples/wrap/caps
# Should show: TPM2_Startup pass
```

**Recovery via power cycle:** If GPIO reset is not wired, a full power cycle of
the board (not just reboot) is required to reset the TPM.

**Note:** After recovery, SPDM remains enabled (NTC2_PreConfig is persistent) but
any active session is cleared. You can verify with `--status` and proceed with
`--connect` to establish a new session.

## Demo Options

| Option | Description |
|--------|-------------|
| `--emu` | Test SPDM with libspdm emulator (TCP) |
| `--host <ip>` | Emulator host IP (default: 127.0.0.1) |
| `--port <num>` | Emulator port (default: 2323) |
| `--enable` | Enable SPDM on Nuvoton TPM |
| `--status` | Query SPDM status from TPM |
| `--get-pubkey` | Get TPM's SPDM-Identity public key |
| `--connect` | Establish SPDM session with TPM |
| `--caps` | Run TPM commands over SPDM (Startup + GetCapabilities) |
| `--lock` | Lock SPDM-only mode |
| `--unlock` | Unlock SPDM-only mode |
| `--all` | Run full Nuvoton demo sequence |
| `-h, --help` | Show help message |

## SPDM Protocol Flow

### Standard SPDM 1.2 (Emulator Mode)

1. **GET_VERSION / VERSION** - Negotiate SPDM protocol version
2. **GET_CAPABILITIES / CAPABILITIES** - Exchange capability flags
3. **NEGOTIATE_ALGORITHMS / ALGORITHMS** - Negotiate crypto algorithms
4. **GET_DIGESTS / DIGESTS** - Get certificate chain digests
5. **GET_CERTIFICATE / CERTIFICATE** - Retrieve certificate chain
6. **KEY_EXCHANGE / KEY_EXCHANGE_RSP** - ECDH key exchange with signature
7. **FINISH / FINISH_RSP** - Complete handshake (encrypted)

### Nuvoton SPDM (Hardware Mode)

See [Nuvoton SPDM Protocol Flow](#nuvoton-spdm-protocol-flow) above for the
Nuvoton-specific flow which differs from standard SPDM.

## Troubleshooting

### Bind error 0x62 (EADDRINUSE)
Port still in use from previous run:
```bash
pkill -9 spdm_responder_emu
sleep 5
./spdm_responder_emu
```

### Connection refused
Check if emulator is listening:
```bash
ss -tlnp | grep 2323
```

### Certificate not found
Run emulator from the `spdm-emu/build/bin` directory so it can find the certificate files:
```bash
cd spdm-emu/build/bin
./spdm_responder_emu
```

### TPM_RC_DISABLED (0x120)

All TPM commands returning `TPM_RC_DISABLED` means the TPM is in SPDM-only mode
without an active session. This happens after a failed SPDM handshake. See
[TPM Recovery from SPDM-Only Mode](#tpm-recovery-from-spdm-only-mode) for
recovery steps.

### SPDM Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x01 | InvalidRequest | Message format incorrect |
| 0x04 | UnexpectedRequest | Message out of sequence |
| 0x05 | DecryptError | Decryption or MAC verification failed |
| 0x06 | UnsupportedRequest | Request not supported or format rejected |
| 0x41 | VersionMismatch | SPDM version mismatch |
