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

For Nuvoton NPCT75x TPMs with SPDM AC support (Firmware 7.2+):

```bash
# Enable SPDM on the TPM
./examples/spdm/spdm_demo --enable

# Query SPDM status
./examples/spdm/spdm_demo --status

# Get TPM's SPDM-Identity public key
./examples/spdm/spdm_demo --get-pubkey

# Establish SPDM session
./examples/spdm/spdm_demo --connect

# Run full demo sequence
./examples/spdm/spdm_demo --all
```

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
| `--lock` | Lock SPDM-only mode |
| `--unlock` | Unlock SPDM-only mode |
| `--all` | Run full Nuvoton demo sequence |
| `-h, --help` | Show help message |

## SPDM Protocol Flow

The SPDM 1.2 handshake performs:

1. **GET_VERSION / VERSION** - Negotiate SPDM protocol version
2. **GET_CAPABILITIES / CAPABILITIES** - Exchange capability flags
3. **NEGOTIATE_ALGORITHMS / ALGORITHMS** - Negotiate crypto algorithms
4. **GET_DIGESTS / DIGESTS** - Get certificate chain digests
5. **GET_CERTIFICATE / CERTIFICATE** - Retrieve certificate chain
6. **KEY_EXCHANGE / KEY_EXCHANGE_RSP** - ECDH key exchange with signature
7. **FINISH / FINISH_RSP** - Complete handshake (encrypted)

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

### SPDM Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x01 | InvalidRequest | Message format incorrect |
| 0x04 | UnexpectedRequest | Message out of sequence |
| 0x05 | Unspecified | General error |
| 0x41 | VersionMismatch | SPDM version mismatch |
