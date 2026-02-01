# wolfTPM SPDM Support

wolfTPM supports SPDM (Security Protocol and Data Model) for establishing authenticated and encrypted communication channels with TPMs that support the SPDM protocol.

## Overview

SPDM is defined by DMTF specification DSP0274. It provides:
- Device authentication using certificates
- Secure session establishment with key exchange
- Encrypted and authenticated messaging

wolfTPM's SPDM implementation supports:
- Nuvoton TPMs with SPDM AC (Authenticated Channel) support
- Standard SPDM protocol flow for testing with emulators

## Building wolfTPM with SPDM Support

### Prerequisites

wolfSSL must be built with all cryptographic algorithms needed for SPDM:

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-all
make && sudo make install && sudo ldconfig
```

**Note:** The `--enable-all` flag is required because SPDM uses:
- P-384 (secp384r1) for ECDSA signatures and ECDH key exchange
- SHA-384 for hashing
- HKDF for key derivation

### Building wolfTPM

```bash
cd wolfTPM
./autogen.sh
./configure --enable-debug --enable-spdm
make
```

For Nuvoton TPM hardware:
```bash
./configure --enable-debug --enable-nuvoton --enable-spdm
```

## Testing with libspdm Emulator (spdm-emu)

For testing standard SPDM protocol flow without hardware, use the DMTF libspdm emulator.

### Building spdm-emu

```bash
# Clone the repository
git clone https://github.com/DMTF/spdm-emu.git
cd spdm-emu

# Build with mbedtls crypto backend
mkdir build && cd build

# For x86_64:
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls ..

# For ARM64 (Raspberry Pi, etc.):
cmake -DARCH=arm64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls ..

# Build
make copy_sample_key
make -j4
```

### Starting the SPDM Responder Emulator

The wolfTPM SPDM demo uses MCTP transport which is the default for spdm_responder_emu.

```bash
cd spdm-emu/build/bin

# Default mode (MCTP transport on port 2323) - use this for wolfTPM
./spdm_responder_emu

# With specific SPDM version
./spdm_responder_emu --ver 1.2

# With specific algorithms
./spdm_responder_emu --ver 1.2 --hash SHA_256,SHA_384 --asym ECDSA_P256,ECDSA_P384

# With DHE and AEAD options
./spdm_responder_emu --ver 1.2 --dhe SECP_256_R1,SECP_384_R1 --aead AES_128_GCM,AES_256_GCM
```

### Common Emulator Options

| Option | Values | Description |
|--------|--------|-------------|
| `--trans` | MCTP, TCP | Transport type (default: MCTP on port 2323) |
| `--ver` | 1.0, 1.1, 1.2, 1.3, 1.4 | SPDM version |
| `--hash` | SHA_256, SHA_384, SHA_512 | Hash algorithms |
| `--asym` | ECDSA_P256, ECDSA_P384, RSASSA_2048 | Asymmetric algorithms |
| `--dhe` | SECP_256_R1, SECP_384_R1 | DHE named groups |
| `--aead` | AES_128_GCM, AES_256_GCM | AEAD cipher suites |

Multiple values can be specified with commas: `--hash SHA_256,SHA_384`

### Running wolfTPM SPDM Demo

The `--standard` mode connects to the libspdm emulator using TCP sockets and performs a complete SPDM 1.2 handshake with session establishment.

```bash
# Terminal 1: Start the emulator (uses MCTP transport on port 2323 by default)
cd spdm-emu/build/bin
./spdm_responder_emu

# Terminal 2: Run wolfTPM SPDM demo in standard mode
cd wolfTPM
./examples/spdm/spdm_demo --standard

# With specific host/port (for remote emulator)
./examples/spdm/spdm_demo --standard --host 192.168.1.100 --port 2323
```

### Demo Options

| Option | Description |
|--------|-------------|
| `--standard` | Connect to libspdm emulator for testing (requires spdm_responder_emu) |
| `--nuvoton` | Connect to Nuvoton TPM with SPDM AC support (default, requires hardware) |
| `--host <ip>` | Emulator host IP address (default: 127.0.0.1) |
| `--port <num>` | Emulator port number (default: 2323) |
| `-h, --help` | Show help message |

### SPDM Protocol Flow

The `--standard` demo performs the complete SPDM 1.2 handshake:

1. **GET_VERSION / VERSION** - Negotiate SPDM protocol version (uses v1.0 for this message)
2. **GET_CAPABILITIES / CAPABILITIES** - Exchange capability flags (encryption, key exchange, etc.)
3. **NEGOTIATE_ALGORITHMS / ALGORITHMS** - Negotiate crypto: SHA-384, ECDSA P-384, ECDH P-384, AES-256-GCM
4. **GET_DIGESTS / DIGESTS** - Get certificate chain digests for available slots
5. **GET_CERTIFICATE / CERTIFICATE** - Retrieve full certificate chain (may require multiple requests)
6. **KEY_EXCHANGE / KEY_EXCHANGE_RSP** - ECDH key exchange with signature verification
7. **FINISH / FINISH_RSP** - Complete handshake with encrypted HMAC verification

A successful run shows:
```
=== Standard SPDM Test (TCP to libspdm emulator) ===
This demo implements FULL transcript tracking for SPDM 1.2
Connecting to 127.0.0.1:2323...
TCP: Connected to 127.0.0.1:2323

--- Step 1: GET_VERSION ---
SUCCESS: Received VERSION response (16 bytes)

--- Step 2: GET_CAPABILITIES ---
SUCCESS: Received CAPABILITIES response (20 bytes)

--- Step 3: NEGOTIATE_ALGORITHMS ---
SUCCESS: Received ALGORITHMS response (52 bytes)

--- Step 4: GET_DIGESTS ---
SUCCESS: Received DIGESTS response (148 bytes)

--- Step 5: GET_CERTIFICATE (full chain) ---
SUCCESS: Retrieved full certificate chain (1591 bytes)

--- Step 6: KEY_EXCHANGE ---
SUCCESS: Received KEY_EXCHANGE_RSP (294 bytes)
*** ResponderVerifyData VERIFIED! ***

--- Step 7: FINISH ---
╔══════════════════════════════════════════════════════════════╗
║     SUCCESS: SPDM SESSION ESTABLISHED (VERIFIED!)           ║
╚══════════════════════════════════════════════════════════════╝
```

### Quick Start

```bash
# 1. Start the emulator (in first terminal)
cd ~/spdm-emu/build/bin && ./spdm_responder_emu

# 2. Run the demo (in second terminal)
cd ~/wolfTPM && ./examples/spdm/spdm_demo --standard
```

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

### SPDM message errors

- **Error 0x01 (InvalidRequest)**: Message format incorrect or missing required fields
- **Error 0x04 (UnexpectedRequest)**: Message sent out of sequence
- **Error 0x41 (VersionMismatch)**: SPDM version in message doesn't match negotiated version

## SPDM vs SWTPM

| Feature | SWTPM | spdm-emu |
|---------|-------|----------|
| Purpose | TPM 2.0 command emulation | SPDM protocol testing |
| Default Port | 2321 | 2323 |
| Configure Option | `--enable-swtpm` | `--enable-spdm` |
| Protocol | TPM 2.0 commands | SPDM (DSP0274) |

Both can be used independently for different testing purposes.
