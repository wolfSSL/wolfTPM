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

```bash
cd spdm-emu/build/bin

# Default mode (MCTP transport on port 2323)
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

```bash
# Terminal 1: Start emulator
cd spdm-emu/build/bin
./spdm_responder_emu

# Terminal 2: Run wolfTPM SPDM demo
cd wolfTPM
./examples/spdm/spdm_demo --standard

# With specific host/port
./examples/spdm/spdm_demo --standard --host 192.168.1.100 --port 2323
```

### SPDM Protocol Flow

The demo tests the following SPDM messages:

1. **GET_VERSION** - Negotiate SPDM protocol version
2. **GET_CAPABILITIES** - Exchange capability flags
3. **NEGOTIATE_ALGORITHMS** - Negotiate cryptographic algorithms

A successful run shows:
```
SUCCESS: Received VERSION response!
SUCCESS: Received CAPABILITIES response!
SUCCESS: Received ALGORITHMS response!
```

## Troubleshooting

### Bind error 0x62 (EADDRINUSE)

Port still in use from previous run. Kill old processes and wait for socket cleanup:

```bash
pkill -9 spdm_responder
sleep 30  # Wait for socket TIME_WAIT to expire
./spdm_responder_emu
```

### Connection refused

Emulator not running or wrong port:

```bash
# Check if emulator is listening
netstat -tlnp | grep 2323
# or
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
