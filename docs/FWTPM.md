# wolfTPM fwTPM (fTPM / swtpm) -- Firmware TPM 2.0

## Overview

The wolfTPM fwTPM (industry terms: fTPM, swtpm-compatible) is a portable firmware TPM 2.0 implementation built entirely
on wolfCrypt cryptographic primitives. It provides a standards-compliant TPM 2.0
command processor as a standalone server process (`fwtpm_server`) implementing
105 of 113 commands from the TPM 2.0 v1.38 specification (93% coverage). The
fwTPM can replace a hardware TPM for:

- **Embedded/IoT platforms** without a discrete TPM chip (bare-metal via SPI/I2C TIS HAL)
- **Development and testing** of TPM-dependent applications (drop-in for swtpm or MS TPM simulator)
- **CI/CD pipelines** requiring TPM functionality (socket transport compatible with tpm2-tools)
- **Prototyping** TPM workflows before hardware is available

### Architecture

```
+---------------------+          +---------------------------+
| wolfTPM Client App  |          |  fwtpm_server             |
| (examples, tests)   |          |                           |
+----------+----------+          |  +---------------------+  |
           |                     |  | fwtpm_command.c      | |
     TCP (SWTPM protocol)        |  | (command processor)  | |
     or TIS shared memory        |  +----------+----------+  |
           |                     |             |             |
+----------v----------+          |  +----------v----------+  |
| Transport Layer     +--------->+  | wolfCrypt           |  |
| (socket or TIS HAL) |          |  | (RSA, ECC, SHA,     |  |
+---------------------+          |  |  HMAC, RNG, AES)    |  |
                                 |  +---------------------+  |
                                 |             |             |
                                 |  +----------v----------+  |
                                 |  | fwtpm_nv.c           | |
                                 |  | (persistent storage) | |
                                 |  +---------------------+  |
                                 +---------------------------+
```

**Components:**

| File | Role |
|------|------|
| `fwtpm_command.c` | TPM 2.0 command processor and dispatch table (~9500 lines) |
| `fwtpm_io.c` | Transport layer -- SWTPM TCP socket protocol (default) |
| `fwtpm_nv.c` | NV storage -- file-based (default), HAL-abstracted for embedded |
| `fwtpm_tis.c` | TIS register state machine (transport-agnostic) |
| `fwtpm_tis_shm.c` | POSIX shared memory + semaphore TIS transport |
| `fwtpm_main.c` | Server entry point, CLI argument parsing |
| `tpm2_util.c` | Shared utilities (hash helpers, ForceZero, PrintBin) |
| `tpm2_packet.c` | TPM packet marshaling/unmarshaling |
| `tpm2_param_enc.c` | Parameter encryption (XOR and AES session encryption) |


## Building

### Prerequisites

wolfSSL must be built with TPM support:

```sh
cd wolfssl
./configure --enable-wolftpm --enable-pkcallbacks
make
sudo make install
```

### Build fwTPM Server

**Socket transport (SWTPM protocol, default for development):**

```sh
cd wolftpm
./configure --enable-fwtpm --enable-swtpm
make
```

This produces `src/fwtpm/fwtpm_server` and builds the wolfTPM client library
with `WOLFTPM_SWTPM` for socket-based communication.

**TIS/shared-memory transport (for fwTPM HAL integration):**

```sh
./configure --enable-fwtpm
make
```

When `--enable-swtpm` is omitted, the build uses TIS shared-memory transport
(`WOLFTPM_FWTPM_HAL`, `WOLFTPM_ADV_IO`) and compiles `fwtpm_tis.c` into the
server.

**fwTPM server only (no client library or examples):**

```sh
./configure --enable-fwtpm-only --enable-swtpm
make
```

This builds only the `fwtpm_server` binary, skipping `libwolftpm`, examples,
and tests. Useful for embedded targets that only need the TPM server.

**Debug build:**

```sh
./configure --enable-fwtpm --enable-swtpm --enable-debug
make
```

### Build Output

| Artifact | Description |
|----------|-------------|
| `src/fwtpm/fwtpm_server` | Standalone fwTPM server binary |
| `src/.libs/libwolftpm.*` | wolfTPM client library |

### Key Build Flags

| Configure Option | Effect |
|-----------------|--------|
| `--enable-fwtpm` | Build `fwtpm_server` binary (alongside client library) |
| `--enable-fwtpm-only` | Build only `fwtpm_server` (no client library, examples, or tests) |
| `--enable-swtpm` | Use SWTPM TCP socket transport (ports 2321/2322) |
| `--enable-debug` | Enable debug logging |

| Compile Define | Set By |
|---------------|--------|
| `WOLFTPM_FWTPM` | Automatically set for `fwtpm_server` target only |
| `WOLFTPM_SWTPM` | `--enable-swtpm` |
| `WOLFTPM_FWTPM_HAL` | `--enable-fwtpm` without `--enable-swtpm` |
| `WOLFTPM_FWTPM_TIS` | `--enable-fwtpm` without `--enable-swtpm` |
| `WOLFTPM_ADV_IO` | Set with `WOLFTPM_FWTPM_HAL` |


## Usage

### Starting the Server

```sh
./src/fwtpm/fwtpm_server [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--help`, `-h` | Show usage information |
| `--version`, `-v` | Print version string |
| `--port <port>` | Command port (default: 2321) |
| `--platform-port <port>` | Platform port (default: 2322) |

**Example:**

```sh
# Start with default ports
./src/fwtpm/fwtpm_server

# Start on custom ports
./src/fwtpm/fwtpm_server --port 2331 --platform-port 2332
```

The server prints its configuration on startup:

```
wolfTPM fwTPM Server v0.1.0
  Command port:  2321
  Platform port: 2322
  Manufacturer:  WOLF
  Model:         fwTPM
```

### Connecting wolfTPM Clients

Any wolfTPM application built with `--enable-swtpm` connects to the fwTPM
server automatically via TCP:

```sh
# In one terminal: start the server
./src/fwtpm/fwtpm_server

# In another terminal: run wolfTPM examples
./examples/wrap/wrap_test
./examples/keygen/keygen keyblob.bin -rsa -t
./examples/attestation/make_credential
```

### NV Persistence

The server stores persistent state (hierarchy seeds, auth values, PCR state,
NV indices) in `fwtpm_nv.bin` (configurable via `FWTPM_NV_FILE`). On first
start, seeds are randomly generated and saved. Subsequent starts reload
existing state.


## Supported TPM 2.0 Commands

### Startup / Self-Test

| Command | Description |
|---------|-------------|
| `TPM2_Startup` | Initialize TPM (SU_CLEAR or SU_STATE) |
| `TPM2_Shutdown` | Save state and prepare for power-off |
| `TPM2_SelfTest` | Execute full self-test |
| `TPM2_IncrementalSelfTest` | Incremental algorithm self-test |
| `TPM2_GetTestResult` | Return self-test result |

### Random Number Generation

| Command | Description |
|---------|-------------|
| `TPM2_GetRandom` | Generate random bytes (max 48 per call) |
| `TPM2_StirRandom` | Add entropy to RNG state |

### Capability

| Command | Description |
|---------|-------------|
| `TPM2_GetCapability` | Query TPM properties, algorithms, handles |

### Key Management

| Command | Description |
|---------|-------------|
| `TPM2_CreatePrimary` | Create primary key under a hierarchy |
| `TPM2_Create` | Create child key under a parent |
| `TPM2_CreateLoaded` | Create and load key in one command |
| `TPM2_Load` | Load key from private/public parts |
| `TPM2_LoadExternal` | Load external (software) key |
| `TPM2_Import` | Import externally wrapped key |
| `TPM2_Duplicate` | Export key for transfer (inner/outer wrapping) |
| `TPM2_Rewrap` | Re-wrap key under new parent (placeholder) |
| `TPM2_FlushContext` | Unload a transient object or session |
| `TPM2_ContextSave` | Save object/session context |
| `TPM2_ContextLoad` | Restore saved context |
| `TPM2_ReadPublic` | Read public area of a loaded key |
| `TPM2_ObjectChangeAuth` | Change authorization of a key |
| `TPM2_EvictControl` | Make transient key persistent (or remove) |
| `TPM2_HierarchyControl` | Enable or disable a hierarchy |
| `TPM2_HierarchyChangeAuth` | Change hierarchy authorization value |
| `TPM2_Clear` | Clear hierarchy (Owner or Platform) |
| `TPM2_ChangePPS` | Replace platform primary seed |
| `TPM2_ChangeEPS` | Replace endorsement primary seed |

### Cryptographic Operations

| Command | Description |
|---------|-------------|
| `TPM2_Sign` | Sign digest with loaded key |
| `TPM2_VerifySignature` | Verify signature against loaded key |
| `TPM2_RSA_Encrypt` | RSA encryption (OAEP, PKCS1) |
| `TPM2_RSA_Decrypt` | RSA decryption |
| `TPM2_EncryptDecrypt` | Symmetric encrypt/decrypt |
| `TPM2_EncryptDecrypt2` | Symmetric encrypt/decrypt (alternate) |
| `TPM2_Hash` | Single-shot hash computation |
| `TPM2_HMAC` | Single-shot HMAC computation |
| `TPM2_ECDH_KeyGen` | Generate ephemeral ECC key pair |
| `TPM2_ECDH_ZGen` | Compute ECDH shared secret |
| `TPM2_ECC_Parameters` | Get ECC curve parameters |
| `TPM2_TestParms` | Validate algorithm parameter support |

### Hash Sequences

| Command | Description |
|---------|-------------|
| `TPM2_HashSequenceStart` | Start a hash sequence |
| `TPM2_HMAC_Start` | Start an HMAC sequence |
| `TPM2_SequenceUpdate` | Add data to a hash/HMAC sequence |
| `TPM2_SequenceComplete` | Finalize hash/HMAC sequence and get result |
| `TPM2_EventSequenceComplete` | Finalize hash sequence and extend PCR |

### Sealing

| Command | Description |
|---------|-------------|
| `TPM2_Unseal` | Unseal data from a sealed object |

### PCR (Platform Configuration Registers)

| Command | Description |
|---------|-------------|
| `TPM2_PCR_Read` | Read PCR values |
| `TPM2_PCR_Extend` | Extend a PCR with a digest |
| `TPM2_PCR_Reset` | Reset a resettable PCR |

### Clock

| Command | Description |
|---------|-------------|
| `TPM2_ReadClock` | Read TPM clock values |
| `TPM2_ClockSet` | Set TPM clock |

### Sessions and Authorization

| Command | Description |
|---------|-------------|
| `TPM2_StartAuthSession` | Create HMAC, policy, or trial session |

### Policy

| Command | Description |
|---------|-------------|
| `TPM2_PolicyGetDigest` | Get current policy session digest |
| `TPM2_PolicyRestart` | Reset policy session digest |
| `TPM2_PolicyPCR` | Bind policy to PCR values |
| `TPM2_PolicyPassword` | Include password in policy |
| `TPM2_PolicyAuthValue` | Include auth value in policy |
| `TPM2_PolicyCommandCode` | Restrict policy to specific command |
| `TPM2_PolicyOR` | Logical OR of policy branches |
| `TPM2_PolicySecret` | Authorization with secret |
| `TPM2_PolicyAuthorize` | Approve policy with signing key |
| `TPM2_PolicyNV` | Policy based on NV index comparison |
| `TPM2_PolicyLocality` | Restrict policy to specific locality |
| `TPM2_PolicySigned` | Authorize policy with external signing key |

### NV RAM

| Command | Description |
|---------|-------------|
| `TPM2_NV_DefineSpace` | Create an NV index |
| `TPM2_NV_UndefineSpace` | Delete an NV index |
| `TPM2_NV_ReadPublic` | Read NV index public metadata |
| `TPM2_NV_Write` | Write data to NV index |
| `TPM2_NV_Read` | Read data from NV index |
| `TPM2_NV_Extend` | Extend NV index (hash-extend) |
| `TPM2_NV_Increment` | Increment NV counter |
| `TPM2_NV_WriteLock` | Lock NV index for writes |
| `TPM2_NV_ReadLock` | Lock NV index for reads |
| `TPM2_NV_SetBits` | OR bits into NV bit field index |
| `TPM2_NV_ChangeAuth` | Change NV index authorization value |
| `TPM2_NV_Certify` | Certify NV index contents |

### Attestation and Credentials

| Command | Description |
|---------|-------------|
| `TPM2_Quote` | Generate signed PCR quote |
| `TPM2_Certify` | Certify a loaded key |
| `TPM2_CertifyCreation` | Prove key was created by this TPM |
| `TPM2_GetTime` | Signed attestation of TPM clock |
| `TPM2_MakeCredential` | Create credential blob for a key |
| `TPM2_ActivateCredential` | Unwrap credential blob |


## HAL Abstraction

The fwTPM provides two hardware abstraction layers (HALs) for porting to
embedded targets without modifying core logic.

### IO HAL (Transport)

The IO HAL abstracts the transport between the fwTPM server and its clients.
The default implementation uses TCP sockets (SWTPM protocol). For embedded
targets, replace with SPI, I2C, UART, or shared memory callbacks.

**Callback structure** (defined in `FWTPM_IO_HAL` in `fwtpm.h`):

| Callback | Signature | Description |
|----------|-----------|-------------|
| `send` | `int (*)(void* ctx, const void* buf, int sz)` | Send data to client |
| `recv` | `int (*)(void* ctx, void* buf, int sz)` | Receive data from client |
| `wait` | `int (*)(void* ctx)` | Wait for data/connections. Returns bitmask: `0x01`=command data, `0x02`=platform data, `0x04`=new command connection, `0x08`=new platform connection |
| `accept` | `int (*)(void* ctx, int type)` | Accept new connection (type: 0=command, 1=platform) |
| `close_conn` | `void (*)(void* ctx, int type)` | Close connection (type: 0=command, 1=platform) |
| `ctx` | `void*` | User context pointer |

**Registration:**

```c
FWTPM_IO_HAL myHal;
myHal.send = my_send;
myHal.recv = my_recv;
myHal.wait = my_wait;
myHal.accept = my_accept;
myHal.close_conn = my_close;
myHal.ctx = &myTransportCtx;

FWTPM_IO_SetHAL(&ctx, &myHal);
```

### NV HAL (Persistent Storage)

The NV HAL abstracts persistent storage. The default implementation uses a
local file (`fwtpm_nv.bin`). For embedded targets, replace with flash, EEPROM,
or other non-volatile storage callbacks.

**Callback structure** (defined in `FWTPM_NV_HAL` in `fwtpm.h`):

| Callback | Signature | Description |
|----------|-----------|-------------|
| `read` | `int (*)(void* ctx, word32 offset, byte* buf, word32 size)` | Read from NV at offset |
| `write` | `int (*)(void* ctx, word32 offset, const byte* buf, word32 size)` | Write to NV at offset |
| `ctx` | `void*` | User context pointer |

**Registration:**

```c
FWTPM_NV_HAL myNvHal;
myNvHal.read = my_flash_read;
myNvHal.write = my_flash_write;
myNvHal.ctx = &myFlashCtx;

FWTPM_NV_SetHAL(&ctx, &myNvHal);
```

### Porting Example

For a bare-metal embedded target with SPI transport and SPI flash NV:

```c
FWTPM_CTX ctx;
FWTPM_Init(&ctx);

/* Set custom IO transport */
FWTPM_IO_HAL ioHal = {
    .send = spi_slave_send,
    .recv = spi_slave_recv,
    .wait = spi_slave_poll,
    .accept = NULL,         /* not connection-oriented */
    .close_conn = NULL,
    .ctx = &spiHandle
};
FWTPM_IO_SetHAL(&ctx, &ioHal);

/* Set custom NV storage */
FWTPM_NV_HAL nvHal = {
    .read = spi_flash_read,
    .write = spi_flash_write,
    .ctx = &flashHandle
};
FWTPM_NV_SetHAL(&ctx, &nvHal);

/* Initialize IO and run */
FWTPM_IO_Init(&ctx);
FWTPM_IO_ServerLoop(&ctx);  /* blocks */

FWTPM_IO_Cleanup(&ctx);
FWTPM_Cleanup(&ctx);
```


## Configuration Macros

All macros are compile-time overridable (e.g., `-DFWTPM_MAX_OBJECTS=8`).

| Macro | Default | Description |
|-------|---------|-------------|
| `FWTPM_MAX_COMMAND_SIZE` | 4096 | Maximum command/response buffer size (bytes) |
| `FWTPM_MAX_RANDOM_BYTES` | 48 | Maximum bytes per `GetRandom` call |
| `FWTPM_MAX_OBJECTS` | 16 | Maximum concurrently loaded transient objects |
| `FWTPM_MAX_PERSISTENT` | 8 | Maximum persistent objects (via `EvictControl`) |
| `FWTPM_MAX_PRIVKEY_DER` | 2048 | Maximum DER-encoded private key size (bytes) |
| `FWTPM_MAX_HASH_SEQ` | 4 | Maximum concurrent hash/HMAC sequences |
| `FWTPM_MAX_PRIMARY_CACHE` | 16 | Cached primary keys per hierarchy+template |
| `FWTPM_MAX_SESSIONS` | 8 | Maximum concurrent auth sessions |
| `FWTPM_MAX_NV_INDICES` | 16 | Maximum NV RAM index slots |
| `FWTPM_MAX_NV_DATA` | 2048 | Maximum data per NV index (bytes) |
| `FWTPM_MAX_DATA_BUF` | 1024 | Internal buffer for HMAC, hash, general data |
| `FWTPM_MAX_PUB_BUF` | 512 | Internal buffer for public area, signatures |
| `FWTPM_MAX_DER_SIG_BUF` | 256 | Internal buffer for DER signatures, ECC points |
| `FWTPM_MAX_ATTEST_BUF` | 1024 | Internal buffer for attestation marshaling |
| `FWTPM_CMD_PORT` | 2321 | Default TCP command port |
| `FWTPM_PLAT_PORT` | 2322 | Default TCP platform port |
| `FWTPM_NV_FILE` | `"fwtpm_nv.bin"` | Default NV storage file path |
| `FWTPM_PCR_BANKS` | 2 | Number of PCR banks (SHA-256 + SHA-384) |
| `FWTPM_TIS_BURST_COUNT` | 64 | TIS FIFO burst count (bytes per transfer) |
| `FWTPM_TIS_FIFO_SIZE` | 4096 | TIS command/response FIFO size |

### Stack/Heap Control

| Macro | Effect |
|-------|--------|
| `WOLFTPM_SMALL_STACK` | Use heap allocation for large stack objects |
| `WOLFTPM2_NO_HEAP` | Forbid heap allocation (all stack) |

Note: `WOLFTPM_SMALL_STACK` and `WOLFTPM2_NO_HEAP` are mutually exclusive and
will produce a compile error if both are defined.

### Algorithm Feature Macros

These macros use wolfCrypt's existing compile-time options to control which
cryptographic algorithms are available in fwtpm_server. If an algorithm is
disabled, the corresponding TPM commands are excluded from the build.

| Macro | Default | Effect |
|-------|---------|--------|
| `NO_RSA` | not defined | Excludes RSA keygen, sign, verify, `RSA_Encrypt`, `RSA_Decrypt` |
| `HAVE_ECC` | defined | Enables ECC keygen, sign, verify, `ECDH_KeyGen`, `ECDH_ZGen`, `ECC_Parameters` |
| `HAVE_ECC384` | defined | Enables P-384 curve support |
| `HAVE_ECC521` | defined | Enables P-521 curve support |
| `NO_AES` | not defined | Excludes `EncryptDecrypt`, `EncryptDecrypt2`, AES parameter encryption |
| `WOLFSSL_SHA384` | defined | Enables SHA-384 PCR bank |

When an algorithm is disabled, commands that exclusively use that algorithm
are removed from the dispatch table at compile time. Commands that support
multiple algorithms (e.g., `CreatePrimary`, `Sign`) remain available but
return `TPM_RC_ASYMMETRIC` for the disabled algorithm type.

### TPM Feature Group Macros

These fwTPM-specific macros disable entire groups of TPM 2.0 functionality
to reduce code size on constrained targets.

| Macro | Default | Commands Excluded |
|-------|---------|-------------------|
| `FWTPM_NO_ATTESTATION` | not defined | `Quote`, `Certify`, `CertifyCreation`, `GetTime`, `NV_Certify` |
| `FWTPM_NO_NV` | not defined | `NV_DefineSpace`, `NV_UndefineSpace`, `NV_ReadPublic`, `NV_Write`, `NV_Read`, `NV_Extend`, `NV_Increment`, `NV_WriteLock`, `NV_ReadLock`, `NV_Certify` |
| `FWTPM_NO_POLICY` | not defined | `PolicyGetDigest`, `PolicyRestart`, `PolicyPCR`, `PolicyPassword`, `PolicyAuthValue`, `PolicyCommandCode`, `PolicyOR`, `PolicySecret`, `PolicyAuthorize`, `PolicyNV` |
| `FWTPM_NO_CREDENTIAL` | not defined | `MakeCredential`, `ActivateCredential` |

**Minimal build example** (measured boot only):

```sh
./configure --enable-fwtpm --enable-swtpm \
    CFLAGS="-DNO_RSA -DFWTPM_NO_NV -DFWTPM_NO_ATTESTATION \
            -DFWTPM_NO_POLICY -DFWTPM_NO_CREDENTIAL"
```

This retains only: `Startup`, `Shutdown`, `SelfTest`, `GetRandom`, `GetCapability`,
`PCR_Read`, `PCR_Extend`, `PCR_Reset`, `Hash`, ECC keygen/sign, and session support.

**Dependencies:**
- `FWTPM_NO_NV` also removes `NV_Certify` (even if `FWTPM_NO_ATTESTATION` is not set)
- `NO_RSA` implies no RSA attestation signatures (ECC-only attestation still works with `HAVE_ECC`)


## Transport Modes

### Socket / SWTPM (Default)

Built with `--enable-fwtpm --enable-swtpm`. The server listens on two TCP
ports using the SWTPM wire protocol:

- **Command port** (default 2321): TPM command/response traffic
- **Platform port** (default 2322): Platform signals (power on/off, NV on, cancel, reset, session end, stop)

**SWTPM TCP protocol commands** (platform port):

| Signal | Value | Description |
|--------|-------|-------------|
| `SIGNAL_POWER_ON` | 1 | Power on the TPM |
| `SIGNAL_POWER_OFF` | 2 | Power off the TPM |
| `SIGNAL_PHYS_PRES_ON` | 3 | Assert physical presence |
| `SIGNAL_PHYS_PRES_OFF` | 4 | Deassert physical presence |
| `SIGNAL_HASH_START` | 5 | Start measured boot hash |
| `SIGNAL_HASH_DATA` | 6 | Provide measured boot data |
| `SIGNAL_HASH_END` | 9 | End measured boot hash |
| `SEND_COMMAND` | 8 | Send TPM command (command port) |
| `SIGNAL_NV_ON` | 11 | NV storage available |
| `SIGNAL_CANCEL_ON` | 13 | Cancel current command |
| `SIGNAL_CANCEL_OFF` | 14 | Clear cancel |
| `SIGNAL_RESET` | 17 | Reset TPM |
| `SESSION_END` | 20 | End TCP session |
| `STOP` | 21 | Stop server |

wolfTPM clients connect using the standard SWTPM interface, compatible with
`tpm2-tools` and other SWTPM-aware software.

### TIS / Shared Memory

Built with `--enable-fwtpm` (without `--enable-swtpm`). Uses POSIX shared
memory and named semaphores to emulate TIS (TPM Interface Specification)
register-level access. This mode simulates an SPI-attached TPM.

**Shared memory layout** (`FWTPM_TIS_SHM`):

| Field | Description |
|-------|-------------|
| `magic` / `version` | Validation header (`0x57544953` / `"WTIS"`) |
| `reg_addr`, `reg_len`, `reg_is_write`, `reg_data` | Register access request |
| TIS register shadow: `access`, `sts`, `int_enable`, `int_status`, `intf_caps`, `did_vid`, `rid` | Emulated TIS registers |
| `cmd_buf[4096]`, `cmd_len`, `fifo_write_pos` | Command FIFO |
| `rsp_buf[4096]`, `rsp_len`, `fifo_read_pos` | Response FIFO |

**Paths** (compile-time configurable):

| Define | Default | Description |
|--------|---------|-------------|
| `FWTPM_TIS_SHM_PATH` | `/tmp/fwtpm.shm` | Shared memory file |
| `FWTPM_TIS_SEM_CMD` | `/fwtpm_cmd` | Command semaphore name |
| `FWTPM_TIS_SEM_RSP` | `/fwtpm_rsp` | Response semaphore name |

**Server-side API:**

- `FWTPM_TIS_Init()` -- Create shared memory and semaphores
- `FWTPM_TIS_Cleanup()` -- Remove shared memory and semaphores
- `FWTPM_TIS_ServerLoop()` -- Process TIS register accesses, dispatch commands

**Client-side API** (enabled by `WOLFTPM_FWTPM_HAL`):

- `FWTPM_TIS_ClientConnect()` -- Attach to existing shared memory
- `FWTPM_TIS_ClientDisconnect()` -- Detach from shared memory


## Testing

See [src/fwtpm/README.md](../src/fwtpm/README.md) for the full CI test matrix
and test script usage. Quick reference:

```sh
make check                  # Build + unit.test + run_examples.sh + tpm2-tools
scripts/tpm2_tools_test.sh  # tpm2-tools only (311 tests)
```

`make check` runs `tests/fwtpm_check.sh`, which starts and stops
`fwtpm_server` automatically -- do not start it manually.


## API Reference

### Core (`fwtpm.h`)

| Function | Description |
|----------|-------------|
| `int FWTPM_Init(FWTPM_CTX* ctx)` | Initialize fwTPM context, RNG, load NV state |
| `int FWTPM_Cleanup(FWTPM_CTX* ctx)` | Save NV, free resources, zero sensitive data |
| `const char* FWTPM_GetVersionString(void)` | Return version string (e.g., `"0.1.0"`) |

### Command Processor (`fwtpm_command.h`)

| Function | Description |
|----------|-------------|
| `int FWTPM_ProcessCommand(FWTPM_CTX* ctx, const byte* cmdBuf, int cmdSize, byte* rspBuf, int* rspSize, int locality)` | Process a raw TPM command packet and produce a response. Returns `TPM_RC_SUCCESS` on successful processing; the response buffer may contain a TPM error RC. |

### IO Transport (`fwtpm_io.h`)

| Function | Description |
|----------|-------------|
| `int FWTPM_IO_SetHAL(FWTPM_CTX* ctx, FWTPM_IO_HAL* hal)` | Register custom IO transport callbacks |
| `int FWTPM_IO_Init(FWTPM_CTX* ctx)` | Initialize transport (sockets or custom HAL) |
| `void FWTPM_IO_Cleanup(FWTPM_CTX* ctx)` | Close transport and release resources |
| `int FWTPM_IO_ServerLoop(FWTPM_CTX* ctx)` | Main server loop -- blocks until `ctx->running` is cleared |

### NV Storage (`fwtpm_nv.h`)

| Function | Description |
|----------|-------------|
| `int FWTPM_NV_Init(FWTPM_CTX* ctx)` | Load NV state from storage or create new (generates seeds) |
| `int FWTPM_NV_Save(FWTPM_CTX* ctx)` | Save current TPM state to NV storage |
| `int FWTPM_NV_SetHAL(FWTPM_CTX* ctx, FWTPM_NV_HAL* hal)` | Register custom NV storage callbacks |

### TIS Server (`fwtpm_tis.h`)

| Function | Description |
|----------|-------------|
| `int FWTPM_TIS_Init(FWTPM_CTX* ctx)` | Create shared memory region and semaphores |
| `void FWTPM_TIS_Cleanup(FWTPM_CTX* ctx)` | Unlink shared memory and semaphores |
| `int FWTPM_TIS_ServerLoop(FWTPM_CTX* ctx)` | Process TIS register accesses (blocks) |

### TIS Client (`fwtpm_tis.h`, requires `WOLFTPM_FWTPM_HAL`)

| Function | Description |
|----------|-------------|
| `int FWTPM_TIS_ClientConnect(FWTPM_TIS_CLIENT_CTX* client)` | Attach to fwTPM shared memory |
| `void FWTPM_TIS_ClientDisconnect(FWTPM_TIS_CLIENT_CTX* client)` | Detach from shared memory |


## Startup / Shutdown Lifecycle

1. **First boot:** `FWTPM_NV_Init` finds no NV file, generates random hierarchy
   seeds, saves initial state.
2. **`TPM2_Startup(SU_CLEAR)`:** Flushes transient objects and sessions, resets
   PCRs. Required before any other TPM command.
3. **Normal operation:** Commands are processed via `FWTPM_ProcessCommand`.
4. **`TPM2_Shutdown`:** Saves NV state but does NOT clear the "started" flag.
   The TPM remains logically powered on.
5. **Server restart** (process exit and relaunch) constitutes a power cycle.
   Only after a power cycle can `TPM2_Startup` be called again.

Calling `TPM2_Startup` on an already-started TPM returns `TPM_RC_INITIALIZE`.


## Primary Key Derivation

Primary keys are deterministically derived from the hierarchy seed per TPM 2.0
Part 1 Section 26. The same seed + same template always produces the same key:

- **RSA**: Primes p, q derived via iterative KDFa with labels `"RSA p"` / `"RSA q"`,
  primality testing, then CRT computation
- **ECC**: Private scalar d derived via `KDFa(nameAlg, seed, "ECC", hashUnique, counter)`,
  public point Q = d*G
- **KEYEDHASH/SYMCIPHER**: Key bytes derived via `KDFa(nameAlg, seed, label, hashUnique)`
- **hashUnique**: `H(sensitiveCreate.data || inPublic.unique)` per Section 26.1

A primary key cache (SHA-256 of template, `FWTPM_MAX_PRIMARY_CACHE` slots) avoids
re-deriving expensive RSA keys on repeated `CreatePrimary` calls.

Hierarchy seeds are managed by `ChangePPS` (platform) and `ChangeEPS` (endorsement).
`Clear` regenerates owner and endorsement seeds. The null seed is re-randomized on
every `Startup(CLEAR)`.
