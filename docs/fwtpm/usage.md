# Using the fwTPM

This page covers running the fwTPM server, connecting clients, transport modes, NV persistence, testing, the C API, and real-world board examples. To build the server first, see [Building](building.md).

## Starting the Server

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
| `--clear` | Start with cleared NV |
| `--spdm-tcg`, `--spdm-psk`, `--no-spdm` | SPDM responder mode (see [SPDM Responder](spdm.md)) |

The `--port` and `--platform-port` options are socket-mode only and are not available in TIS builds (`--enable-fwtpm` without `--enable-swtpm`).

**Example:**

```sh
# Start with default ports (localhost:2321 command, :2322 platform)
./src/fwtpm/fwtpm_server

# Start on custom ports
./src/fwtpm/fwtpm_server --port 2331 --platform-port 2332

# Start with clear NV
./src/fwtpm/fwtpm_server --clear
```

The server prints its configuration on startup:

```
wolfTPM fwTPM Server v0.1.0
  Command port:  2321
  Platform port: 2322
  Manufacturer:  WOLF
  Model:         fwTPM
```

In `--spdm-tcg` test mode the server also prints its generated responder public key. This is a local test-harness convenience, not a provisioning or trust-anchor channel for hardware responders.

## Connecting wolfTPM Clients

Any wolfTPM application built with `--enable-swtpm` connects to the fwTPM server automatically over TCP. The built-in swtpm client speaks the mssim protocol.

```sh
# In one terminal: start the server
./src/fwtpm/fwtpm_server

# In another terminal: run wolfTPM examples
./examples/wrap/wrap_test
./examples/wrap/caps
./examples/keygen/keygen keyblob.bin -rsa -t
./examples/attestation/make_credential
```

### Using tpm2-tools

In socket mode (`--enable-swtpm`), the server supports both the mssim (Microsoft TPM simulator) and swtpm (Stefan Berger) TCTI protocols, which it auto-detects on the command port. Either TCTI works:

```sh
# mssim TCTI (default for wolfTPM test scripts)
export TPM2TOOLS_TCTI="mssim:host=localhost,port=2321"
tpm2_startup -c

# swtpm TCTI (also works, auto-detected)
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"
tpm2_getrandom 8
```

## NV Persistence

The server stores persistent state (hierarchy seeds, auth values, PCR state, NV indices) in `fwtpm_nv.bin` (configurable with `FWTPM_NV_FILE`). On first start, seeds are randomly generated and saved. Later starts reload the existing state.

Embedded targets replace the file backend with a flash, EEPROM, or other NV HAL, including an append-only mode for write-once flash. See [HAL and Porting](hal-and-porting.md).

## Transport Modes

### Socket / SWTPM (Default)

Built with `--enable-fwtpm --enable-swtpm`. The server listens on two TCP ports using the SWTPM wire protocol:

- **Command port** (default 2321): TPM command and response traffic
- **Platform port** (default 2322): Platform signals (power on and off, NV on, cancel, reset, session end, stop)

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

wolfTPM clients connect through the standard SWTPM interface, which is compatible with `tpm2-tools` and other SWTPM-aware software.

### TIS / Shared Memory

Built with `--enable-fwtpm` (without `--enable-swtpm`). This mode uses POSIX shared memory and named semaphores to emulate TIS (TPM Interface Specification) register-level access. It simulates an SPI-attached TPM.

**Shared memory layout** (`FWTPM_TIS_SHM`):

| Field | Description |
|-------|-------------|
| `magic` / `version` | Validation header (`0x57544953` / "WTIS", protocol version 2) |
| `reg_addr`, `reg_len`, `reg_is_write`, `reg_data` | Register access request |
| TIS register shadow: `access`, `sts`, `int_enable`, `int_status`, `intf_caps`, `did_vid`, `rid` | Emulated TIS registers |
| `cmd_buf[4096]`, `cmd_len`, `fifo_write_pos` | Command FIFO |
| `rsp_buf[4096]`, `rsp_len`, `fifo_read_pos` | Response FIFO |

**Paths** (compile-time configurable):

| Define | Default | Description |
|--------|---------|-------------|
| `FWTPM_TIS_SHM_PATH` | `/tmp/fwtpm.shm` | Shared memory file; clients require a regular, single-link, same-UID, exact-size `0600` endpoint |
| `FWTPM_TIS_SEM_CMD` | `/fwtpm_cmd` | Command semaphore name |
| `FWTPM_TIS_SEM_RSP` | `/fwtpm_rsp` | Response semaphore name |

Clients require an exact protocol version and shared-region-size match, so rebuild the client library and `fwtpm_server` together when changing options that affect `FWTPM_TIS_FIFO_SIZE`. The default paths are global, so run one server per host.

**Server-side API:**

- `FWTPM_TIS_Init()`: create shared memory and semaphores
- `FWTPM_TIS_Cleanup()`: remove shared memory and semaphores
- `FWTPM_TIS_ServerLoop()`: process TIS register accesses and dispatch commands

**Client-side API** (enabled by `WOLFTPM_FWTPM_HAL`):

- `FWTPM_TIS_ClientConnect()`: attach to existing shared memory
- `FWTPM_TIS_ClientDisconnect()`: detach from shared memory

## Testing

```sh
make check                  # Build + unit.test + run_examples.sh + tpm2-tools
scripts/tpm2_tools_test.sh  # tpm2-tools only (311 tests)
```

`make check` runs `tests/fwtpm_check.sh`, which starts and stops `fwtpm_server` automatically. Do not start the server manually for it.

### CI Tests (fwtpm-test.yml)

All tests below run in GitHub Actions CI. Run them manually before PR submission. ASan, UBSan, and LeakSan coverage lives in `sanitizer.yml`, not this workflow.

**Runtime tests (build, run_examples.sh, make check):**

| Name | wolfTPM Config | Extra | Notes |
|------|---------------|-------|-------|
| fwtpm-socket | `--enable-fwtpm --enable-swtpm --enable-debug` | | Primary test |
| fwtpm-tis | `--enable-fwtpm --enable-debug` | | TIS/SHM transport |
| fwtpm-v185 | `--enable-fwtpm --enable-v185` | | PQC: wrapper and handler unit tests |
| fwtpm-macos-socket | `--enable-fwtpm --enable-swtpm --enable-debug` | | macOS runner |

**Runtime tests, gated builds (`fwtpm-gated-runtime` job):**

These configurations remove commands, so `make check` (which drives the examples and tpm2-tools) does not apply. The job builds and runs only `tests/fwtpm_unit.test`. Its `test_fwtpm_command_gates`, `test_fwtpm_total_commands`, and `test_fwtpm_pcr_bounds` cases assert that a gated command is rejected with `TPM_RC_COMMAND_CODE`, is absent from `TPM_CAP_COMMANDS`, and is not counted in `TPM_PT_TOTAL_COMMANDS`.

| Name | wolfTPM Config | wolfSSL Config | Extra CFLAGS |
|------|---------------|---------------|-------------|
| all-gates-ecc-only | `--enable-fwtpm --enable-swtpm` | `--disable-rsa` | the eleven command-group `-DFWTPM_NO_*` gates together (NV retained) |
| all-gates-mldsa | `--enable-fwtpm --enable-swtpm --enable-v185 --enable-mldsa` | `--enable-dilithium --enable-mlkem` | the same eleven gates; proves SequenceUpdate survives for ML-DSA while SequenceComplete does not |
| reduced-pcr | `--enable-fwtpm --enable-swtpm` | | `-DIMPLEMENTATION_PCR=8 -DPLATFORM_PCR=8` |

**Build-only tests:**

| Name | wolfTPM Config | wolfSSL Config | Extra CFLAGS |
|------|---------------|---------------|-------------|
| fwtpm-no-rsa | `--enable-fwtpm --enable-swtpm` | `--disable-rsa` | |
| fwtpm-no-ecc | `--enable-fwtpm --enable-swtpm` | `--disable-ecc` | |
| fwtpm-no-sha384 | `--enable-fwtpm --enable-swtpm` | `--disable-sha384` | |
| fwtpm-no-sha1 | `--enable-fwtpm --enable-swtpm` | `--disable-sha` | `-DNO_SHA` |
| fwtpm-v185-build-only | `--enable-fwtpm --enable-v185` | | `-DDEBUG_WOLFTPM` |
| fwtpm-only | `--enable-fwtpm-only --enable-swtpm` | | No client library |
| fwtpm-minimal | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_ATTESTATION -DFWTPM_NO_NV -DFWTPM_NO_POLICY -DFWTPM_NO_CREDENTIAL -DFWTPM_NO_DA -DFWTPM_NO_PARAM_ENC` |
| fwtpm-no-policy | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_POLICY` |
| fwtpm-no-nv | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_NV` |
| fwtpm-no-attestation | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_ATTESTATION` |
| fwtpm-no-credential | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_CREDENTIAL` |
| fwtpm-no-da | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_DA` |
| fwtpm-no-param-enc | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_PARAM_ENC` |
| fwtpm-no-key-migration | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_KEY_MIGRATION` |
| fwtpm-no-ecdh | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_ECDH` |
| fwtpm-no-hash-cmds | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_HASH_CMDS` |
| fwtpm-no-context | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_CONTEXT` |
| fwtpm-no-sym-encrypt | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_SYM_ENCRYPT` |
| fwtpm-no-clock | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_CLOCK` |
| fwtpm-reduced-pcr | `--enable-fwtpm --enable-swtpm` | | `-DIMPLEMENTATION_PCR=8 -DPLATFORM_PCR=8` |
| fwtpm-no-rsa-no-policy | `--enable-fwtpm --enable-swtpm` | `--disable-rsa` | `-DFWTPM_NO_POLICY` |
| fwtpm-no-ecc-no-nv | `--enable-fwtpm --enable-swtpm` | `--disable-ecc` | `-DFWTPM_NO_NV` |
| fwtpm-small-stack | `--enable-fwtpm --enable-swtpm` | | `-DWOLFTPM_SMALL_STACK` |

**Pedantic builds (build-only, -Werror):**

| Name | Compiler | Config |
|------|----------|--------|
| fwtpm-pedantic-gcc | gcc | `--enable-fwtpm --enable-swtpm` |
| fwtpm-pedantic-clang | clang | `--enable-fwtpm --enable-swtpm` |
| fwtpm-pedantic-only | gcc | `--enable-fwtpm-only` |

**Separate job: tpm2-tools (311 tests):**

```sh
scripts/tpm2_tools_test.sh
```

## API Reference

### Core (`fwtpm.h`)

| Function | Description |
|----------|-------------|
| `int FWTPM_Init(FWTPM_CTX* ctx)` | Initialize fwTPM context, RNG, load NV state |
| `int FWTPM_Cleanup(FWTPM_CTX* ctx)` | Save NV, free resources, zero sensitive data |
| `const char* FWTPM_GetVersionString(void)` | Return version string (for example `"0.1.0"`) |

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
| `int FWTPM_IO_ServerLoop(FWTPM_CTX* ctx)` | Main server loop; blocks until `ctx->running` is cleared |

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

## Real-world examples

The [wolftpm-examples](https://github.com/wolfSSL/wolftpm-examples) repository holds complete fwTPM projects for real boards. Each one shows a different isolation or storage choice.

| Board | Project | What it shows |
|-------|---------|---------------|
| STM32H5 NUCLEO-H563ZI | [STM32/fwtpm-stm32h5](https://github.com/wolfSSL/wolftpm-examples/tree/main/STM32/fwtpm-stm32h5) | fwTPM in the Cortex-M33 TrustZone secure world, internal-flash NV, UART with the mssim protocol |
| Xilinx ZCU102 (R5, lock-step) | [Xilinx/fwtpm-zcu102-r5](https://github.com/wolfSSL/wolftpm-examples/tree/main/Xilinx/fwtpm-zcu102-r5) | AMP: fwTPM bare-metal on the Cortex-R5 pair in lock-step, PetaLinux client on the A53 over OpenAMP RPMsg; volatile DDR NV or persistent QSPI |
| Xilinx ZC702 (A9) | [Xilinx/fwtpm-zc702-a9](https://github.com/wolfSSL/wolftpm-examples/tree/main/Xilinx/fwtpm-zc702-a9) | SRAM-PUF derived device-unique NV key, so no root key is stored in flash |
| SCU35 (MicroBlaze-V soft core) | [Xilinx/fwtpm-scu35-microblazev](https://github.com/wolfSSL/wolftpm-examples/tree/main/Xilinx/fwtpm-scu35-microblazev) | ECC-only fwTPM that fits in about 190 KB of block RAM |
| PolarFire SoC MPFS250T | [Microchip/fwtpm-polarfire-miv](https://github.com/wolfSSL/wolftpm-examples/tree/main/Microchip/fwtpm-polarfire-miv) | AMP: fwTPM bare-metal on a U54 hart, isolated from Linux, TIS over shared L2-LIM memory |
| PolarFire MPF300 Splash (soft MIV) | [Microchip/miv-mpf300-splash](https://github.com/wolfSSL/wolftpm-examples/tree/main/Microchip/miv-mpf300-splash) | Soft Mi-V core with persistent on-die sNVM |

The STM32H5, PolarFire SoC, and ZCU102 projects are also listed as ports in [HAL and Porting](hal-and-porting.md).

## See Also

- [Overview](overview.md)
- [Building](building.md)
- [HAL and Porting](hal-and-porting.md)
- [Post-Quantum Support](post-quantum.md)
- [SPDM Responder](spdm.md)
