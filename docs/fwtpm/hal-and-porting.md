# HAL and Porting

The fwTPM provides hardware abstraction layers (HALs) so it can be ported to embedded targets without modifying the core logic. There is an IO HAL for the transport, an NV HAL for persistent storage, and an optional clock HAL. Full reference ports for several boards live in the [wolftpm-examples](https://github.com/wolfSSL/wolftpm-examples) repository.

## IO HAL (Transport)

The IO HAL abstracts the transport between the fwTPM server and its clients. The default implementation uses TCP sockets (SWTPM protocol). For embedded targets, replace it with SPI, I2C, UART, or shared memory callbacks.

**Callback structure** (defined as `FWTPM_IO_HAL` in `fwtpm.h`):

| Callback | Signature | Description |
|----------|-----------|-------------|
| `send` | `int (*)(void* ctx, const void* buf, int sz)` | Send data to client |
| `recv` | `int (*)(void* ctx, void* buf, int sz)` | Receive data from client |
| `wait` | `int (*)(void* ctx)` | Wait for data or connections. Returns a bitmask: `0x01`=command data, `0x02`=platform data, `0x04`=new command connection, `0x08`=new platform connection |
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

## NV HAL (Persistent Storage)

The NV HAL abstracts persistent storage. The default implementation uses a local file (`fwtpm_nv.bin`). For embedded targets, replace it with flash, EEPROM, or other non-volatile storage callbacks.

**Callback structure** (defined as `FWTPM_NV_HAL` in `fwtpm.h`):

| Callback | Signature | Description |
|----------|-----------|-------------|
| `read` | `int (*)(void* ctx, word32 offset, byte* buf, word32 size)` | Read from NV at offset |
| `write` | `int (*)(void* ctx, word32 offset, const byte* buf, word32 size)` | Write to NV at offset |
| `erase` | see `fwtpm.h` | Erase the NV region (used by flash ports and by compaction) |
| `ctx` | `void*` | User context pointer |
| `maxSize` | `word32` | Size of the NV region in bytes |
| `appendOnly`, `writeAlign` | fields | Append-only mode and program granule size (see below) |
| `get_integrity_key` | callback | Supplies a device secret used to authenticate the journal |

**Registration:**

```c
FWTPM_NV_HAL myNvHal;
myNvHal.read = my_flash_read;
myNvHal.write = my_flash_write;
myNvHal.ctx = &myFlashCtx;

FWTPM_NV_SetHAL(&ctx, &myNvHal);
```

Register the HAL before `FWTPM_Init()`.

### NV Storage HAL for Embedded Ports

NV access goes through `FWTPM_NV_HAL` (`read`, `write`, `erase`, `ctx`, `maxSize`, `get_integrity_key`). The default backend is a file. An embedded port supplies its own HAL and registers it before `FWTPM_Init()`.

The journal is log-structured. On a byte-addressable backend (the file default) it writes TLV entries at byte-granular offsets, rewrites the header in place, and rewrites a trailing integrity MAC after every append. Internal flash and NOR are write-once and aligned to the program granularity, so they cannot service in-place rewrites.

For those parts, build with `--enable-fwtpm-nv-appendonly` (`-DWOLFTPM_FWTPM_NV_APPEND_ONLY`, CMake `WOLFTPM_FWTPM_NV_APPEND_ONLY=yes`) and set `appendOnly` and `writeAlign` on the HAL. The journal then runs in append-only mode:

- The header is written only at compaction.
- `writePos` is derived by scanning on load.
- Each commit is sealed with an appended MAC-checkpoint entry, padded up to `writeAlign`.

The existing `read`, `write`, and `erase` HAL is the integration point. There is no separate adapter.

```c
/* Native flash HAL. In append-only mode the journal only ever calls write()
 * with writeAlign-aligned, forward, into-erased bytes, so write() is a simple
 * flash program; erase() erases the region (sector loop); read() reads raw. */
FWTPM_NV_HAL hal;
XMEMSET(&hal, 0, sizeof(hal));
hal.read = myRead; hal.write = myProgram; hal.erase = myErase;
hal.ctx = myCtx; hal.maxSize = NV_SIZE;
hal.appendOnly = 1;
hal.writeAlign = PROG_SIZE;            /* flash word size, e.g. 16 (STM32H5) */
hal.get_integrity_key = myDeviceSecret;/* recommended on flash */
FWTPM_NV_SetHAL(&ctx, &hal);           /* before FWTPM_Init() */
```

In append-only mode the journal buffers a pending program granule internally and flushes full, aligned granules through `write()`. A programmed cell is never rewritten, and a whole sector is erased only on compaction. The header sector is therefore not erased on every append, and a torn final commit (for example from power loss) is ignored on the next load while all previously committed state survives.

A `get_integrity_key` callback is strongly recommended on flash, so the MAC checkpoints authenticate the journal and reject a torn or tampered tail. Setting `writeAlign <= 1` selects no buffering, so byte-writable NV (EEPROM or FRAM) works with a plain `write()`.

!!! warning
    Compaction still erases the whole region before rewriting, so a power loss during compaction itself remains a vulnerable window. A future two-region ping-pong layout would close it.

## Clock HAL

The clock HAL is optional. It supplies `get_ms()`, which returns milliseconds since boot. Register it with `FWTPM_Clock_SetHAL()` before `FWTPM_Init()`. With a clock HAL registered, dictionary attack protection self-heals over time (see [Overview](overview.md)).

## Porting Example

A bare-metal embedded target with SPI transport and SPI flash NV:

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

## Available Ports

| Port | Repository | Description |
|------|-----------|-------------|
| STM32H5 | [STM32/fwtpm-stm32h5](https://github.com/wolfSSL/wolftpm-examples/tree/main/STM32/fwtpm-stm32h5) | STM32H5 Cortex-M33 with TrustZone (CMSE); internal-flash NV |
| PolarFire SoC | [Microchip/fwtpm-polarfire-miv](https://github.com/wolfSSL/wolftpm-examples/tree/main/Microchip/fwtpm-polarfire-miv) | MPFS250T; fwTPM bare-metal in M-mode on a U54 RISC-V hart (HSS AMP alongside Linux), TIS over shared L2-LIM memory |
| Zynq UltraScale+ ZCU102 | [Xilinx/fwtpm-zcu102-r5](https://github.com/wolfSSL/wolftpm-examples/tree/main/Xilinx/fwtpm-zcu102-r5) | ZynqMP MPSoC; fwTPM bare-metal on the Cortex-R5 RPU pair in lock-step, OpenAMP RPMsg client on the A53 (PetaLinux); volatile DDR NV or persistent QSPI |

## Porting Guide

To add a new platform, implement these HAL callbacks:

1. **NV Storage HAL** (`FWTPM_NV_HAL`): `read()`, `write()`, and `erase()` for persistent flash storage. Register it with `FWTPM_NV_SetHAL()` before `FWTPM_Init()`.

    The NV journal is log-structured. On a byte-addressable backend it writes at byte-granular offsets and rewrites the header and a trailing integrity MAC in place after every append. Internal flash and NOR are write-once and aligned to the program granularity, so they cannot service in-place rewrites. For those, build with `--enable-fwtpm-nv-appendonly` and set `hal.appendOnly = 1` and `hal.writeAlign = <program size>` (for example 16 on STM32H5) before `FWTPM_NV_SetHAL()`.

    The journal then writes the header only at compaction, derives `writePos` by scanning on load, seals each commit with an appended, program-granule-aligned MAC checkpoint, and buffers a pending program granule internally. It only ever calls `write()` with `writeAlign`-aligned, forward, into-erased bytes. Your `write()` is therefore a simple flash program with no buffering or read-modify-write in the port, `erase()` erases the region (sector loop), and `read()` reads raw bytes. A programmed cell is never rewritten and a whole sector is erased only on compaction, so the header sector is not worn on every append and a torn final commit is ignored on the next load. Provide a `get_integrity_key` on `FWTPM_NV_HAL` so the checkpoints authenticate the journal. Setting `writeAlign <= 1` disables buffering for byte-writable NV such as EEPROM or FRAM.

2. **Clock HAL** (optional): `get_ms()` returning milliseconds since boot. Register it with `FWTPM_Clock_SetHAL()` before `FWTPM_Init()`.

3. **Entry point**: zero `FWTPM_CTX`, register the HALs, call `FWTPM_Init()`, then process TPM commands with `FWTPM_ProcessCommand()`.

See the STM32 port in wolftpm-examples for a complete reference implementation.

## See Also

- [Overview](overview.md)
- [Building](building.md)
- [Usage](usage.md)
- [Post-Quantum Support](post-quantum.md)
- [SPDM Responder](spdm.md)
