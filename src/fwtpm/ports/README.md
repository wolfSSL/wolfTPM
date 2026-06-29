# fwTPM Embedded Ports

Platform-specific ports of the wolfTPM fwTPM server for embedded targets.
Full reference ports live in the
[wolftpm-examples](https://github.com/wolfSSL/wolftpm-examples) repository.

## Available Ports

| Port | Repository | Description |
|------|-----------|-------------|
| STM32H5 | [STM32/fwtpm-stm32h5](https://github.com/wolfSSL/wolftpm-examples/tree/main/STM32/fwtpm-stm32h5) | STM32H5 Cortex-M33 with TrustZone (CMSE); internal-flash NV |
| PolarFire SoC | [Microchip/fwtpm-polarfire-miv](https://github.com/wolfSSL/wolftpm-examples/tree/main/Microchip/fwtpm-polarfire-miv) | MPFS250T; fwTPM bare-metal in M-mode on a U54 RISC-V hart (HSS AMP alongside Linux), TIS over shared L2-LIM memory |
| Zynq UltraScale+ ZCU102 | [Xilinx/fwtpm-zcu102-r5](https://github.com/wolfSSL/wolftpm-examples/tree/main/Xilinx/fwtpm-zcu102-r5) | ZynqMP MPSoC; fwTPM bare-metal on the Cortex-R5 RPU pair in lock-step, OpenAMP RPMsg client on the A53 (PetaLinux); volatile DDR NV or persistent QSPI |

## Porting Guide

To add a new platform, implement these HAL callbacks:

1. **NV Storage HAL** (`FWTPM_NV_HAL`): `read()`, `write()`, `erase()` for
   persistent flash storage. Register via `FWTPM_NV_SetHAL()` before `FWTPM_Init()`.

   The NV journal is log-structured. On a byte-addressable backend it writes at
   byte-granular offsets and rewrites the header and a trailing integrity MAC in
   place after every append. Internal flash and NOR are write-once and
   program-granularity aligned, so they cannot service in-place rewrites. For
   those, build with `--enable-fwtpm-nv-appendonly` (`-DWOLFTPM_FWTPM_NV_APPEND_ONLY`,
   CMake `WOLFTPM_FWTPM_NV_APPEND_ONLY=yes`) and set `hal.appendOnly = 1` and
   `hal.writeAlign = <program size>` (e.g. 16 on STM32H5) before
   `FWTPM_NV_SetHAL()`. The journal then writes the
   header only at compaction, derives writePos by scanning on load, seals each
   commit with an appended, program-granule-aligned MAC checkpoint, and buffers
   a pending program granule internally so it only ever calls `write()` with
   `writeAlign`-aligned, forward, into-erased bytes - your `write()` is a simple
   flash program (no buffering or read-modify-write in the port), `erase()`
   erases the region (sector loop), `read()` reads raw bytes. A programmed cell
   is never rewritten and a whole sector is erased only on compaction, so the
   header sector is not worn on every append and a torn final commit is ignored
   on the next load. Provide a `get_integrity_key` on `FWTPM_NV_HAL` so the
   checkpoints authenticate the journal. (`writeAlign <= 1` disables buffering
   for byte-writable NV like EEPROM/FRAM.)

2. **Clock HAL** (optional): `get_ms()` returning milliseconds since boot.
   Register via `FWTPM_Clock_SetHAL()` before `FWTPM_Init()`.

3. **Entry point**: Zero `FWTPM_CTX`, register HALs, call `FWTPM_Init()`,
   then process TPM commands via `FWTPM_ProcessCommand()`.

See the STM32 port in wolftpm-examples for a complete reference implementation.
