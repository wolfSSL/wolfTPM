# Build Options

This page lists the configure options and preprocessor defines that control how wolfTPM is built. The block below is the curated reference from the project README. Each configure switch shows the macro it defines when one exists.

## Build options and defines


```text
--enable-debug          Add debug code/turns off optimizations (yes|no|verbose|io) - DEBUG_WOLFTPM, WOLFTPM_DEBUG_VERBOSE, WOLFTPM_DEBUG_IO
                        WARNING: Define WOLFTPM_DEBUG_SECRETS manually (NOT enabled by default and NOT
                        exposed via configure) to additionally print sensitive material - auth values,
                        session keys, bind keys, HMAC keys, hierarchy auth, and encryption secrets.
                        For developer debugging only. NEVER enable in production builds or on devices
                        that log stdout to persistent storage.
--enable-examples       Enable Examples (default: enabled)
--enable-wrapper        Enable wrapper code (default: enabled) - WOLFTPM2_NO_WRAPPER
--enable-wolfcrypt      Enable wolfCrypt hooks for RNG, Auth Sessions and Parameter encryption (default: enabled) - WOLFTPM2_NO_WOLFCRYPT
--enable-advio          Enable Advanced IO (default: disabled) - WOLFTPM_ADV_IO
--enable-spi            Intent signal for SPI hardware build. SPI is the default transport when --enable-i2c is not set;
                        this flag adds no compile-time macro but disables the auto-enabled swTPM/fwTPM defaults. (default: not set)
--enable-i2c            Enable I2C TPM Support (default: disabled, requires advio) - WOLFTPM_I2C
--enable-mmio           Enable built-in MMIO callbacks (default: disabled) - WOLFTPM_MMIO
--enable-wolfhal        Enable wolfHAL IO callbacks (default: disabled) - WOLFTPM_WOLFHAL
                        Requires the wolfHAL headers and an application provided board.h.
                        See hal/README.md for the required BOARD_* definitions.
--enable-checkwaitstate Enable TIS / SPI Check Wait State support (default: depends on chip) - WOLFTPM_CHECK_WAIT_STATE
--enable-smallstack     Enable options to reduce stack usage
--enable-tislock        Enable Linux Named Semaphore for locking access to SPI device for concurrent access between processes - WOLFTPM_TIS_LOCK
--enable-firmware       Enable firmware upgrade support for Infineon SLB9672/SLB9673 and ST ST33 (default: disabled) - WOLFTPM_FIRMWARE_UPGRADE

--enable-autodetect     Enable Runtime Module Detection (default: enable - when no module specified) - WOLFTPM_AUTODETECT
                        On Linux this also auto-detects /dev/tpmrm0 or /dev/tpm0 at runtime,
                        falling back to SPI if the kernel driver is not available.
--enable-infineon       Enable Infineon SLB9670/SLB9672/SLB9673 TPM Support (default: disabled) - WOLFTPM_SLB9670 / WOLFTPM_SLB9672
--enable-st             Enable ST ST33 Support (default: disabled) - WOLFTPM_ST33
--enable-microchip      Enable Microchip ATTPM20 Support (default: disabled) - WOLFTPM_MICROCHIP
--enable-nuvoton        Enable Nuvoton NPCT65x/NPCT75x Support (default: disabled) - WOLFTPM_NUVOTON
--enable-nations        Enable Nations Technology NS350 Support (default: disabled) - WOLFTPM_NATIONS
--enable-sealsq         Enable SealSQ QVault post-quantum TPM Support (default: disabled) - WOLFTPM_SEALSQ

--enable-devtpm         Enable using Linux kernel driver for /dev/tpmX (default: disabled) - WOLFTPM_LINUX_DEV
                        Note: With autodetect (default) this is no longer required on Linux;
                        the kernel driver is tried automatically before SPI.
--enable-swtpm          Enable using SWTPM TCP protocol. For use with simulator. (default: enabled on Linux x86_64/aarch64,
                        disabled elsewhere or when a hardware path is selected via any of
                        --enable-spi/--enable-i2c/--enable-mmio/--enable-nuvoton/--enable-nations/
                        --enable-infineon/--enable-st/--enable-microchip/--enable-devtpm/--enable-autodetect) - WOLFTPM_SWTPM
--enable-swtpm=uart     Enable using SWTPM protocol over UART serial. For use with fwTPM on
                        embedded targets (e.g. STM32H5). Uses termios serial I/O instead of
                        TCP sockets. - WOLFTPM_SWTPM + WOLFTPM_SWTPM_UART
--enable-fwtpm          Enable firmware TPM (fwTPM) server. Same default behavior as --enable-swtpm
                        (auto-enabled on Linux x86_64/aarch64, auto-disabled when a hardware
                        path is selected). - WOLFTPM_FWTPM_SERVER
--enable-winapi         Use Windows TBS API. (default: disabled) - WOLFTPM_WINAPI

WOLFTPM_USE_SYMMETRIC   Enables symmetric AES/Hashing/HMAC support for TLS examples.
WOLFTPM2_USE_SW_ECDHE   Disables use of TPM for ECC ephemeral key generation and shared secret for TLS examples.
WOLFTPM2_ECC_DEFAULT_CURVE  Default ECC curve for wrapper key templates that request P256 (SRK/AIK/general ECC). Defaults to TPM_ECC_NIST_P256, or the smallest enabled curve meeting ECC_MIN_KEY_SZ. Override e.g. -DWOLFTPM2_ECC_DEFAULT_CURVE=TPM_ECC_NIST_P384.
TLS_BENCH_MODE          Enables TLS benchmarking mode.
NO_TPM_BENCH            Disables the TPM benchmarking example.
WOLFTPM_MAX_RETRIES     Default number of times a command is transparently resubmitted when the TPM returns TPM_RC_RETRY (momentarily busy, e.g. persisting the daUsed flag on first auth use of an externally provisioned non-noDA AIK/SUDI key). Disabled by default (0); opt in with TPM2_SetCommandRetries() at runtime or -DWOLFTPM_MAX_RETRIES=N at build time. wolfTPM's own key templates set noDA and never trigger it.
WOLFTPM_NO_RETRY        Compiles out the TPM_RC_RETRY auto-resubmit handling entirely; TPM_RC_RETRY is returned to the caller for manual handling.
WOLFTPM_LOCALITY_DEFAULT  Default TIS locality requested at startup (default 0). Runtime override via wolfTPM2_SetLocality() on SPI/memory-mapped and swtpm transports. The I2C HAL addresses only locality 0 (the TIS locality lives in address bits 12+, which the 8-bit I2C register address cannot carry), so a non-zero wolfTPM2_SetLocality() on I2C returns NOT_COMPILED_IN rather than silently operating at locality 0.
WOLFTPM_TIS_RESET_STALE_LOCALITY  At startup, release any other active locality so the default can be granted - recovers a wedge left when a prior session did not return to locality 0. Off by default; single-master buses only, since on a shared bus it could clear a locality another master holds (or use the nRST reset HAL to recover).
WOLFTPM_LOCALITY_TIMEOUT_TRIES  Poll attempts when requesting a locality at runtime (default 1000). Kept small so a locality that cannot be granted fails fast.
WOLFTPM_RESET_LINE      nRST GPIO line number for the optional reset HAL; set via --enable-hal-reset=LINE and driven with TPM2_IoCb_Reset() (see hal/README.md).
```

!!! note
    For I2C support on a Raspberry Pi you may need to enable I2C first:

    1. Edit `/boot/config.txt` (for example `sudo vim /boot/config.txt`).
    2. Uncomment `dtparam=i2c_arm=on`.
    3. Reboot with `sudo reboot`.

## Full configure reference

`configure.ac` in the wolfTPM source tree is the authoritative and complete list of configure options. The exhaustive per-macro reference will be expanded in a later revision of this manual. The option families currently present are:

| Family | Options and macros |
| --- | --- |
| Debug | `--enable-debug`, `DEBUG_WOLFTPM`, `WOLFTPM_DEBUG_VERBOSE`, `WOLFTPM_DEBUG_IO` |
| Wrapper and wolfCrypt | `--enable-wrapper` (`WOLFTPM2_NO_WRAPPER`), `--enable-wolfcrypt` (`WOLFTPM2_NO_WOLFCRYPT`) |
| IO layer | `--enable-advio`, `--enable-i2c`, `--enable-mmio`, `--enable-wolfhal`, `--enable-spi` |
| Timing and locking | `--enable-checkwaitstate`, `--enable-tislock` |
| Firmware upgrade | `--enable-firmware` (`WOLFTPM_FIRMWARE_UPGRADE`) |
| Module detection | `--enable-autodetect` (`WOLFTPM_AUTODETECT`) |
| Vendors | `--enable-infineon` (SLB9670, SLB9672, SLB9673), `--enable-st` (ST33), `--enable-microchip`, `--enable-nuvoton`, `--enable-nations`, `--enable-sealsq` |
| Operating system transports | `--enable-devtpm` (`WOLFTPM_LINUX_DEV`), `--enable-winapi` (`WOLFTPM_WINAPI`) |
| Simulators and firmware TPM | `--enable-swtpm`, `--enable-swtpm=uart`, `--enable-fwtpm` (`WOLFTPM_FWTPM_SERVER`) |
| Runtime behavior | `WOLFTPM_MAX_RETRIES`, `WOLFTPM_NO_RETRY`, `WOLFTPM_LOCALITY_DEFAULT`, `WOLFTPM_TIS_RESET_STALE_LOCALITY`, `WOLFTPM_LOCALITY_TIMEOUT_TRIES`, `WOLFTPM_RESET_LINE`, `WOLFTPM2_ECC_DEFAULT_CURVE` |

## See Also

- [Building wolfTPM](building.md)
- [System Interfaces](system-interfaces.md)
- [Supported Hardware](supported-hardware.md)
- [Getting Started](getting-started.md)
