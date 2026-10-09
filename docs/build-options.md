# Build Options

This page is the reference for the Autotools (`./configure`) options and the preprocessor defines that control how wolfTPM is built. Each configure switch lists the macro it defines when one exists. `configure.ac` in the wolfTPM source tree is the authoritative source.

!!! note
    This page documents the Autotools build. The CMake build differs: fwTPM is off by default and the TPM interface is chosen with the `WOLFTPM_INTERFACE` cache variable (`auto`, `SWTPM`, `WINAPI`, `DEVTPM`, `SPI`, `I2C` or `MMIO`) instead of `--enable-*` flags. See [Building wolfTPM](building.md) for CMake.

## Reading the tables

- Every `--enable-X` flag also has a `--disable-X` form. The default column shows the state when the flag is not given.
- A few macros are opt-outs. `WOLFTPM2_NO_WRAPPER` is defined by `--disable-wrapper`, and `WOLFTPM2_NO_WOLFCRYPT` is defined by `--disable-wolfcrypt`. The enable forms do not define them.
- The generated `wolftpm/options.h` records the macros chosen at configure time.

## General and debug

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-debug[=yes\|no\|verbose\|io]` | no | Adds debug code and turns off optimizations. Defines `DEBUG_WOLFTPM`. `verbose` also defines `WOLFTPM_DEBUG_VERBOSE`, and `io` defines both `WOLFTPM_DEBUG_VERBOSE` and `WOLFTPM_DEBUG_IO`. |
| `--enable-examples` | enabled | Build the example programs. |
| `--enable-wrapper` | enabled | Build the wrapper API. `--disable-wrapper` defines `WOLFTPM2_NO_WRAPPER`. |
| `--enable-wolfcrypt` | enabled | Use wolfCrypt for RNG, authorization sessions and parameter encryption. `--disable-wolfcrypt` defines `WOLFTPM2_NO_WOLFCRYPT`. |
| `--with-wolfcrypt=PATH` | `/usr/local` | Path to the wolfSSL install. The directory must contain `lib` and `include`. |
| `--enable-smallstack` | disabled | Defines `WOLFTPM_SMALL_STACK` to reduce stack usage. Also sets `MAX_COMMAND_SIZE=1024`, `MAX_RESPONSE_SIZE=1350` and `MAX_DIGEST_BUFFER=896`. With `--disable-wolfcrypt` it also sets `MAX_SESSION_NUM=1`. |
| `--enable-provisioning` | enabled | Support for provisioning Initial Device Identity (IDevID) and Attestation Identity Keys. Defines `WOLFTPM_PROVISIONING`. |
| `--enable-firmware` | enabled | TPM firmware upgrade support for Infineon SLB9672/SLB9673 and ST ST33. Defines `WOLFTPM_FIRMWARE_UPGRADE`. Use `--disable-firmware` to remove it. |
| `--enable-fuzz` | disabled | Build the fuzz targets. |

!!! warning
    `WOLFTPM_DEBUG_SECRETS` is not set by any configure option and is off by default. Defining it manually prints sensitive material such as auth values, session keys, bind keys, HMAC keys, hierarchy auth and encryption secrets. Use it only for developer debugging. Never enable it in production builds or on devices that log stdout to persistent storage.

## I/O layer and bus selection

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-spi` | not set | Intent signal for a SPI hardware build. SPI is the default transport when `--enable-i2c` is not set. Adds no macro, but counts as a hardware selection and so turns off the automatic swTPM and fwTPM defaults. Cannot be combined with `--enable-i2c`. |
| `--enable-i2c` | disabled | I2C TPM support. Defines `WOLFTPM_I2C` and automatically defines `WOLFTPM_ADV_IO`. |
| `--enable-mmio` | disabled | Built-in memory-mapped I/O callbacks. Defines `WOLFTPM_MMIO` and automatically defines `WOLFTPM_ADV_IO`. |
| `--enable-advio` | disabled | Advanced I/O callback signature. Defines `WOLFTPM_ADV_IO`. You do not need to pass it separately with I2C or MMIO. |
| `--enable-wolfhal` | disabled | wolfHAL I/O callbacks. Defines `WOLFTPM_WOLFHAL`. Requires the wolfHAL headers and an application-provided `board.h`. See `hal/README.md` for the required `BOARD_*` definitions. |
| `--enable-hal` | enabled | Build the example HAL interfaces. Defines `WOLFTPM_EXAMPLE_HAL`. |
| `--enable-hal-reset[=LINE]` | disabled | TPM nRST reset HAL through the Linux GPIO character device. Always defines `WOLFTPM_HAL_RESET`. A numeric `LINE` also defines `WOLFTPM_RESET_LINE`. Without a line the default is GPIO24 for ST33 and GPIO4 for Nuvoton. Drive it with `TPM2_IoCb_Reset()`. |
| `--enable-checkwaitstate` | depends on chip | TIS and SPI check-wait-state support. Defines `WOLFTPM_CHECK_WAIT_STATE`. Configure turns it on for autodetect and for every build that is not Infineon-only. |
| `--enable-tislock` | disabled | Defines `WOLFTPM_TIS_LOCK`. Uses a named semaphore to serialize TIS commands across processes. Linux only. |

`--enable-hal-reset` needs the SPI or I2C hardware HAL. Configure rejects it together with swTPM or `--enable-devtpm`. Because swTPM is the default on common hosts, pass `--enable-spi` or `--enable-i2c` with it.

!!! note
    For I2C support on a Raspberry Pi you may need to enable I2C first:

    1. Edit `/boot/firmware/config.txt` on current Raspberry Pi OS (for example `sudo vim /boot/firmware/config.txt`). Older images use `/boot/config.txt`.
    2. Uncomment `dtparam=i2c_arm=on`.
    3. Reboot with `sudo reboot`.

## TPM vendors and modules

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-infineon[=slb9670\|slb9672\|slb9673]` | disabled | Plain `--enable-infineon` selects SLB9672 and defines `WOLFTPM_SLB9672`. `--enable-infineon=slb9670` defines `WOLFTPM_SLB9670`. `--enable-infineon=slb9673` defines `WOLFTPM_SLB9673` and is I2C only: use `--enable-i2c` and do not pass `--enable-spi`. |
| `--enable-st33`, `--enable-st` | disabled | ST ST33 support. Defines `WOLFTPM_ST33`. The two flags are equivalent. |
| `--enable-microchip`, `--enable-mchp` | disabled | Microchip ATTPM20 support. Defines `WOLFTPM_MICROCHIP`. The two flags are equivalent. |
| `--enable-nuvoton` | disabled | Nuvoton NPCT65x/NPCT75x support. Defines `WOLFTPM_NUVOTON`. |
| `--enable-nations` | disabled | Nations Technology NS350 support. Defines `WOLFTPM_NATIONS`. |
| `--enable-sealsq` | disabled | SealSQ QVault post-quantum TPM support. Defines `WOLFTPM_SEALSQ`. |
| `--enable-autodetect` | on when no vendor module is selected | Runtime module detection. Defines `WOLFTPM_AUTODETECT`. |

Selecting an Infineon device with its argument looks like this:

```sh
./configure --enable-infineon=slb9670
./configure --enable-infineon=slb9673 --enable-i2c
```

## Operating system transports and simulators

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-devtpm` | disabled | Use the Linux kernel driver (`/dev/tpmrm0` or `/dev/tpm0`). Defines `WOLFTPM_LINUX_DEV`. Cannot be combined with swTPM. |
| `--enable-swtpm` | see below | Talk to a simulator over the swtpm TCP protocol. Defines `WOLFTPM_SWTPM` and `TPM2_SWTPM_PORT`. |
| `--enable-swtpm=uart` | disabled | swtpm protocol over a UART serial port, for fwTPM on embedded targets such as STM32H5. Defines `WOLFTPM_SWTPM`, `WOLFTPM_SWTPM_UART` and `TPM2_SWTPM_PORT`, where the port value is the baud rate (default 115200). |
| `--with-swtpm-port=PORT` | 2321 | Sets `TPM2_SWTPM_PORT`. For `--enable-swtpm=uart` it sets the baud rate instead. |
| `--enable-fwtpm` | see below | Build the firmware TPM (fwTPM) server. Requires wolfCrypt. |
| `--enable-winapi` (alias `--enable-wintbs`) | disabled | Use the Windows TBS API. Defines `WOLFTPM_WINAPI`. Cannot be combined with swTPM or devtpm. |

### Default simulator behavior

`--enable-swtpm` and `--enable-fwtpm` are on by default when all of these hold:

- the host CPU is x86_64, amd64 or aarch64;
- the host OS is not Windows (mingw, cygwin, msys, win32);
- wolfCrypt is enabled;
- no hardware path was selected with any of `--enable-spi`, `--enable-i2c`, `--enable-mmio`, `--enable-devtpm`, `--enable-autodetect`, `--enable-winapi`, `--enable-infineon`, `--enable-st`, `--enable-st33`, `--enable-microchip`, `--enable-nuvoton`, `--enable-nations` or `--enable-sealsq`.

This applies to macOS and BSD as well as Linux. Everywhere else the default is off.

!!! warning
    A bare `./configure` on these hosts can define both `WOLFTPM_AUTODETECT` and `WOLFTPM_SWTPM`. `WOLFTPM_SWTPM` suppresses the kernel-device detection, so such a build never tries `/dev/tpmrm0` or `/dev/tpm0`. To use a real TPM, pass `--enable-autodetect`, `--enable-devtpm` or a vendor flag explicitly. Explicit `--enable-autodetect` prevents the simulator default and gives the kernel-first behavior: on Linux it tries `/dev/tpmrm0` or `/dev/tpm0` at runtime and falls back to SPI if the kernel driver is not available.

### fwTPM macros

| Macro | Where it is set |
| --- | --- |
| `WOLFTPM_FWTPM_BUILD` | Added to the generated `options.h` for any fwTPM build. This is the marker that test scripts look for. |
| `WOLFTPM_FWTPM` | Set only on the fwTPM server and fuzz targets. It gates server-side code in the shared sources. |
| `WOLFTPM_FWTPM_HAL`, `WOLFTPM_ADV_IO` | Added for TIS and shared-memory builds, that is fwTPM without `--enable-swtpm`. Not supported on Windows. |

### fwTPM-only and NV modes

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-fwtpm-only` | disabled | Build only the fwTPM server. Skips the client library, wrapper and examples, and defines `WOLFTPM2_NO_WRAPPER`. Implies `--enable-fwtpm` and needs wolfCrypt. Not compatible with `--enable-spdm`. |
| `--enable-fwtpm-nv-appendonly` | disabled | Append-only NV journal mode for write-once flash fwTPM ports. Defines `WOLFTPM_FWTPM_NV_APPEND_ONLY`. |

## SPDM

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-spdm` | disabled | SPDM support. Defines `WOLFTPM_SPDM`. Needs the wolfSPDM submodule: run `git submodule update --init lib/wolfSPDM`. With fwTPM it also defines `WOLFTPM_SPDM_RESPONDER`. |
| `--enable-tcg` | auto under `--enable-spdm` | SPDM TCG Binding mode. Defines `WOLFTPM_SPDM_TCG`. Turned on automatically with fwTPM, Nuvoton or Nations. |
| `--enable-psk` | auto with Nations | SPDM PSK mode. Defines `WOLFTPM_SPDM_PSK`. Requires `--enable-tcg`. |

Related rules enforced by configure:

- `--enable-tcg` and `--enable-psk` require `--enable-spdm`.
- `--enable-nuvoton` with SPDM requires `--enable-tcg` and defines `WOLFSPDM_NUVOTON`.
- `--enable-nations` with SPDM requires both `--enable-tcg` and `--enable-psk` and defines `WOLFSPDM_NATIONS`.
- fwTPM with SPDM requires at least one of `--enable-tcg` or `--enable-psk`.
- `--with-wolfspdm` is removed and now fails configure. Use `--enable-spdm`.
- A debug build with SPDM also defines `WOLFSPDM_DEBUG`.

## Post-quantum (v1.85)

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-v185` | auto-detect | Full TPM 2.0 v1.85 features: ML-DSA and ML-KEM, sign and verify sequence and digest commands, new response codes and capability properties. Defines `WOLFTPM_V185`. Auto-enabled for fwTPM builds when wolfCrypt has both ML-DSA and ML-KEM. |
| `--enable-pqc` | auto-detect | Lean post-quantum subset (ML-DSA and ML-KEM only). Defines `WOLFTPM_PQC`. A fwTPM build promotes it to full v1.85. `--enable-v185` wins if both are given. |
| `--enable-mldsa[=all\|sign-only\|verify-only\|no]` | all | Limit ML-DSA. `sign-only` defines `WOLFTPM_NO_MLDSA_VERIFY`, `verify-only` defines `WOLFTPM_NO_MLDSA_SIGN`, and `no` defines `WOLFTPM_NO_MLDSA`. |
| `--enable-mlkem[=all\|enc\|dec\|no]` | all | Limit ML-KEM. `enc` defines `WOLFTPM_NO_MLKEM_DECAP`, `dec` defines `WOLFTPM_NO_MLKEM_ENCAP`, and `no` defines `WOLFTPM_NO_MLKEM`. |
| `--disable-hash-mldsa` | pre-hash enabled | Drops pre-hash ML-DSA key support. Defines `WOLFTPM_NO_HASH_MLDSA`. |

Use `--disable-v185` or `--disable-pqc` to turn off post-quantum support, including the auto-detect. Setting both `--enable-mldsa=no` and `--enable-mlkem=no` is an error. With wolfCrypt enabled, PQC needs wolfSSL 5.9.2-stable or later built with ML-DSA (`--enable-mldsa`, or the wolfSSL alias `--enable-dilithium`) and ML-KEM (`--enable-mlkem`). With `--disable-wolfcrypt`, PQC is command marshaling only.

## Preprocessor defines

These are not configure options. Set them with `CFLAGS`, for example `./configure CFLAGS="-DWOLFTPM_MAX_RETRIES=3"`.

| Macro | Effect |
| --- | --- |
| `WOLFTPM_USE_SYMMETRIC` | Enables symmetric AES, hashing and HMAC support for the TLS examples. |
| `WOLFTPM2_USE_SW_ECDHE` | Stops the TLS examples from using the TPM for ECC ephemeral key generation and the shared secret. |
| `TLS_BENCH_MODE` | Enables TLS benchmarking mode. |
| `NO_TPM_BENCH` | Disables the TPM benchmarking example. |
| `WOLFTPM2_ECC_DEFAULT_CURVE` | Curve used by the named wrapper templates that do not take an explicit curve, currently SRK and AIK. Defaults to `TPM_ECC_NIST_P256`, or the smallest enabled curve that meets `ECC_MIN_KEY_SZ`. Override with `-DWOLFTPM2_ECC_DEFAULT_CURVE=TPM_ECC_NIST_P384`. `wolfTPM2_GetKeyTemplate_ECC` and `_ECC_ex` take an explicit curve, so this macro does not remap them, except that P-256 is substituted when `NO_ECC256` is set. |
| `WOLFTPM_MAX_RETRIES` | Default number of times a command is resubmitted when the TPM returns `TPM_RC_RETRY` (the TPM is momentarily busy, for example while persisting the `daUsed` flag on first authorization use of an externally provisioned key without `noDA`). Default 0, which is disabled. Opt in at runtime with `TPM2_SetCommandRetries()` or at build time with `-DWOLFTPM_MAX_RETRIES=N`. wolfTPM does not set `noDA` on every key it creates: the generic key-template APIs use the attributes the caller passes in, and the EK template omits `noDA`, so those keys can hit this condition. |
| `WOLFTPM_NO_RETRY` | Compiles out the `TPM_RC_RETRY` resubmit handling. `TPM_RC_RETRY` is returned to the caller. Conflicts with `WOLFTPM_MAX_RETRIES` greater than 0. |
| `WOLFTPM_LOCALITY_DEFAULT` | TIS locality requested at startup (default 0). Change it at runtime with `wolfTPM2_SetLocality()` on SPI, memory-mapped and swtpm transports. The wolfTPM I2C HAL does not implement locality selection and uses locality 0 only, so a non-zero `wolfTPM2_SetLocality()` on I2C returns `NOT_COMPILED_IN`. |
| `WOLFTPM_TIS_RESET_STALE_LOCALITY` | At startup, releases any active locality other than `WOLFTPM_LOCALITY_DEFAULT` so the default can be granted. Recovers a TPM left wedged when a previous session did not release its locality. Off by default. Use only on single-master buses, since on a shared bus it could clear a locality another master holds. The nRST reset HAL is the alternative. |
| `WOLFTPM_LOCALITY_TIMEOUT_TRIES` | Poll attempts when requesting a locality at runtime (default 1000). Kept small so a locality that cannot be granted fails fast. |
| `WOLFTPM_RESET_LINE` | nRST GPIO line number for the reset HAL. Set it with `--enable-hal-reset=LINE`. |

## See Also

- [Building wolfTPM](building.md)
- [System Interfaces](system-interfaces.md)
- [Supported Hardware](supported-hardware.md)
- [Getting Started](getting-started.md)
