# Supported Hardware

wolfTPM talks to TPM 2.0 parts over SPI or I2C through a single HAL I/O callback, or to a system TPM through the operating system driver. This page lists the platforms wolfTPM has HAL backends for, the hardware it has been tested with, the configure flag for each part, and the build steps for each vendor.

## Platform

The hardware examples are most often run on a Raspberry Pi using the Linux `spidev` interface. That is the example platform, not a requirement. The Linux HAL picks a default SPI chip select per vendor: Infineon builds use `/dev/spidev0.1`, while Microchip, ST, Nuvoton, Nations Technologies and SEALSQ builds use `/dev/spidev0.0`. Override the device with `TPM2_SPI_DEV_PATH` and `TPM2_SPI_DEV_CS` if your wiring differs.

To interface with your hardware bus (SPI or I2C), wolfTPM uses a single HAL callback. You pass it during initialization when calling `TPM2_Init` or `wolfTPM2_Init`. See [HAL IO Callback](hal-io-callback.md) for the callback model.

Example HAL implementations are provided in the `hal` directory for:

* Atmel ASF (`tpm_io_atmel.c`)
* Barebox (`tpm_io_barebox.c`)
* Espressif ESP-IDF (`tpm_io_espressif.c`)
* Firmware TPM (`tpm_io_fwtpm.c`)
* Infineon TriCore and PSoC/CyHAL (`tpm_io_infineon.c`)
* Linux SPI and I2C (`tpm_io_linux.c`)
* Memory-mapped I/O (`tpm_io_mmio.c`)
* Microchip Harmony (`tpm_io_microchip.c`)
* QNX (`tpm_io_qnx.c`)
* STM32 CubeMX (`tpm_io_st.c`)
* U-Boot (`tpm_io_uboot.c`)
* wolfHAL (`tpm_io_wolfhal.c`)
* Xilinx (`tpm_io_xilinx.c`)
* Zephyr (`tpm_io_zephyr.c`)

An advanced I/O option (`--enable-advio` or `WOLFTPM_ADV_IO`) adds the register address and a read/write flag as parameters to the I/O callback. This is required for I2C support, and `--enable-i2c` turns it on.

## Tested Hardware

wolfTPM has been tested with:

* Infineon OPTIGA(TM) Trusted Platform Module 2.0 SLB9670 (SPI), SLB9672 (SPI) and SLB9673 (I2C).
    * [LetsTrust](https://letstrust.de) is a vendor of TPM development boards.
* STMicroelectronics ST33KTPM2XSPI, ST33KTPM2I, ST33TPHF2XSPI (SPI) and ST33TPHF2XI2C (I2C).
* Microchip ATTPM20 module.
* Nuvoton NPCT650 and NPCT750 TPM 2.0 modules.
* Nations Technologies Z32H330 and NS350 TPM 2.0 modules.
* SEALSQ QVault TPM 2.0 module (SPI, post-quantum ML-DSA and ML-KEM).
* NVIDIA Jetson Orin (Tegra234) firmware TPM: a TPM 2.0 running as an OP-TEE trusted application, reached through the Linux kernel driver rather than a bus. See [System Interfaces](system-interfaces.md).

The firmware updater also recognizes the ST33KTPM2A firmware line, but that part is not in the tested list.

Device identification is printed in two steps. A direct bus connection first prints a `TPM2: Caps ... Did ... Vid ... Rid` line read from the TIS registers. A second `Mfg ...` line then reports the manufacturer, vendor string, firmware version and certification flags. A firmware TPM has no TIS registers, so it prints only the second line. See [TPM 2.0 Overview](tpm2-overview.md) for captured output from each tested module.

## Supported Parts

| Vendor | Part(s) | Bus | configure flag | Notes |
| ------ | ------- | --- | -------------- | ----- |
| Infineon | SLB9670 | SPI | `--enable-infineon=slb9670` | Library SPI clock default 43 MHz. AES key size limited to 128 bits. |
| Infineon | SLB9672 | SPI | `--enable-infineon` | Default for SPI. Library SPI clock default 33 MHz. Supports firmware upgrade. |
| Infineon | SLB9673 | I2C | `--enable-infineon=slb9673 --enable-i2c --enable-advio` | I2C only, so no SPI clock applies. |
| STMicroelectronics | ST33KTPM2XSPI, ST33TPHF2XSPI | SPI | `--enable-st33` | Library SPI clock default 33 MHz. Wait states required. |
| STMicroelectronics | ST33KTPM2I, ST33TPHF2XI2C | I2C | `--enable-st33 --enable-i2c` | Wait states required. Firmware upgrade support is on by default. |
| Microchip | ATTPM20 | SPI | `--enable-microchip` | Library SPI clock default 33 MHz. Wait states required. |
| Nuvoton | NPCT650, NPCT750 | SPI | `--enable-nuvoton` | Library SPI clock default 43 MHz. Wait states required. |
| Nations Technologies | Z32H330, NS350 | SPI | `--enable-nations` | Wait states required (`WOLFTPM_CHECK_WAIT_STATE`, enabled for Nations builds). |
| SEALSQ | QVault TPM 2.0 | SPI | `--enable-sealsq` | Library SPI clock default 33 MHz. Wait states required. Post-quantum commands also need `--enable-pqc` or `--enable-v185`. |
| NVIDIA | Jetson Orin (Tegra234) firmware TPM | None (kernel driver) | `--enable-autodetect` or `--enable-devtpm` | Accessed through `/dev/tpmrm0`, falling back to `/dev/tpm0`. No bus flag. |

The SPI clocks in this table are library defaults from `wolftpm/tpm2_types.h`, not the electrical limits of each part. The part limits are set by the vendor datasheets and can be lower or higher:

* **Infineon SLB9670:** 43 MHz is allowed only at 3.3 V with a sufficiently fast SCLK edge. The limit is lower at 1.8 V or with slower edges.
* **Infineon SLB9672:** the datasheet gives 33 MHz nominal and 34.65 MHz maximum.
* **STMicroelectronics:** ST33KTPM2X supports up to 66 MHz, ST33KTPM2I up to 48 MHz and ST33TPHF2XSPI up to 33 MHz. wolfTPM uses 33 MHz for all ST parts.
* **Microchip ATTPM20:** rated to 36 MHz, but wolfTPM uses 33 MHz because of issues at the higher rate.
* **SEALSQ QVault:** the datasheet lists 33 MHz in its summary and 36 MHz in its timing table. wolfTPM uses the conservative 33 MHz.

!!! note
    The part limits above come from vendor datasheets and were not checked against code in this repository. Confirm them against the current datasheet for your part.

To change the SPI clock, define `TPM2_SPI_MAX_HZ` at build time, for example `CFLAGS="-DTPM2_SPI_MAX_HZ=20000000"`. The default for a selected vendor is set in `wolftpm/tpm2_types.h`. I2C builds on Linux default to 400 kHz (`TPM2_I2C_HZ`).

## Autodetect and the Kernel Device

When no vendor flag is given, `--enable-autodetect` is on by default. It detects the module at run time. With autodetect, wolfTPM turns on wait state checking and caps the SPI clock at 33 MHz, the lowest default among the supported parts. This cap applies when wolfTPM falls back to direct SPI access, where it tries `/dev/spidev0.0` through `/dev/spidev0.4`.

On Linux, autodetect and `--enable-devtpm` first try the kernel TPM device. The driver opens `/dev/tpmrm0` (the resource manager, kernel 5.12 and later) and falls back to `/dev/tpm0` if it is not present. Define `WOLFTPM_USE_TPMRM` to use only the resource manager, or set `TPM2_LINUX_DEV` to pin a specific device. See [System Interfaces](system-interfaces.md).

## Building per Vendor

All builds start from a clone of the repository:

```sh
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM
```

### Infineon

Supports SLB9670 or SLB9672 (SPI) and SLB9673 (I2C). Pick one of the following.

SLB9672 on SPI (the default for `--enable-infineon`):

```sh
./autogen.sh
./configure --enable-infineon
make
```

SLB9670 on SPI:

```sh
./autogen.sh
./configure --enable-infineon=slb9670
make
```

SLB9673 on I2C:

```sh
./autogen.sh
./configure --enable-infineon=slb9673 --enable-i2c --enable-advio
make
```

### STMicroelectronics ST33

SPI parts (ST33KTPM2XSPI, ST33TPHF2XSPI):

```sh
./autogen.sh
./configure --enable-st33
make
```

I2C parts (ST33KTPM2I, ST33TPHF2XI2C):

```sh
./autogen.sh
./configure --enable-st33 --enable-i2c
make
```

Firmware upgrade support is enabled by default (`--enable-firmware`), which builds the `st33_fw_update` example tool. Pass `--disable-firmware` to leave it out.

Raspberry Pi wiring: the ST33KTPM2X SPI device is `/dev/spidev0.0`, with nRST (active low) on GPIO24 (pin 18). Nuvoton uses GPIO4. You can optionally drive nRST from code with `--enable-hal-reset` and `TPM2_IoCb_Reset()`. See [HAL IO Callback](hal-io-callback.md).

### Microchip ATTPM20

```sh
./autogen.sh
./configure --enable-microchip
make
```

### Nuvoton

```sh
./autogen.sh
./configure --enable-nuvoton
make
```

### Nations Technologies

Pass `--enable-nations`. Without it, a default `./configure` does not define `WOLFTPM_NATIONS`, so the Nations settings and vendor commands are not built. Z32H330 and NS350 are the tested modules. The NS350 Raspberry Pi TPM 2.0 module uses `/dev/spidev0.0`. Wait states are required and are turned on for Nations builds through `WOLFTPM_CHECK_WAIT_STATE`.

```sh
./autogen.sh
./configure --enable-nations
make
```

### SEALSQ QVault

Build with `--enable-sealsq` for the ordinary TPM commands. The ML-DSA and ML-KEM commands are gated separately, so also pass `--enable-pqc` (lean post-quantum subset) or `--enable-v185` (full v1.85 command set), which require a wolfSSL build with ML-DSA and ML-KEM. The post-quantum build options are covered in [Post-Quantum Support](post-quantum.md).

```sh
./autogen.sh
./configure --enable-sealsq --enable-pqc
make
```

### Espressif ESP-IDF

The ESP-IDF component needs a wolfSSL source tree. If CMake cannot find one, it stops with the error "Could not find wolfssl". Place a wolfSSL checkout in a parent directory named `wolfssl`, `wolfssl-master` or `wolfssl-<user>`, or point the `WOLFSSL_ROOT` variable at it. The wolfSSL ESP Registry managed component also works as an alternative.

The wolfTPM-specific settings are in the wolfSSL `user_settings.h` file, typically found in `[project]/components/wolfssl/include`.

```sh
git clone https://github.com/wolfSSL/wolfssl.git
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM/IDE/Espressif

# set your path to ESP-IDF, shown here for VisualGDB using v5.2
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2

. "${WRK_IDF_PATH}/export.sh"
idf.py build
```

## See Also

* [HAL IO Callback](hal-io-callback.md)
* [System Interfaces](system-interfaces.md)
* [TPM 2.0 Overview](tpm2-overview.md)
* [Post-Quantum Support](post-quantum.md)
