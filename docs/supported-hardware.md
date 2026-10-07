# Supported Hardware

wolfTPM talks to TPM 2.0 parts over SPI or I2C through a single HAL IO callback, or to a system TPM through the operating system driver. This page lists the platform used by the examples, the hardware wolfTPM has been tested with, the configure flag for each part, and the build steps for each vendor.

## Platform

The examples in this library are written for use on a Raspberry Pi and use the Linux `spidev` interface (`/dev/spidev0.0`).

For interfacing to your hardware bus (SPI or I2C), a single HAL callback is used. It is configured on initialization when calling `TPM2_Init` or `wolfTPM2_Init`. See [HAL IO Callback](hal-io-callback.md) for the callback model.

Example HAL implementations are provided in the `hal` directory for:

* Atmel ASF
* Barebox
* Espressif ESP-IDF
* Infineon TriCore
* Linux
* STM32 CubeMX
* wolfHAL
* Xilinx

An advanced IO option (`--enable-advio` or `WOLFTPM_ADV_IO`) adds the register address and a read/write flag as parameters to the IO callback. This is required for I2C support.

## Tested Hardware

wolfTPM has been tested with:

* Infineon OPTIGA(TM) Trusted Platform Module 2.0 SLB9670, SLB9672 and SLB9673 (I2C).
    * LetsTrust is a vendor of TPM development boards (http://letstrust.de).
* STMicro STSAFE-TPM, ST33TPHF2XSPI, ST33TPHF2XI2C and ST33KTPM2X (SPI and I2C)
* Microchip ATTPM20 module
* Nuvoton NPCT65X or NPCT75x TPM 2.0 modules
* Nations Technologies Z32H330 or NS350 TPM 2.0 modules
* SealSQ QVault TPM 2.0 module (SPI, post-quantum ML-DSA and ML-KEM)
* NVIDIA Jetson Orin (Tegra234) firmware TPM: a TPM 2.0 running as an OP-TEE trusted application, reached through the Linux kernel driver rather than a bus. See `docs/DEVTPM.md` in the source tree.

The first line of example output identifies the part (capabilities, device ID, vendor ID, revision, firmware version). See [TPM 2.0 Overview](tpm2-overview.md) for how to capture and read the device identification.

## Supported Parts

| Vendor | Part(s) | Bus | configure flag | Notes |
| ------ | ------- | --- | -------------- | ----- |
| Infineon | SLB9670 | SPI | `--enable-infineon=slb9670` | Max SPI clock 43 MHz. No wait states needed. AES key size limited to 128 bits. |
| Infineon | SLB9672 | SPI | `--enable-infineon` | Default for SPI. Max SPI clock 33 MHz. Supports firmware upgrade. |
| Infineon | SLB9673 | I2C | `--enable-infineon --enable-i2c` | Default for I2C. Uses the SLB9672 SPI clock default. |
| STMicro | ST33KTPM2X, ST33TPHF2X | SPI or I2C | `--enable-st33 [--enable-i2c] [--enable-firmware]` | Max SPI clock 33 MHz. Wait states required. `--enable-firmware` adds the `st33_fw_update` tool. |
| Microchip | ATTPM20 | SPI | `--enable-microchip` | Rated to 36 MHz, but wolfTPM uses 33 MHz because of issues at the higher rate. Wait states required. |
| Nuvoton | NPCT650, NPCT750 | SPI | `--enable-nuvoton` | Max SPI clock 43 MHz. Wait states required. |
| Nations Technologies | Z32H330, NS350 | SPI | `--enable-nations` | The NS350 needs `WOLFTPM_CHECK_WAIT_STATE`, which is on by default. |
| SealSQ | QVault TPM 2.0 | SPI | `--enable-sealsq` | Post-quantum algorithms in silicon. Max SPI clock 33 MHz. Wait states required. |
| NVIDIA | Jetson Orin (Tegra234) firmware TPM | None (kernel driver) | `--enable-autodetect` or `--enable-devtpm` | Accessed through `/dev/tpmrm0`. No bus flag. |

!!! note
    With `--enable-autodetect`, wolfTPM turns on wait state checking and caps the SPI clock at 33 MHz, the lowest maximum of the supported parts.

The SPI clock limits above are the defaults for each part in `wolftpm/tpm2_types.h`. They can be overridden by defining `TPM2_SPI_MAX_HZ`.

## Building per Vendor

All builds start from a clone of the repository:

```sh
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM
```

### Infineon

Supports SLB9670 or SLB9672 (SPI) and SLB9673 (I2C).

```sh
./autogen.sh
./configure --enable-infineon [--enable-i2c]
make
```

The default is SLB9672 (SPI) or SLB9673 (when I2C is enabled). To select the SLB9670, use `--enable-infineon=slb9670`.

### ST ST33

```sh
./autogen.sh
./configure --enable-st33 [--enable-i2c] [--enable-firmware]
make
```

The `--enable-firmware` option enables firmware upgrade support for ST33 TPMs. It adds the `st33_fw_update` example tool.

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

Use `./configure` with the defaults. All Nations TPM 2.0 modules are compatible, and `--enable-nations` selects the part-specific settings. The NS350 Raspberry Pi TPM 2.0 module uses `/dev/spidev0.0`. TPM wait states are required and are on by default through `WOLFTPM_CHECK_WAIT_STATE`.

### SealSQ QVault

Build with `--enable-sealsq`. The post-quantum build options are covered in [Post-Quantum Support](post-quantum.md).

### Espressif ESP-IDF

See the wolfTPM-specific settings in the wolfSSL `user_settings.h` file, typically found in `[project]/components/wolfssl/include`.

```sh
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM/IDE/Espressif

# set your path to ESP-IDF, shown here for VisualGDB using v5.2
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2

. ${WRK_IDF_PATH}/export.sh
idf.py build
```

## See Also

* [HAL IO Callback](hal-io-callback.md)
* [TPM 2.0 Overview](tpm2-overview.md)
* [Post-Quantum Support](post-quantum.md)
