# Experimental support for Das U-boot

wolfTPM could be used with all platforms that have hardware SPI support or can use the U-boot software bit-bang implementation(SPI_SOFT).

The example wolfTPM IO Callback was tested on RPI3 model B with ST33 TPM 2.0 module, using `make rpi_3_32b_defconfig` and changes to the DeviceTree as described below in `U-boot preparations`.

https://source.denx.de/u-boot/u-boot

## Current state of TPM support in U-boot

The internal U-boot support for TPM is limited to only several commands:

* TPM2_PCR_Read
* TPM2_PCR_Extend
* TPM2_GetCapability

and few others for maintenance purposes, like TPM2_Clear.

## Using wolfTPM with U-boot

Thanks to wolfTPM, U-boot can perform all TPM 2.0 operations, including TPM2_Seal/Unseal, TPM2_Quote, TPM2_EncryptDecrypt2 and TPM2_NV_Write/TPM2_NV_Read.

### U-boot preparation

wolfTPM has a internal TPM Interface Command(TIS) layer and allows wolfTPM to be used as TPM 2.0 driver for baremetal and embedded systems.

Our example IO callback in examples/tpm_io_uboot.c uses the existing SPI driver in U-boot. It is up to the developer to choose between hardware SPI driver or U-boot's software SPI driver. Best compatibility is offered through the software SPI driver that uses bit-bang GPIO to implement SPI interface. For example, U-boot does not offer hardware SPI for Raspberry Pi boards and other Broadcom SoC systems.

To enable U-boot's software SPI driver make sure to enable SPI_SOFT in your U-boot's configuration manually or using `make menuconfig` under Device Drivers, SPI Support.

Once enabled, it is also needed to add Device Tree entry for SPI Slave device

```

tpm2-spi {

		compatible = "spi-gpio"; /* Selection the SPI_SOFT driver */
		cs-gpios = <&gpio 24 0>; /* Pinout from ST33 RPI Eval Board */
		gpio-sck = <&gpio 23 0>;
		gpio-miso = <&gpio 21 0>;
		gpio-mosi = <&gpio 19 0>;
		spi-delay-us = <10>;
		cs@0 {
		};
	};

```

Note:

U-boot should use the new Driver Model or when initializing wolfTPM in U-boot it is required to pass handle to the SPI device registered as the user context. Example below:

```

struct udevice *uDev = &spiDev; /* replace with correct udevice instance */
WOLFTPM2_DEV tpmDev;
wolfTPM2_Init(&tpmDev, TPM2_IoCb_SPI, uDev);

```

In case U-boot's driver model is used, then the Io Callback will try to automatically acquire the spi device at the default SPI bus.

### wolfTPM compilation

To build static version of wolfTPM for U-boot, use the configure script or use the example options.h file in examples/u-boot.

To use configure:

./configure --disable-shared --enable-autodetect --disable-wolfcrypt

This way u-boot can be later linked together with wolfTPM.

## Benefits of using wolfTPM with U-boot

### Native API

wolfTPM provides native API with full access to all TPM 2.0 commands. For example:

* TPM2_Seal/TPM2_Unseal
* TPM2_DefineSpace/TPM2_UndefineSpace
* TPM2_CreatePrimary/TPM2_Create
* TPM2_EncryptDecrypt2

Internal U-boot TPM support for these commands is missing. By adding wolfTPM the system can perform symmetric and asymmetric key generation, PCR operations, TPM 2.0 Quote, TPM 2.0 Certify Creation, Key import, extra GPIO for safety-critical systems, Signature verification, Hash generation and all other TPM 2.0 capabilities.

### Wrappers

wolfTPM's rich API provides wrappers for performing complete TPM 2.0 operations. There are wolfTPM wrappers for the most common and complex TPM 2.0 operations. The wrappers also protect from wrong TPM 2.0 settings and execute all necessary TPM 2.0 commands to achieve the end goal.

wolfTPM wrappers also provide templates for the most commonly used types of TPM 2.0 keys.

Please contact us at facts@wolfssl.com if you are interested in using wolfTPM with U-boot.

## Adding wolfTPM Commands to U-Boot

### 1. Configuration

Enable wolfTPM support in U-Boot by adding these options to your board's defconfig:

```
CONFIG_TPM=y
CONFIG_TPM_V2=y
CONFIG_TPM_WOLF=y
CONFIG_CMD_WOLFTPM=y
```

Or use `make menuconfig` and enable:
- Device Drivers → TPM → TPM 2.0 Support
- Device Drivers → TPM → wolfTPM Support
- Command line interface → Security commands → Enable wolfTPM commands

### 2. SPI Configuration

Configure SPI for your TPM module. Either:

a) Hardware SPI - Enable your board's SPI controller
b) Software SPI - Enable bit-banging SPI:
```
CONFIG_SPI_SOFT=y
```

### 3. Device Tree Configuration

Add TPM device to your board's device tree (example for ST33 on RPi3):

```dts
tpm2-spi {
    compatible = "spi-gpio";    /* For software SPI */
    cs-gpios = <&gpio 24 0>;    /* CS pin */
    gpio-sck = <&gpio 23 0>;    /* Clock pin */
    gpio-miso = <&gpio 21 0>;   /* MISO pin */
    gpio-mosi = <&gpio 19 0>;   /* MOSI pin */
    spi-delay-us = <10>;        /* SPI timing */
    cs@0 {
    };
};
```

## wolfTPM U-Boot Commands

wolfTPM extends U-Boot with additional TPM 2.0 commands for enhanced security and key management capabilities.

### Available Commands

The following commands are available through the `wolftpm` interface:

```
wolftpm <command> [arguments]
```

#### Commands:

* `caps` - Display TPM capabilities and information
  - Shows manufacturer and vendor information
  - Displays firmware version and security certifications
  - Lists available PCR banks and algorithms
  - Shows active persistent handles
  - Useful for verifying TPM configuration and status

* `help` - Display available commands

Example output:
```
=> wolftpm caps
TPM2 Get Capabilities
TPM2: Caps 0x00000000, Did 0x0000, Vid 0x0000, Rid 0x 0
Session 0: Edit
	Handle 0x0 -> 0x40000009
	Attributes 0x0 -> 0x0
Command size: 22
	80 01 00 00 00 16 00 00 01 7a 00 00 00 06 00 00 | .........z......
	01 05 00 00 00 08                               | ......
Response size: 83
	80 01 00 00 00 53 00 00 00 00 01 00 00 00 06 00 | .....S..........
	00 00 08 00 00 01 05 49 42 4d 00 00 00 01 06 53 | .......IBM.....S
	57 20 20 00 00 01 07 20 54 50 4d 00 00 01 08 00 | W  .... TPM.....
	00 00 00 00 00 01 09 00 00 00 00 00 00 01 0a 00 | ................
	00 00 01 00 00 01 0b 20 24 01 25 00 00 01 0c 00 | ....... $.%.....
	12 00 00                                        | ...
Command size: 22
	80 01 00 00 00 16 00 00 01 7a 00 00 00 06 00 00 | .........z......
	01 2d 00 00 00 01                               | .-....
Response size: 27
	80 01 00 00 00 1b 00 00 00 00 01 00 00 00 06 00 | ................
	00 00 01 00 00 01 2d 00 00 00 00                | ......-....
Mfg IBM (0), Vendor SW   TPM, Fw 8228.293 (0x120000), FIPS 140-2 0, CC-EAL4 0
Command size: 22
	80 01 00 00 00 16 00 00 01 7a 00 00 00 01 81 00 | .........z......
	00 00 00 00 00 fe                               | ......
Response size: 19
	80 01 00 00 00 13 00 00 00 00 00 00 00 00 01 00 | ................
	00 00 00                                        | ...
Handles Cap: Start 0x81000000, Count 0
Found 0 persistent handles
Command size: 22
	80 01 00 00 00 16 00 00 01 7a 00 00 00 05 00 00 | .........z......
	00 00 00 00 00 01                               | ......
Response size: 43
	80 01 00 00 00 2b 00 00 00 00 00 00 00 00 05 00 | .....+..........
	00 00 04 00 04 03 ff ff ff 00 0b 03 ff ff ff 00 | ................
	0c 03 ff ff ff 00 0d 03 ff ff ff                | ...........
Assigned PCR's:
	SHA1:  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23
	SHA256:  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23
Command size: 12
	80 01 00 00 00 0c 00 00 01 45 00 00             | .........E..
Response size: 10
	80 01 00 00 00 0a 00 00 00 00                   | ..........
wolfTPM2_Shutdown complete
Command size: 12
	80 01 00 00 00 0c 00 00 01 45 00 00             | .........E..
Response size: 10
	80 01 00 00 00 0a 00 00 00 00                   | ..........
```

More commands will be added in future releases to support additional TPM 2.0 operations including:
- Key generation and management
- PCR operations
- NV storage access
- Cryptographic operations

## Building and Running wolfTPM with U-Boot using QEMU

You can follow the steps here to get a qemu uboot console environment.
https://docs.u-boot.org/en/stable/board/emulation/qemu-arm.html

how to use it with tpm
1. get swtpm
either
```
sudo apt install swtpm
```
or
```
git clone git@github.com:stefanberger/swtpm.git
cd swtpm
./autogen.sh
make
```

2. Now that you have swtpm you can start and make U-boot using these steps:
```
make distclean
export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=aarch64
make qemu_arm64_defconfig
make -j4
```

3. Make dir for tpm from U-boot root.
```
mkdir -p /tmp/mytpm1
```

4. In a first console invoke swtpm with:
```
swtpm socket --tpm2 --tpmstate dir=/tmp/mytpm1 --ctrl type=unixio,path=/tmp/mytpm1/swtpm-sock --log level=20
```

5. In a second console invoke qemu-system-aarch64 with:
```
qemu-system-aarch64 -machine virt -nographic -cpu cortex-a57 -bios u-boot.bin -chardev socket,id=chrtpm,path=/tmp/mytpm1/swtpm-sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis-device,tpmdev=tpm0
```

5. Enable the TPM on U-Boot's command line with:
```
tpm autostart
```

To exit the QEMU you can do ctrl-A and then press X
