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
