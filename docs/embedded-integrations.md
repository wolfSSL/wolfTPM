# Embedded Integrations

This page collects the platform and IDE integrations shipped with wolfTPM: Espressif ESP-IDF, Zephyr, QNX, IAR Embedded Workbench, Visual Studio, and Das U-Boot. For the STM32 Cube Pack, see [STM32CubeIDE](stm32cube.md).

## Espressif ESP-IDF

The Espressif project lives in `IDE/Espressif`. Wolf-specific settings for wolfTPM are in the wolfSSL `user_settings.h` file, typically found in `[project]/components/wolfssl/include`.

Build from a shell with ESP-IDF available (shown here for VisualGDB using v5.2):

```sh
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM/IDE/Espressif

# set your path to ESP-IDF
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2

. ${WRK_IDF_PATH}/export.sh
idf.py build
```

### Memory

The initial minimum memory requirement is 35KB of stack. See `sdkconfig.defaults`. The memory currently assigned is 50960.

### Pin Assignments (I2C)

The following pin assignments are used by default. You can change them in `menuconfig`.

| | SDA | SCL |
| --- | --- | --- |
| ESP I2C Master | I2C_MASTER_SDA | I2C_MASTER_SCL |
| TPM2 Device | SDA | SCL |

For the default values of `I2C_MASTER_SDA` and `I2C_MASTER_SCL`, see `Example Configuration` in `menuconfig`. No external pull-up resistors are needed on SDA and SCL, because the driver enables the internal pull-ups.

### Troubleshooting I2C

- Printing to the UART during an I2C transaction can affect timing and cause errors.
- Make sure the TPM module has been reset after a flash update.
- Check the wiring: `SCL` to `SCL`, `SDA` to `SDA`. Also connect GND. Vcc is 3.3V only.
- Make sure the proper pins are connected on the ESP32. The default SCL is `GPIO 19` and the default SDA is `GPIO 18`.
- Test with a single I2C device before testing alongside other I2C boards.
- When using multiple I2C boards, check for appropriate pull-ups. See the data sheet.
- Reset the TPM device again. Press the button on the TPM SLB9673 eval board, or set TPM pin 17 as appropriate.

## Zephyr

The Zephyr port is in the `zephyr` directory of the wolfTPM source tree. It targets the [Zephyr Project](https://www.zephyrproject.org/) and provides the following:

| Path | Contents |
| --- | --- |
| `modules/lib/wolftpm` | wolfTPM library code |
| `modules/lib/wolftpm/zephyr/` | Configuration and CMake files for wolfTPM as a Zephyr module |
| `modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_caps` | wolfTPM capabilities sample application |
| `modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_test` | wolfTPM wrapper test application |

### Set Up as a Zephyr Module

Follow the [Zephyr getting started guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html) to set up a Zephyr project. Then add wolfTPM as a project in your `west.yml`:

```yaml
manifest:
  remotes:
    # <your other remotes>
    - name: wolftpm
      url-base: https://github.com/wolfssl

  projects:
    # <your other projects>
    - name: wolftpm
      path: modules/lib/wolftpm
      revision: master
      remote: wolftpm
```

!!! note
    wolfTPM depends on wolfSSL, so also add wolfSSL to the `west.yml` in the same way.

Update west's modules:

```sh
west update
```

West now recognizes wolftpm as a module and includes its Kconfig and `CMakeLists.txt` in the build system.

### Build and Run the Wrap Test

To build apps without running `west zephyr-export`, set `CMAKE_PREFIX_PATH` to the location of the Zephyr SDK and build from the `zephyr` directory. For example:

```sh
CMAKE_PREFIX_PATH=/path/to/zephyr-sdk-<VERSION> west build -p always -b qemu_x86 ../modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_test/
```

Build and run `wolftpm_wrap_test`:

```sh
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_test
west build -t run
```

### Build and Run the Capabilities Sample

Build and run `wolftpm_wrap_caps`:

```sh
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_caps
west build -t run
```

## QNX

These steps create a QNX Momentics project that uses wolfTPM over the QNX SPI driver. The files are in `IDE/QNX`.

### Create a QNX Application

1. Create folders for libraries (`lib`) and includes (`inc`).
2. Add the library sources to the `lib` directory as `wolfssl` and `wolftpm`.
3. Edit the Makefile to build the sources and include directories:

```
# wolfSSL and wolfTPM library includes/sources
INCLUDES += -I./inc -I./lib/wolftpm -I./lib/wolfssl
CCFLAGS_all += -DWOLFSSL_USER_SETTINGS -DWOLFTPM_USER_SETTINGS

SRCS += $(call wildcard, lib/wolfssl/wolfcrypt/src/*.c)
SRCS += $(call wildcard, lib/wolfssl/wolfcrypt/src/port/arm/*.c)
SRCS += $(call wildcard, lib/wolfssl/wolfcrypt/src/port/xilinx/*.c)
SRCS += $(call wildcard, lib/wolftpm/src/*.c)

# The QNX SPI Driver
LIBS += -lspi-master
```

4. Create `inc/user_settings.h` for all wolf-specific settings. Here is a template:

```c
#ifndef WOLF_USER_SETTINGS_H
#define WOLF_USER_SETTINGS_H

/* TPM */
#define WOLFTPM_AUTODETECT
#define WOLFTPM_CHECK_WAIT_STATE
#define WOLFTPM_ADV_IO /* use advanced IO HAL callback */
#define TPM_TIMEOUT_TRIES 100000

/* always perform self-test (some chips require) */
#define WOLFTPM_PERFORM_SELFTEST

/* Reduce stack use */
#define MAX_COMMAND_SIZE    1024
#define MAX_RESPONSE_SIZE   1350
#define MAX_DIGEST_BUFFER   896

/* Debugging */
#if 1
   #define DEBUG_WOLFTPM
   //#define WOLFTPM_DEBUG_VERBOSE
   //#define WOLFTPM_DEBUG_IO
   //#define WOLFTPM_DEBUG_TIMEOUT
#endif

/* Platform */
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_IGNORE_FILE_WARN
#define WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MAX

/* Math */
#define ECC_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT
#define USE_FAST_MATH
#define FP_MAX_BITS (2 * 4096)
#define WOLFSSL_NO_HASH_RAW
#define ALT_ECC_SIZE

/* Enables */
#define HAVE_ECC
#define ECC_SHAMIR
#define HAVE_AESGCM
#define GCM_TABLE_4BIT

/* Disables */
#define NO_MAIN_DRIVER
#define NO_WOLFSSL_MEMORY
#define NO_ASN
#define NO_ASN_TIME
#define NO_CODING
#define NO_CERTS
#define NO_PSK

#define NO_PWDBASED
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_HC128
#define NO_RABBIT
#define NO_DES3

#endif /* !WOLF_USER_SETTINGS_H */
```

5. For the wolfTPM HAL, use `tpm_io.c` directly or copy the required HAL interface into your own `.c` file. See [HAL I/O Callback](hal-io-callback.md).
6. Add the wolfTPM example code to your own `.c` file.
7. Consider the QNX BSP SPI master patch below. It lets multiple calls run with chip select asserted, which the SPI wait states require.

### QNX SPI Master Patch for Manual Chip Select

Edit the following QNX BSP files.

1. `bsp/src/hardware/spi/xzynq/aarch64/dll.le.zcu102/xzynq_spi.c`:

```diff
@@ -442,7 +442,7 @@ static void xzynq_setup(xzynq_spi_t *dev, uint32_t device)
     spi_debug1("%s: CONFIG_SPI_REG = 0x%x", __func__, dev->ctrl[id]);
 #endif

-    if(dev->fcs) {
+    if(dev->fcs || (devlist[id].cfg.mode & SPI_MODE_MAN_CS)) {
         out32(base + XZYNQ_SPI_CR_OFFSET, dev->ctrl[id] | XZYNQ_SPI_CR_MAN_CS);
     } else {
         out32(base + XZYNQ_SPI_CR_OFFSET, dev->ctrl[id]);
@@ -621,7 +621,7 @@ void *xzynq_xfer(void *hdl, uint32_t device, uint8_t *buf, int *len)
         reset = 1;
     }

-    if(!dev->fcs) {
+    if(!dev->fcs && !(devlist[id].cfg.mode & SPI_MODE_MAN_CS)) {
         xzynq_spi_slave_select(dev, id, 0);
     }
```

2. `bsp/src/hardware/spi/xzynq/config.c`:

```diff
@@ -72,6 +73,16 @@ int xzynq_cfg(void *hdl, spi_cfg_t *cfg, int cs)
     /* Enable ModeFail generation */
     ctrl |= XZYNQ_SPI_CR_MFAIL_EN;

+    if (cfg->mode & SPI_MODE_MAN_CS)
+        ctrl |= XZYNQ_SPI_CR_MAN_CS; /* enable manual CS mode */
+
+    if (cfg->mode & SPI_MODE_CLEAR_CS) {
+        /* make sure all chip selects are de-asserted */
+        /* set all CS bits high to de-assert */
+        out32(base + XZYNQ_SPI_CR_OFFSET,
+            in32(base + XZYNQ_SPI_CR_OFFSET) | XZYNQ_SPI_CR_CS);
+    }
+
```

3. `target/qnx7/usr/include/hw/spi-master.h`:

```diff
@@ -71,6 +71,8 @@ typedef struct {
 #define	SPI_MODE_RDY_LEVEL		(2 << 14)	/* Low level signal */
 #define	SPI_MODE_IDLE_INSERT	(1 << 16)
+#define	SPI_MODE_MAN_CS			(1 << 17)   /* Manual Chip select */
+#define	SPI_MODE_CLEAR_CS		(1 << 18)   /* Clear all chip selects (used with SPI_MODE_MAN_CS) */

 #define	SPI_MODE_LOCKED			(1 << 31)	/* The device is locked by another client */
```

For questions, email support@wolfssl.com.

## IAR-EWARM

The `IDE/IAR-EWARM` directory holds an IAR Embedded Workbench for ARM project for the TPM 2.0 wrapper API. It has no README.

| Path | Contents |
| --- | --- |
| `ewarm-tpm2.eww` | IAR workspace |
| `ewarm-tpm2.ewp` | IAR project |
| `source/main.c` | Application entry point |
| `source/tpm_main.c` | TPM example code using `wolftpm/tpm2.h` and `wolftpm/tpm2_wrap.h` |
| `header/tpm_main.h` | Header for the example code |

Open `ewarm-tpm2.eww` in IAR Embedded Workbench to build. The example uses fixed handles for the storage key (`0x81000000`), RSA key (`0x81000010`), RSA public key (`0x81000011`), and an NV certificate index (`0x01800000`).

!!! note
    This section needs expansion: required wolfSSL and wolfTPM settings, the HAL used, and tested IAR versions.

## Visual Studio

The `IDE/VisualStudio` directory has a Visual Studio solution, `wolftpm.sln`, with projects for building wolfSSL, wolfTPM, and some examples: `wolfssl.vcxproj`, `wolftpm.vcxproj`, `wrap_test.vcxproj`, `wolfcrypt_test.vcxproj`, and `tls_server.vcxproj`. The solution and projects are based on Visual Studio 2015 and can be retargeted to a newer version when opened.

All build settings are in `IDE/VisualStudio/user_settings.h`. The projects assume the `wolftpm` and `wolfssl` directories sit next to each other.

The solution supports the FIPS Ready bundle from the wolfSSL website. To use it, enable the `#if 0` FIPS section in `user_settings.h`. See `wolfssl/IDE/WIN10/README.txt` in the wolfSSL source for how to set the FIPS integrity check in `fips_test.c` at run time.

!!! note
    This section needs expansion: step-by-step build instructions and the TPM interface used on Windows. For TBS, see [Windows TBS](system-interfaces.md).

## U-Boot

wolfTPM provides experimental support for Das U-Boot, with these features:

- Uses the software SPI driver in U-Boot for TPM communication.
- Implements TPM 2.0 driver functionality through its internal TIS layer.
- Provides native API access to all TPM 2.0 commands.
- Includes the wrapper API for common TPM 2.0 operations.
- Supports two integration paths:
  - `__linux__`: uses the existing tpm interface through `tpm2_linux.c`.
  - `__UBOOT__`: direct SPI communication through `tpm_io_uboot.c`.

The example files are in `examples/u-boot`.

### U-Boot Commands

These commands are available through the `wolftpm` interface.

Basic commands:

| Command | Description |
| --- | --- |
| `help` | Show help text. |
| `device [num device]` | Show all devices or set the specified device. |
| `info` | Show information about the TPM. |
| `state` | Show internal state from the TPM, if available. |
| `autostart` | Initialize the TPM, perform a Startup(clear), and run a full selftest sequence. |
| `init` | Initialize the software stack. Must be the first command. |
| `startup <mode> [<op>]` | Issue a TPM2_Startup command. `<mode>` is `TPM2_SU_CLEAR` (reset state) or `TPM2_SU_STATE` (preserved state). `[<op>]` is an optional shutdown with "off". |
| `self_test <type>` | Test TPM capabilities. `<type>` is "full" (all tests) or "continue" (untested tests only). |

PCR operations:

| Command | Description |
| --- | --- |
| `pcr_extend <pcr> <digest_addr> [<digest_algo>]` | Extend a PCR with a digest. |
| `pcr_read <pcr> <digest_addr> [<digest_algo>]` | Read a PCR to memory. |
| `pcr_allocate <algorithm> <on/off> [<password>]` | Reconfigure a PCR bank algorithm. |
| `pcr_setauthpolicy` or `pcr_setauthvalue <pcr> <key> [<password>]` | Change the PCR access key. |
| `pcr_print` | Print the current PCR state. |

Security management:

| Command | Description |
| --- | --- |
| `clear <hierarchy>` | Issue TPM2_Clear. `<hierarchy>` is `TPM2_RH_LOCKOUT` or `TPM2_RH_PLATFORM`. |
| `change_auth <hierarchy> <new_pw> [<old_pw>]` | Change a hierarchy password. `<hierarchy>` is `TPM2_RH_LOCKOUT`, `TPM2_RH_ENDORSEMENT`, `TPM2_RH_OWNER`, or `TPM2_RH_PLATFORM`. |
| `dam_reset [<password>]` | Reset the internal error counter. |
| `dam_parameters <max_tries> <recovery_time> <lockout_recovery> [<password>]` | Set dictionary attack mitigation (DAM) parameters. |
| `caps` | Show TPM capabilities and info. |

Firmware management:

| Command | Description |
| --- | --- |
| `firmware_update <manifest_addr> <manifest_sz> <firmware_addr> <firmware_sz>` | Update the TPM firmware. |
| `firmware_cancel` | Cancel a TPM firmware update. |

### Enable wolfTPM in U-Boot

Add these options to your board's defconfig:

```
CONFIG_TPM=y
CONFIG_TPM_V2=y
CONFIG_TPM_WOLF=y
CONFIG_CMD_WOLFTPM=y
```

Or use `make menuconfig` and enable:

- Device Drivers, TPM, TPM 2.0 Support
- Device Drivers, TPM, wolfTPM Support
- Command line interface, Security commands, Enable wolfTPM commands

### Build and Run with QEMU

This procedure runs U-Boot with wolfTPM under QEMU, using a TPM simulator.

1. Install swtpm:

```sh
git clone git@github.com:stefanberger/swtpm.git
cd swtpm
./autogen.sh
make
```

2. Build U-Boot:

```sh
make distclean
export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=aarch64
make qemu_arm64_defconfig
make -j4
```

3. Create the TPM state directory:

```sh
mkdir -p /tmp/mytpm1
```

4. Start swtpm in the first terminal:

```sh
swtpm socket --tpm2 --tpmstate dir=/tmp/mytpm1 --ctrl type=unixio,path=/tmp/mytpm1/swtpm-sock --log level=20
```

5. Start QEMU in a second terminal:

```sh
qemu-system-aarch64 -machine virt -nographic -cpu cortex-a57 -bios u-boot.bin -chardev socket,id=chrtpm,path=/tmp/mytpm1/swtpm-sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis-device,tpmdev=tpm0
```

6. Example boot output:

```
U-Boot 2025.07-rc1-ge15cbf232ddf-dirty (May 06 2025 - 16:25:56 -0700)

DRAM:  128 MiB
using memory 0x46658000-0x47698000 for malloc()
Core:  52 devices, 15 uclasses, devicetree: board
Flash: 64 MiB
Loading Environment from Flash... *** Warning - bad CRC, using default environment

In:    serial,usbkbd
Out:   serial,vidconsole
Err:   serial,vidconsole
No USB controllers found
Net:   eth0: virtio-net#32

Hit any key to stop autoboot:  0
=> tpm2 help
tpm2 - Issue a TPMv2.x command

Usage:
tpm2 <command> [<arguments>]

device [num device]
    Show all devices or set the specified device
info
    Show information about the TPM.
```

7. Example commands:

```
=> tpm2 info
tpm_tis@0 v2.0: VendorID 0x1014, DeviceID 0x0001, RevisionID 0x01 [open]
=> tpm2 startup TPM2_SU_CLEAR
=> tpm2 get_capability 0x6 0x20e 0x200 1
Capabilities read from TPM:
Property 0x6a2e45a9: 0x6c3646a9
=> tpm2 pcr_read 10 0x100000
PCR #10 sha256 32 byte content (20 known updates):
 20 25 73 0a 00 56 61 6c 75 65 3a 0a 00 23 23 20
 4f 75 74 20 6f 66 20 6d 65 6d 6f 72 79 0a 00 23
```

8. To exit QEMU, press Ctrl-A followed by X.

## See Also

- [STM32CubeIDE](stm32cube.md)
- [Building](building.md)
- [System Interfaces](system-interfaces.md)
- [HAL I/O Callback](hal-io-callback.md)
- [Supported Hardware](supported-hardware.md)
- [Windows TBS](system-interfaces.md)
