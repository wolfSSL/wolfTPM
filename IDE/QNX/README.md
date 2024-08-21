# wolfTPM with QNX

Instructions for creating a QNX Momentics wolfTPM Project...

## Create a new QNX Application

1) Create folder for libraries (lib) and includes (inc)
2) Add library sources into "lib" directory as "wolfssl" and "wolftpm"
3) Edit Makefile to build sources and include directories.

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

4) Create `inc/user_settings.h` for all wolf specific settings:

Here is a template:

```
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

5) wolfTPM HAL: Use either `tpm_io.c` directly or copy the required HAL interface into your own .c.

6) Add wolfTPM example code into your own .c.

7) Consider QNX BSP SPI master patch for handling multiple calls with CS asserted, which is required for the SPI wait states.

## QNX SPI Master Patch for Manual Chip Select

Edit the following QNX BSP files:

1) `bsp/src/hardware/spi/xzynq/aarch64/dll.le.zcu102/xzynq_spi.c`

```
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

2) `bsp/src/hardware/spi/xzynq/config.c`

```
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

3) `target/qnx7/usr/include/hw/spi-master.h`

```
@@ -71,6 +71,8 @@ typedef struct {
 #define	SPI_MODE_RDY_LEVEL		(2 << 14)	/* Low level signal */
 #define	SPI_MODE_IDLE_INSERT	(1 << 16)
+#define	SPI_MODE_MAN_CS			(1 << 17)   /* Manual Chip select */
+#define	SPI_MODE_CLEAR_CS		(1 << 18)   /* Clear all chip selects (used with SPI_MODE_MAN_CS) */

 #define	SPI_MODE_LOCKED			(1 << 31)	/* The device is locked by another client */
```

## Support

For questions please email support@wolfssl.com
