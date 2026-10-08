# Building wolfTPM

wolfTPM is built on top of wolfSSL (wolfCrypt) and can be built with autotools, CMake, or directly into a bare-metal project using a `user_settings.h` file. This page covers each build method. Per-vendor build steps are on the [Supported Hardware](supported-hardware.md) page, and the full list of configure switches is on the [Build Options](build-options.md) page.

## Building wolfSSL

wolfSSL must be built and installed first. It can be downloaded from the [downloads page](https://wolfssl.com/download/) or cloned from GitHub:

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm
make
sudo make install
sudo ldconfig
```

`autogen.sh` requires automake and libtool: `sudo apt-get install automake libtool`.

The `--enable-wolftpm` option is equivalent to passing these options:

```bash
./configure --enable-certgen --enable-certreq --enable-certext \
    --enable-pkcs7 --enable-cryptocb --enable-aescfb
```

## Using an alternate wolfSSL directory

To build wolfTPM against a wolfSSL installed in a non-default location, install wolfSSL to a prefix and point wolfTPM at it with `--with-wolfcrypt`:

```bash
# cd /your-wolfssl-repo
./autogen.sh # as necessary
./configure --prefix=~/workspace/my_wolfssl_bin --enable-all
make install

# then for some other library such as wolfTPM:

# cd /your-wolftpm-repo
./configure --enable-swtpm --with-wolfcrypt=~/workspace/my_wolfssl_bin
```

## Building with autotools

Once wolfSSL is installed, download wolfTPM from the [downloads page](https://wolfssl.com/download/) or clone it from GitHub, then build it:

```bash
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM
./autogen.sh
./configure
make
```

Add the options you need to `./configure`. For example, `--enable-devtpm` uses the Linux kernel TPM device, and `--enable-swtpm` uses a TPM simulator. See [Build Options](build-options.md) for the list, and [Supported Hardware](supported-hardware.md) for the options each TPM module needs.

On Linux x86_64 and aarch64, a bare `./configure` auto-enables the software TPM backends so that `make check` works without hardware. See [System Interfaces](system-interfaces.md).

## Building using CMake

CMake supports compiling in many environments, including Visual Studio if CMake support is installed. The commands below can be run in a `Developer Command Prompt`.

```bash
mkdir build
cd build
# to use installed wolfSSL location (library and headers)
cmake .. -DWITH_WOLFSSL=/prefix/to/wolfssl/install/
# OR to use a wolfSSL source tree
cmake .. -DWITH_WOLFSSL_TREE=/path/to/wolfssl/
# build
cmake --build .
```

Use `-DWITH_WOLFSSL=` when wolfSSL is already installed (library and headers), or `-DWITH_WOLFSSL_TREE=` to build against a wolfSSL source tree.

## Bare-metal build

wolfTPM can be built for bare-metal embedded environments where no operating system is present. In this approach you compile the wolfTPM source files directly into your project instead of using autotools or CMake. It is common for microcontrollers such as ARM Cortex-M, RISC-V, UltraScale+/Versal, Microblaze, and others.

### Prerequisites

- wolfCrypt library source code
- wolfTPM library source code
- A TPM 2.0 module connected via SPI (or I2C)

### Step 1: Define preprocessor macros

Add these preprocessor macros to your project build settings or compiler command line:

```
WOLFTPM_USER_SETTINGS
WOLFSSL_USER_SETTINGS
```

These macros tell wolfTPM and wolfSSL to look for a `user_settings.h` file instead of using the autoconf-generated `options.h` file.

### Step 2: Create a user_settings.h file

Create a `user_settings.h` file in your project that contains the build configuration options for both wolfSSL and wolfTPM. A reference configuration file is available in the wolfSSL repository: [examples/configs/user_settings_wolftpm.h](https://github.com/wolfSSL/wolfssl/blob/master/examples/configs/user_settings_wolftpm.h).

Example `user_settings.h` for wolfTPM:

```c
/* System */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED
#define WOLFCRYPT_ONLY
#define SIZEOF_LONG_LONG 8

/* Platform - bare metal */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM
#define NO_ERROR_STRINGS
#define NO_SIG_WRAPPER

/* wolfTPM required features */
#define WOLF_CRYPTO_CB
#define WOLFSSL_PUBLIC_MP
#define WOLFSSL_AES_CFB
#define HAVE_AES_DECRYPT

/* ECC options */
#define HAVE_ECC
#define ECC_TIMING_RESISTANT

/* RSA options */
#undef NO_RSA
#define WOLFSSL_KEY_GEN
#define WC_RSA_BLINDING

/* Big math library */
#define WOLFSSL_SP_MATH_ALL /* sp_int.c */
#define WOLFSSL_SP_SMALL
#define SP_INT_BITS 4096
/* #define SP_WORD_SIZE 32 */

/* SHA options: SHA-256 stays enabled, so do not define NO_SHA256 */
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384

/* Disable unneeded features to reduce footprint */
#define NO_PKCS8
#define NO_PKCS12
#define NO_PWDBASED
#define NO_DSA
#define NO_DES3
#define NO_RC4
#define NO_PSK
#define NO_MD4
#define NO_MD5
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256
#define NO_DH

/* Other interesting size reduction options */
#if 0
    #define RSA_LOW_MEM
    #define WOLFSSL_AES_SMALL_TABLES
    #define USE_SLOW_SHA
    #define USE_SLOW_SHA256
    #define USE_SLOW_SHA512
    #define NO_AES_192
#endif

/* Custom random seed source - implement your own */
#define HAVE_HASHDRBG
#define CUSTOM_RAND_GENERATE_SEED my_rng_seed
```

!!! warning
    The `NO_*` macros disable algorithms. wolfTPM wrappers and sessions need SHA-256, so never define `NO_SHA256` in this file.

If you use `CUSTOM_RAND_GENERATE_SEED`, implement your own RNG seed function. This example gets the seed from the TPM with parameter encryption enabled:

```c
int my_rng_seed(byte* seed, word32 sz)
{
    int rc;

    /* enable parameter encryption for the RNG request */
    rc = wolfTPM2_SetAuthSession(&wolftpm_dev, 0, &wolftpm_session,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
        TPMA_SESSION_continueSession));
    if (rc == 0) {
        rc = wolfTPM2_GetRandom(&wolftpm_dev, seed, sz);
    }
    wolfTPM2_UnsetAuthSession(&wolftpm_dev, 0, &wolftpm_session);
    return rc;
}
```

### Step 3: Configure include paths

Add these directories to your project's include paths:

1. The wolfSSL root directory, for example `/path/to/wolfssl`
2. The wolfTPM root directory, for example `/path/to/wolftpm`
3. The directory that holds your `user_settings.h`

Example compiler flags:

```
-I/path/to/wolfssl
-I/path/to/wolftpm
-I/path/to/your/project/include
```

### Step 4: Add source files

Add the required source files from wolfSSL and wolfTPM to your project.

wolfCrypt source files (minimum required for wolfTPM):

```
wolfssl/wolfcrypt/src/aes.c
wolfssl/wolfcrypt/src/asn.c
wolfssl/wolfcrypt/src/cryptocb.c
wolfssl/wolfcrypt/src/ecc.c
wolfssl/wolfcrypt/src/hash.c
wolfssl/wolfcrypt/src/hmac.c
wolfssl/wolfcrypt/src/random.c
wolfssl/wolfcrypt/src/rsa.c
wolfssl/wolfcrypt/src/sha.c
wolfssl/wolfcrypt/src/sha256.c
wolfssl/wolfcrypt/src/sha512.c
wolfssl/wolfcrypt/src/sp_int.c
wolfssl/wolfcrypt/src/wc_port.c
wolfssl/wolfcrypt/src/wolfmath.c
```

wolfTPM source files:

```
wolftpm/src/tpm2.c
wolftpm/src/tpm2_packet.c
wolftpm/src/tpm2_tis.c
wolftpm/src/tpm2_wrap.c
wolftpm/src/tpm2_param_enc.c
```

### Step 5: Implement the SPI HAL callback

wolfTPM needs a single SPI transmit and receive callback to communicate with the TPM module. Implement it for your hardware platform. Reference implementations are in the `hal/` directory of the wolfTPM repository:

- [hal/tpm_io_xilinx.c](https://github.com/wolfSSL/wolfTPM/blob/master/hal/tpm_io_xilinx.c) for Xilinx Microblaze
- [hal/tpm_io_stm32.c](https://github.com/wolfSSL/wolfTPM/blob/master/hal/tpm_io_stm32.c) for STM32
- [hal/tpm_io_infineon.c](https://github.com/wolfSSL/wolfTPM/blob/master/hal/tpm_io_infineon.c) for Infineon Tricore
- [hal/tpm_io_microchip.c](https://github.com/wolfSSL/wolfTPM/blob/master/hal/tpm_io_microchip.c) for Microchip

#### Standard I/O callback

The standard SPI callback has this signature:

```c
typedef int (*TPM2HalIoCb)(
    TPM2_CTX* ctx,
    const byte* txBuf, byte* rxBuf,
    word16 xferSz,
    void* userCtx
);
```

Example implementation:

```c
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_tis.h>

int TPM2_IoCb(TPM2_CTX* ctx,
    const byte* txBuf, byte* rxBuf, word16 xferSz,
    void* userCtx)
{
    int ret = TPM_RC_FAILURE;

    /* TODO: Assert SPI chip select */
    spi_cs_assert();

    /* Perform SPI transfer: send txBuf and receive into rxBuf */
    if (spi_transfer(txBuf, rxBuf, xferSz) == 0) {
        ret = TPM_RC_SUCCESS;
    }

    /* TODO: De-assert SPI chip select */
    spi_cs_deassert();

    (void)ctx;
    (void)userCtx;

    return ret;
}
```

#### Advanced I/O callback

For platforms that need more control, enable `WOLFTPM_ADV_IO` to use the advanced callback:

```c
typedef int (*TPM2HalIoCb)(
    TPM2_CTX* ctx,
    INT32 isRead, UINT32 addr,
    BYTE* xferBuf, UINT16 xferSz,
    void* userCtx
);
```

This gives access to the register address and the read or write direction, for platforms that need separate read and write operations.

### Step 6: Initialize and use wolfTPM

After the setup is complete, initialize wolfTPM and start communicating with the TPM:

```c
#include <wolftpm/tpm2_wrap.h>

int main(void)
{
    int rc;
    WOLFTPM2_DEV dev;

    /* Initialize wolfTPM */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        /* Handle error */
        return rc;
    }

    /* Get TPM capabilities */
    WOLFTPM2_CAPS caps;
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    if (rc == TPM_RC_SUCCESS) {
        /* Use TPM ... */
    }

    /* Cleanup */
    wolfTPM2_Cleanup(&dev);

    return 0;
}
```

### Optional build configurations

To reduce the memory footprint in constrained environments, consider these options in `user_settings.h`:

```c
/* Reduce stack usage */
#define WOLFTPM_SMALL_STACK

/* Disable wrapper layer if using native API only */
#define WOLFTPM2_NO_WRAPPER

/* Use smaller RSA key sizes only */
#define MAX_RSA_BITS 2048
```

If you know your TPM module type at compile time, select it. Select exactly one module variant, not several:

```c
/* For Infineon, pick exactly one of these */
#define WOLFTPM_SLB9670
/* #define WOLFTPM_SLB9672 */
/* #define WOLFTPM_SLB9673 */

/* For ST ST33 */
#define WOLFTPM_ST33

/* For Nuvoton */
#define WOLFTPM_NUVOTON

/* For Microchip ATTPM20 */
#define WOLFTPM_MICROCHIP
```

If no module is specified, wolfTPM attempts to auto-detect it at runtime using `WOLFTPM_AUTODETECT` (the default).

For TPM modules connected via I2C instead of SPI:

```c
#define WOLFTPM_I2C
#define WOLFTPM_ADV_IO
```

You must implement the advanced I/O callback for I2C communication.

### Cryptographic key storage

In bare-metal environments, the TPM provides secure storage for cryptographic keys, isolated from main processor memory. Key material never leaves the TPM in plaintext form.

- Keys created with `TPM2_CreatePrimary` reside in the TPM and return a handle.
- Keys created with `TPM2_Create` return an encrypted blob that can be stored in non-volatile memory and reloaded using `TPM2_Load`.
- Use `TPM2_EvictControl` to store keys persistently in the TPM NVRAM.

This keeps cryptographic keys protected even if the main processor memory is compromised.

### Troubleshooting

SPI communication issues:

1. Verify SPI clock polarity and phase (typically CPOL=0, CPHA=0 for a TPM).
2. Check the SPI clock speed. Start slow (1 to 10 MHz) and increase.
3. Verify chip select is asserted low during the entire send and receive.
4. Some TPMs require wait states during SPI operations, which means extra bytes are read until the MSB is set to signal response readiness (enabled with `WOLFTPM_CHECK_WAIT_STATE`).
5. Enable debug output with `DEBUG_WOLFTPM` (general), `WOLFTPM_DEBUG_VERBOSE` (detailed), or `WOLFTPM_DEBUG_IO` (SPI and I2C transactions).

Build errors:

1. Ensure `WOLFSSL_USER_SETTINGS` and `WOLFTPM_USER_SETTINGS` are defined.
2. Verify the include paths are correct.
3. Check that all required source files are included in the build.

## See Also

- [Getting Started](getting-started.md)
- [Build Options](build-options.md)
- [Supported Hardware](supported-hardware.md)
- [System Interfaces](system-interfaces.md)
