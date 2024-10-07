# wolfTPM (TPM 2.0)

Portable TPM 2.0 project designed for embedded use.


## Project Features

* This implementation provides all TPM 2.0 API's in compliance with the specification.
* Wrappers provided to simplify Key Generation/Loading, RSA encrypt/decrypt, ECC sign/verify, ECDH, NV, Hashing/HACM, AES, Sealing/Unsealing, Attestation, PCR Extend/Quote and Secure Root of Trust.
* Testing done using TPM 2.0 modules from STMicro ST33 (SPI/I2C), Infineon OPTIGA SLB9670/SLB9672, Microchip ATTPM20, Nations Tech Z32H330TC/NS350 and Nuvoton NPCT650/NPCT750.
* wolfTPM uses the TPM Interface Specification (TIS) to communicate either over SPI, or using a memory mapped I/O range.
* wolfTPM can also use the Linux TPM kernel interface (`/dev/tpmX`) to talk with any physical TPM on SPI, I2C and even LPC bus.
* Platform support for Raspberry Pi (Linux), MMIO, STM32 with CubeMX, Atmel ASF, Xilinx, QNX Infineon TriCore and Barebox.
* The design allows for easy portability to different platforms:
    * Native C code designed for embedded use.
    * Single IO callback for hardware SPI interface.
    * No external dependencies.
    * Compact code size and minimal memory use.
* Includes example code for:
    * Most TPM2 native API's
    * All TPM2 wrapper API's
    * PKCS 7
    * Certificate Signing Request (CSR)
    * TLS Client
    * TLS Server
    * Use of the TPM's Non-volatile memory
    * Attestation (activate and make credential)
    * Benchmarking TPM algorithms and TLS
    * Key Generation (primary, RSA/ECC and symmetric), loading and storing to flash (NV memory)
    * Sealing and Unsealing data with an RSA key or externally signed policy.
    * Time signed or set
    * PCR read/reset
    * GPIO configure, read and write.
    * Endrosement Key/Cert retreival and validation.
* Parameter encryption support using AES-CFB or XOR.
* Support for salted unbound authenticated sessions.
* Support for HMAC Sessions.
* Support for reading Endorsement certificates (EK Credential Profile).

Note: See [examples/README.md](examples/README.md) for details on using the examples.


## TPM 2.0 Overview

### Hierarchies

```
Platform    TPM_RH_PLATFORM
Owner       TPM_RH_OWNER
Endorsement TPM_RH_ENDORSEMENT
```

Each hierarchy has their own manufacture generated seed.

The arguments used on `TPM2_Create` or `TPM2_CreatePrimary` create a template, which is fed into a KDF to produce the same key based hierarchy used. The key generated is the same each time; even after reboot. The generation of a new RSA 2048 bit key takes about 15 seconds. Typically these are created and then stored in NV using `TPM2_EvictControl`. Each TPM generates their own keys uniquely based on the seed.

There is also an Ephemeral hierarchy (`TPM_RH_NULL`), which can be used to create ephemeral keys.

### Platform Configuration Registers (PCRs)

Contains hash digests for SHA-1 and SHA-256 with an index 0-23. These hash digests can be extended to prove the integrity of a boot sequence (secure boot).


### Terminology

This project uses the terms append vs. marshall and parse vs. unmarshall.

Acronyms:
* HAL: Hardware Abstraction Layer.
* NV: Non-Volatile memory.
* TPM: Trusted Platform Module.

## Platform

The examples in this library are written for use on a Raspberry Pi and use the `spi_dev` interface.

### IO Callback (HAL)

See the HAL manual in [hal/README.md](hal/README.md).

For interfacing to your hardware interface (SPI/I2C) a single HAL callback is used and configuration on initialization when calling `TPM2_Init` or `wolfTPM2_Init`.

There are HAL examples in `hal` directory for:

* Atmel ASF
* BareBox
* Espressif ESP-IDF
* Infineon TriCore
* Linux
* STM32 CubeMX
* Xilinx

We also support an advanced IO option (`--enable-advio`/`WOLFTPM_ADV_IO`), which adds the register and read/write flag as parameter to the IO callback. This is required for I2C support.

### Hardware

Tested with:

* Infineon OPTIGA (TM) Trusted Platform Module 2.0 SLB9670, SLB9672 and SLB9673 (I2C).
    - LetsTrust: Vendor for TPM development boards [http://letstrust.de](http://letstrust.de).
* STMicro STSAFE-TPM, ST33TPHF2XSPI/2XI2C and ST33KTPM2X (SPI and I2C)
* Microchip ATTPM20 module
* Nuvoton NPCT65X or NPCT75x TPM2.0 modules
* Nations Technologies Z32H330 or NS350 TPM 2.0 modules

#### Device Identification

Infineon SLB9670:
TPM2: Caps 0x30000697, Did 0x001b, Vid 0x15d1, Rid 0x10
Mfg IFX (1), Vendor SLB9670, Fw 7.85 (4555), FIPS 140-2 1, CC-EAL4 1

Infineon SLB9672:
TPM2: Caps 0x30000697, Did 0x001d, Vid 0x15d1, Rid 0x36
Mfg IFX (1), Vendor SLB9672, Fw 16.10 (0x4068), FIPS 140-2 1, CC-EAL4 1

Infineon SLB9673:
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a), FIPS 140-2 1, CC-EAL4 1

STMicro ST33KTPM2XSPI
TPM2: Caps 0x30000415, Did 0x0003, Vid 0x104a, Rid 0x 0
Mfg STM  (2), Vendor ST33KTPM2XSPI, Fw 9.256 (0x0), FIPS 140-2 1, CC-EAL4 0

STMicro ST33TPHF2XSPI
TPM2: Caps 0x1a7e2882, Did 0x0000, Vid 0x104a, Rid 0x4e
Mfg STM  (2), Vendor , Fw 74.8 (1151341959), FIPS 140-2 1, CC-EAL4 0

STMicro ST33TPHF2XI2C
TPM2: Caps 0x1a7e2882, Did 0x0000, Vid 0x104a, Rid 0x4e
Mfg STM  (2), Vendor , Fw 74.9 (1151341959), FIPS 140-2 1, CC-EAL4 0

Microchip ATTPM20
TPM2: Caps 0x30000695, Did 0x3205, Vid 0x1114, Rid 0x 1
Mfg MCHP (3), Vendor , Fw 512.20481 (0), FIPS 140-2 0, CC-EAL4 0

Nations Technologies Inc. Z32H330 TPM 2.0 module
Mfg NTZ (0), Vendor Z32H330, Fw 7.51 (419631892), FIPS 140-2 0, CC-EAL4 0

Nations Technologies Inc. NS350 TPM 2.0 module
TPM2: Caps 0x30000615, Did 0x0701, Vid 0x9999, Rid 0x 1
Mfg NSG (0), Vendor NS350, Fw 30.30 (0x24042510), FIPS 140-2 1, CC-EAL4 0

Nuvoton NPCT650 TPM2.0
Mfg NTC (0), Vendor rlsNPCT , Fw 1.3 (65536), FIPS 140-2 0, CC-EAL4 0

Nuvoton NPCT750 TPM2.0
TPM2: Caps 0x30000697, Did 0x00fc, Vid 0x1050, Rid 0x 1
Mfg NTC (0), Vendor NPCT75x"!!4rls, Fw 7.2 (131072), FIPS 140-2 1, CC-EAL4 0

## Building

### Building wolfSSL

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm
make
sudo make install
sudo ldconfig
```

autogen.sh requires: automake and libtool: `sudo apt-get install automake libtool`

### Building wolfSSL with an alternate directory

```bash
# cd /your-wolfssl-repo
./autogen.h # as necessary
./configure --prefix=~/workspace/my_wolfssl_bin --enable-all
make install

# then for some other library such as wolfTPM:

# cd /your-wolftpm-repo
./configure --enable-swtpm --with-wolfcrypt=~/workspace/my_wolfssl_bin
```

### Build options and defines

```text
--enable-debug          Add debug code/turns off optimizations (yes|no|verbose|io) - DEBUG_WOLFTPM, WOLFTPM_DEBUG_VERBOSE, WOLFTPM_DEBUG_IO
--enable-examples       Enable Examples (default: enabled)
--enable-wrapper        Enable wrapper code (default: enabled) - WOLFTPM2_NO_WRAPPER
--enable-wolfcrypt      Enable wolfCrypt hooks for RNG, Auth Sessions and Parameter encryption (default: enabled) - WOLFTPM2_NO_WOLFCRYPT
--enable-advio          Enable Advanced IO (default: disabled) - WOLFTPM_ADV_IO
--enable-i2c            Enable I2C TPM Support (default: disabled, requires advio) - WOLFTPM_I2C
--enable-checkwaitstate Enable TIS / SPI Check Wait State support (default: depends on chip) - WOLFTPM_CHECK_WAIT_STATE
--enable-smallstack     Enable options to reduce stack usage
--enable-tislock        Enable Linux Named Semaphore for locking access to SPI device for concurrent access between processes - WOLFTPM_TIS_LOCK

--enable-autodetect     Enable Runtime Module Detection (default: enable - when no module specified) - WOLFTPM_AUTODETECT
--enable-infineon       Enable Infineon SLB9670/SLB9672/SLB9673 TPM Support (default: disabled) - WOLFTPM_SLB9670 / WOLFTPM_SLB9672
--enable-st             Enable ST ST33 Support (default: disabled) - WOLFTPM_ST33
--enable-microchip      Enable Microchip ATTPM20 Support (default: disabled) - WOLFTPM_MICROCHIP
--enable-nuvoton        Enable Nuvoton NPCT65x/NPCT75x Support (default: disabled) - WOLFTPM_NUVOTON

--enable-devtpm         Enable using Linux kernel driver for /dev/tpmX (default: disabled) - WOLFTPM_LINUX_DEV
--enable-swtpm          Enable using SWTPM TCP protocol. For use with simulator. (default: disabled) - WOLFTPM_SWTPM
--enable-winapi         Use Windows TBS API. (default: disabled) - WOLFTPM_WINAPI

WOLFTPM_USE_SYMMETRIC   Enables symmetric AES/Hashing/HMAC support for TLS examples.
WOLFTPM2_USE_SW_ECDHE   Disables use of TPM for ECC ephemeral key generation and shared secret for TLS examples.
TLS_BENCH_MODE          Enables TLS benchmarking mode.
NO_TPM_BENCH            Disables the TPM benchmarking example.
```

Note: For the I2C support on Raspberry Pi you may need to enable I2C. Here are the steps:
1. Edit `sudo vim /boot/config.txt`
2. Uncomment `dtparam=i2c_arm=on`
3. Reboot `sudo reboot`


### Building Infineon

Support for SLB9670 or SLB9672 (SPI) / SLB9673 (I2C)

Build wolfTPM:

```bash
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM
./autogen.sh
./configure --enable-infineon [--enable-i2c]
make
```

The default is SLB9672/SLB9673 (if I2C). To specify SLB9670 use `--enable-infineon=slb9670`.

### Building ST ST33

Build wolfTPM:

```bash
./autogen.sh
./configure --enable-st33 [--enable-i2c]
make
```

### Building Microchip ATTPM20

Build wolfTPM:

```bash
./autogen.sh
./configure --enable-microchip
make
```

### Building Nuvoton

Build wolfTPM:

```bash
./autogen.sh
./configure --enable-nuvoton
make
```

### Building Nations Tech

Use `./configure` with defaults. All TPM 2.0 modules are compatible.
The Nations NS350 Raspberry Pi TPM 2.0 module uses `/dev/spidev0.0`. The TPM wait states are required (on by default with WOLFTPM_CHECK_WAIT_STATE).

### Building Espressif ESP-IDF

See the wolfTPM-specific settings in the wolfSSL `user_settings.h` file, typically found in `[project]/components/wolfssl/include`.

```bash
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM/IDE/Espressif

# set your path to ESP-IDF, shown here for VisualGDB using v5.2
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2

. ${WRK_IDF_PATH}/export.sh
idf.py build
```

### Building for "/dev/tpmX"

The `--enable-devtpm` or `WOLFTPM_LINUX_DEV` build option allows you to use the Linux supplied TPM (TIS) driver.

To specify a different `/dev/tpmX` device use `CFLAGS="-DTPM2_LINUX_DEV=/dev/tpm1"`

```bash
./autogen.sh
./configure --enable-devtpm
make
```

The `TPM2_Init` or `wolfTPM2_Init` calls should use NULL for the HAL IO callback argument. The default HAL IO `TPM2_IoCb` maps to a macro specifying NULL (`#define TPM2_IoCb NULL`) in tpm_io.h for the devtpm option.

By default the `/dev/tpmX` requires sudo permissions to use it. If using the tpm2-tss it will install a "tss" group that you can add permissions to `sudo adduser [username] tss`.

To add your own custom wolfTPM rule for /dev/tpm0 do the following:

1) Create new group and add your user to it (replace "[username]" with yours):

```bash
sudo addgroup wolftpm
sudo adduser [username] wolftpm
sudo chgrp wolftpm /dev/tpm0
```

2) Create new rule file: `sudo vim /etc/udev/rules.d/wolftpm-udev.rules`

3) Add the following rule to file:

```
KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", GROUP="wolftpm"
```

4) Reboot or reload rules: `sudo udevadm control -R`


### Building for SWTPM

See `docs/SWTPM.md`

### Building for Windows TBS API

See `docs/WindowTBS.md`

## Building using CMake

CMake supports compiling in many environments including Visual Studio
if CMake support is installed. The commands below can be run in
`Developer Command Prompt`.

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

## Running Examples

These examples demonstrate features of a TPM 2.0 module. The examples create RSA and ECC keys in NV for testing using handles defined in `./hal/tpm_io.h`. The PKCS #7 and TLS examples require generating CSR's and signing them using a test script. See `examples/README.md` for details on using the examples. To run the TLS sever and client on same machine you must build with `WOLFTPM_TIS_LOCK` to enable concurrent access protection.

### TPM2 Capabilities

Simple test that gets TPM capabilities and search for any persistent handles.

```
./examples/wrap/caps
TPM2 Get Capabilities
wolfSSL Entering wolfCrypt_Init
Mfg NSG (0), Vendor NS350, Fw 30.30 (0x24042510), FIPS 140-2 1, CC-EAL4 0
Found 2 persistent handles
```

### TPM2 Wrapper Tests

```
./examples/wrap/wrap_test
TPM2 Demo for Wrapper API's
Mfg STM  (2), Vendor , Fw 74.8 (1151341959), FIPS 140-2 1, CC-EAL4 0
RSA Encrypt/Decrypt Test Passed
RSA Encrypt/Decrypt OAEP Test Passed
RSA Key 0x80000000 Exported to wolf RsaKey
wolf RsaKey loaded into TPM: Handle 0x80000000
RSA Private Key Loaded into TPM: Handle 0x80000000
ECC Sign/Verify Passed
ECC DH Test Passed
ECC Verify Test Passed
ECC Key 0x80000000 Exported to wolf ecc_key
wolf ecc_key loaded into TPM: Handle 0x80000000
ECC Private Key Loaded into TPM: Handle 0x80000000
NV Test on index 0x1800200 with 1024 bytes passed
Hash SHA256 test success
HMAC SHA256 test success
Encrypt/Decrypt (known key) test success
Encrypt/Decrypt test success
```

### TPM2 Benchmarks

Note: Key Generation is using existing template from hierarchy seed.

Run on Infineon OPTIGA SLB9670 at 43MHz:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
RNG                 16 KB took 1.140 seconds,   14.033 KB/s
Benchmark symmetric AES-128-CBC-enc not supported!
Benchmark symmetric AES-128-CBC-dec not supported!
Benchmark symmetric AES-256-CBC-enc not supported!
Benchmark symmetric AES-256-CBC-dec not supported!
Benchmark symmetric AES-128-CTR-enc not supported!
Benchmark symmetric AES-128-CTR-dec not supported!
Benchmark symmetric AES-256-CTR-enc not supported!
Benchmark symmetric AES-256-CTR-dec not supported!
Benchmark symmetric AES-256-CFB-enc not supported!
Benchmark symmetric AES-256-CFB-dec not supported!
SHA1               138 KB took 1.009 seconds,  136.783 KB/s
SHA256             138 KB took 1.009 seconds,  136.763 KB/s
RSA     2048 key gen        5 ops took 10.981 sec, avg 2196.230 ms, 0.455 ops/sec
RSA     2048 Public       113 ops took 1.005 sec, avg 8.893 ms,   112.449 ops/sec
RSA     2048 Private        7 ops took 1.142 sec, avg 163.207 ms,   6.127 ops/sec
RSA     2048 Pub  OAEP     73 ops took 1.011 sec, avg 13.848 ms,   72.211 ops/sec
RSA     2048 Priv OAEP      6 ops took 1.004 sec, avg 167.399 ms,   5.974 ops/sec
ECC      256 key gen        5 ops took 1.157 sec, avg 231.350 ms,   4.322 ops/sec
ECDSA    256 sign          15 ops took 1.033 sec, avg 68.865 ms,   14.521 ops/sec
ECDSA    256 verify         9 ops took 1.022 sec, avg 113.539 ms,   8.808 ops/sec
ECDHE    256 agree          5 ops took 1.161 sec, avg 232.144 ms,   4.308 ops/sec
```

Run on Infineon OPTIGA SLB9672 at 43MHz:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
RNG                 24 KB took 1.070 seconds,   22.429 KB/s
Benchmark symmetric AES-128-CBC-enc not supported!
Benchmark symmetric AES-128-CBC-dec not supported!
Benchmark symmetric AES-256-CBC-enc not supported!
Benchmark symmetric AES-256-CBC-dec not supported!
Benchmark symmetric AES-128-CTR-enc not supported!
Benchmark symmetric AES-128-CTR-dec not supported!
Benchmark symmetric AES-256-CTR-enc not supported!
Benchmark symmetric AES-256-CTR-dec not supported!
AES-128-CFB-enc     86 KB took 1.001 seconds,   85.890 KB/s
AES-128-CFB-dec     88 KB took 1.020 seconds,   86.267 KB/s
AES-256-CFB-enc     86 KB took 1.023 seconds,   84.073 KB/s
AES-256-CFB-dec     86 KB took 1.019 seconds,   84.370 KB/s
SHA1                88 KB took 1.021 seconds,   86.155 KB/s
SHA256              86 KB took 1.015 seconds,   84.717 KB/s
SHA384              90 KB took 1.007 seconds,   89.405 KB/s
RSA     2048 key gen       10 ops took 15.677 sec, avg 1567.678 ms, 0.638 ops/sec
RSA     2048 Public       110 ops took 1.000 sec, avg 9.095 ms, 109.951 ops/sec
RSA     2048 Private       14 ops took 1.078 sec, avg 76.996 ms, 12.988 ops/sec
RSA     2048 Pub  OAEP     51 ops took 1.012 sec, avg 19.838 ms, 50.408 ops/sec
RSA     2048 Priv OAEP     12 ops took 1.053 sec, avg 87.738 ms, 11.398 ops/sec
ECC      256 key gen        8 ops took 1.088 sec, avg 135.956 ms, 7.355 ops/sec
ECDSA    256 sign          29 ops took 1.033 sec, avg 35.621 ms, 28.073 ops/sec
ECDSA    256 verify        42 ops took 1.013 sec, avg 24.114 ms, 41.470 ops/sec
ECDHE    256 agree         16 ops took 1.055 sec, avg 65.948 ms, 15.164 ops/sec
```

Run on Infineon SLB9673 on I2C at 400kHz:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
RNG                  4 KB took 1.429 seconds,    2.799 KB/s
Benchmark symmetric AES-128-CBC-enc not supported!
Benchmark symmetric AES-128-CBC-dec not supported!
Benchmark symmetric AES-256-CBC-enc not supported!
Benchmark symmetric AES-256-CBC-dec not supported!
Benchmark symmetric AES-128-CTR-enc not supported!
Benchmark symmetric AES-128-CTR-dec not supported!
Benchmark symmetric AES-256-CTR-enc not supported!
Benchmark symmetric AES-256-CTR-dec not supported!
AES-128-CFB-enc      4 KB took 1.022 seconds,    3.914 KB/s
AES-128-CFB-dec      4 KB took 1.021 seconds,    3.916 KB/s
AES-256-CFB-enc      4 KB took 1.023 seconds,    3.911 KB/s
AES-256-CFB-dec      4 KB took 1.023 seconds,    3.912 KB/s
SHA1                 8 KB took 1.203 seconds,    6.650 KB/s
SHA256               8 KB took 1.208 seconds,    6.623 KB/s
SHA384               8 KB took 1.209 seconds,    6.617 KB/s
RSA     2048 key gen       10 ops took 19.106 sec, avg 1910.554 ms, 0.523 ops/sec
RSA     2048 Public        14 ops took 1.046 sec, avg 74.740 ms, 13.380 ops/sec
RSA     2048 Private        6 ops took 1.008 sec, avg 168.057 ms, 5.950 ops/sec
RSA     2048 Pub  OAEP     15 ops took 1.008 sec, avg 67.231 ms, 14.874 ops/sec
RSA     2048 Priv OAEP      7 ops took 1.126 sec, avg 160.789 ms, 6.219 ops/sec
ECC      256 key gen        4 ops took 1.244 sec, avg 311.031 ms, 3.215 ops/sec
ECDSA    256 sign          14 ops took 1.009 sec, avg 72.057 ms, 13.878 ops/sec
ECDSA    256 verify        18 ops took 1.043 sec, avg 57.921 ms, 17.265 ops/sec
ECDHE    256 agree          9 ops took 1.025 sec, avg 113.888 ms, 8.781 ops/sec
```

Run on STMicro ST33KTPM2XSPI at 33MHz:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
RNG                 24 KB took 1.042 seconds,   23.028 KB/s
AES-128-CBC-enc     52 KB took 1.018 seconds,   51.077 KB/s
AES-128-CBC-dec     52 KB took 1.027 seconds,   50.644 KB/s
AES-256-CBC-enc     46 KB took 1.012 seconds,   45.446 KB/s
AES-256-CBC-dec     46 KB took 1.021 seconds,   45.072 KB/s
AES-128-CTR-enc     44 KB took 1.025 seconds,   42.927 KB/s
AES-128-CTR-dec     44 KB took 1.024 seconds,   42.955 KB/s
AES-256-CTR-enc     40 KB took 1.025 seconds,   39.016 KB/s
AES-256-CTR-dec     40 KB took 1.026 seconds,   38.992 KB/s
AES-128-CFB-enc     52 KB took 1.026 seconds,   50.674 KB/s
AES-128-CFB-dec     46 KB took 1.023 seconds,   44.986 KB/s
AES-256-CFB-enc     46 KB took 1.021 seconds,   45.047 KB/s
AES-256-CFB-dec     42 KB took 1.033 seconds,   40.665 KB/s
SHA1               138 KB took 1.009 seconds,  136.727 KB/s
SHA256             128 KB took 1.010 seconds,  126.723 KB/s
SHA384             116 KB took 1.001 seconds,  115.833 KB/s
RSA     2048 key gen        9 ops took 17.497 sec, avg 1944.057 ms, 0.514 ops/sec
RSA     2048 Public       155 ops took 1.003 sec, avg 6.468 ms, 154.601 ops/sec
RSA     2048 Private       12 ops took 1.090 sec, avg 90.806 ms, 11.013 ops/sec
RSA     2048 Pub  OAEP    122 ops took 1.004 sec, avg 8.230 ms, 121.501 ops/sec
RSA     2048 Priv OAEP     11 ops took 1.023 sec, avg 92.964 ms, 10.757 ops/sec
ECC      256 key gen       12 ops took 1.070 sec, avg 89.172 ms, 11.214 ops/sec
ECDSA    256 sign          40 ops took 1.010 sec, avg 25.251 ms, 39.602 ops/sec
ECDSA    256 verify        28 ops took 1.023 sec, avg 36.543 ms, 27.365 ops/sec
ECDHE    256 agree         16 ops took 1.062 sec, avg 66.391 ms, 15.062 ops/sec
```

Run on STMicro ST33TPHF2XSPI at 33MHz:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
RNG                 14 KB took 1.017 seconds,   13.763 KB/s
AES-128-CBC-enc     40 KB took 1.008 seconds,   39.666 KB/s
AES-128-CBC-dec     42 KB took 1.032 seconds,   40.711 KB/s
AES-256-CBC-enc     40 KB took 1.013 seconds,   39.496 KB/s
AES-256-CBC-dec     40 KB took 1.011 seconds,   39.563 KB/s
AES-128-CTR-enc     26 KB took 1.055 seconds,   24.646 KB/s
AES-128-CTR-dec     26 KB took 1.035 seconds,   25.117 KB/s
AES-256-CTR-enc     26 KB took 1.028 seconds,   25.302 KB/s
AES-256-CTR-dec     26 KB took 1.030 seconds,   25.252 KB/s
AES-128-CFB-enc     42 KB took 1.045 seconds,   40.201 KB/s
AES-128-CFB-dec     40 KB took 1.008 seconds,   39.699 KB/s
AES-256-CFB-enc     40 KB took 1.022 seconds,   39.151 KB/s
AES-256-CFB-dec     42 KB took 1.041 seconds,   40.362 KB/s
SHA1                86 KB took 1.005 seconds,   85.559 KB/s
SHA256              84 KB took 1.019 seconds,   82.467 KB/s
RSA     2048 key gen        1 ops took 7.455 sec, avg 7455.036 ms, 0.134 ops/sec
RSA     2048 Public       110 ops took 1.003 sec, avg 9.122 ms,  109.624 ops/sec
RSA     2048 Private        5 ops took 1.239 sec, avg 247.752 ms,  4.036 ops/sec
RSA     2048 Pub  OAEP     81 ops took 1.001 sec, avg 12.364 ms,  80.880 ops/sec
RSA     2048 Priv OAEP      4 ops took 1.007 sec, avg 251.780 ms,  3.972 ops/sec
ECC      256 key gen        5 ops took 1.099 sec, avg 219.770 ms,  4.550 ops/sec
ECDSA    256 sign          24 ops took 1.016 sec, avg 42.338 ms,  23.619 ops/sec
ECDSA    256 verify        14 ops took 1.036 sec, avg 74.026 ms,  13.509 ops/sec
ECDHE    256 agree          5 ops took 1.235 sec, avg 247.085 ms,  4.047 ops/sec

```

Run on Microchip ATTPM20 at 33MHz:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
RNG                  2 KB took 1.867 seconds,    1.071 KB/s
Benchmark symmetric AES-128-CBC-enc not supported!
Benchmark symmetric AES-128-CBC-dec not supported!
Benchmark symmetric AES-256-CBC-enc not supported!
Benchmark symmetric AES-256-CBC-dec not supported!
Benchmark symmetric AES-128-CTR-enc not supported!
Benchmark symmetric AES-128-CTR-dec not supported!
Benchmark symmetric AES-256-CTR-enc not supported!
Benchmark symmetric AES-256-CTR-dec not supported!
AES-128-CFB-enc     16 KB took 1.112 seconds,   14.383 KB/s
AES-128-CFB-dec     16 KB took 1.129 seconds,   14.166 KB/s
AES-256-CFB-enc     12 KB took 1.013 seconds,   11.845 KB/s
AES-256-CFB-dec     12 KB took 1.008 seconds,   11.909 KB/s
SHA1                22 KB took 1.009 seconds,   21.797 KB/s
SHA256              22 KB took 1.034 seconds,   21.270 KB/s
RSA     2048 key gen        3 ops took 15.828 sec, avg 5275.861 ms, 0.190 ops/sec
RSA     2048 Public        22 ops took 1.034 sec, avg 47.021 ms, 21.267 ops/sec
RSA     2048 Private        9 ops took 1.059 sec, avg 117.677 ms, 8.498 ops/sec
RSA     2048 Pub  OAEP     21 ops took 1.007 sec, avg 47.959 ms, 20.851 ops/sec
RSA     2048 Priv OAEP      9 ops took 1.066 sec, avg 118.423 ms, 8.444 ops/sec
ECC      256 key gen        7 ops took 1.072 sec, avg 153.140 ms, 6.530 ops/sec
ECDSA    256 sign          18 ops took 1.056 sec, avg 58.674 ms, 17.043 ops/sec
ECDSA    256 verify        24 ops took 1.031 sec, avg 42.970 ms, 23.272 ops/sec
ECDHE    256 agree         16 ops took 1.023 sec, avg 63.934 ms, 15.641 ops/sec
```

Run on Nations Technologies Inc. Z32H330 TPM 2.0 module at 33MHz:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
RNG                 12 KB took 1.065 seconds,   11.270 KB/s
AES-128-CBC-enc     48 KB took 1.026 seconds,   46.780 KB/s
AES-128-CBC-dec     48 KB took 1.039 seconds,   46.212 KB/s
AES-256-CBC-enc     48 KB took 1.035 seconds,   46.370 KB/s
AES-256-CBC-dec     48 KB took 1.025 seconds,   46.852 KB/s
Benchmark symmetric AES-128-CTR-enc not supported!
Benchmark symmetric AES-128-CTR-dec not supported!
Benchmark symmetric AES-256-CTR-enc not supported!
Benchmark symmetric AES-256-CTR-dec not supported!
AES-128-CFB-enc     50 KB took 1.029 seconds,   48.591 KB/s
AES-128-CFB-dec     50 KB took 1.035 seconds,   48.294 KB/s
AES-256-CFB-enc     48 KB took 1.000 seconds,   47.982 KB/s
AES-256-CFB-dec     48 KB took 1.003 seconds,   47.855 KB/s
SHA1                80 KB took 1.009 seconds,   79.248 KB/s
SHA256              80 KB took 1.004 seconds,   79.702 KB/s
SHA384              78 KB took 1.018 seconds,   76.639 KB/s
RSA     2048 key gen        8 ops took 17.471 sec, avg 2183.823 ms, 0.458 ops/sec
RSA     2048 Public        52 ops took 1.004 sec, avg 19.303 ms, 51.805 ops/sec
RSA     2048 Private        8 ops took 1.066 sec, avg 133.243 ms, 7.505 ops/sec
RSA     2048 Pub  OAEP     51 ops took 1.001 sec, avg 19.621 ms, 50.966 ops/sec
RSA     2048 Priv OAEP      8 ops took 1.073 sec, avg 134.182 ms, 7.453 ops/sec
ECC      256 key gen       20 ops took 1.037 sec, avg 51.871 ms, 19.279 ops/sec
ECDSA    256 sign          43 ops took 1.006 sec, avg 23.399 ms, 42.736 ops/sec
ECDSA    256 verify        28 ops took 1.030 sec, avg 36.785 ms, 27.185 ops/sec
ECDHE    256 agree         26 ops took 1.010 sec, avg 38.847 ms, 25.742 ops/sec
```

Run on Nations Technologies Inc. NS350 TPM 2.0 module at 33MHz:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
        Use Parameter Encryption: NULL
RNG                  6 KB took 1.052 seconds,    5.703 KB/s
Benchmark symmetric AES-128-CBC-enc not supported!
Benchmark symmetric AES-128-CBC-dec not supported!
Benchmark symmetric AES-256-CBC-enc not supported!
Benchmark symmetric AES-256-CBC-dec not supported!
Benchmark symmetric AES-128-CTR-enc not supported!
Benchmark symmetric AES-128-CTR-dec not supported!
Benchmark symmetric AES-256-CTR-enc not supported!
Benchmark symmetric AES-256-CTR-dec not supported!
Encrypt/Decrypt unavailable
AES-128-CFB-enc      0 bytes took 0.005 seconds,    0.000 bytes/s
Encrypt/Decrypt unavailable
AES-128-CFB-dec      0 bytes took 0.006 seconds,    0.000 bytes/s
Encrypt/Decrypt unavailable
AES-256-CFB-enc      0 bytes took 0.006 seconds,    0.000 bytes/s
Encrypt/Decrypt unavailable
AES-256-CFB-dec      0 bytes took 0.005 seconds,    0.000 bytes/s
SHA1                68 KB took 1.003 seconds,   67.772 KB/s
SHA256              68 KB took 1.002 seconds,   67.871 KB/s
SHA384              66 KB took 1.007 seconds,   65.548 KB/s
RSA     2048 key gen        7 ops took 16.652 sec, avg 2378.893 ms, 0.420 ops/sec
RSA     2048 Public       126 ops took 1.005 sec, avg 7.980 ms, 125.321 ops/sec
RSA     2048 Private       20 ops took 1.035 sec, avg 51.735 ms, 19.329 ops/sec
RSA     2048 Pub  OAEP     81 ops took 1.008 sec, avg 12.443 ms, 80.366 ops/sec
RSA     2048 Priv OAEP     19 ops took 1.027 sec, avg 54.033 ms, 18.507 ops/sec
ECC      256 key gen       20 ops took 1.042 sec, avg 52.095 ms, 19.196 ops/sec
ECDSA    256 sign          60 ops took 1.009 sec, avg 16.816 ms, 59.466 ops/sec
ECDSA    256 verify        46 ops took 1.008 sec, avg 21.921 ms, 45.618 ops/sec
ECDHE    256 agree         38 ops took 1.008 sec, avg 26.532 ms, 37.691 ops/sec
```

Run on Nuvoton NPCT650:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
RNG                  8 KB took 1.291 seconds,    6.197 KB/s
Benchmark symmetric AES-128-CBC-enc not supported!
Benchmark symmetric AES-128-CBC-dec not supported!
Benchmark symmetric AES-256-CBC-enc not supported!
Benchmark symmetric AES-256-CBC-dec not supported!
Benchmark symmetric AES-256-CTR-enc not supported!
Benchmark symmetric AES-256-CTR-dec not supported!
Benchmark symmetric AES-256-CFB-enc not supported!
Benchmark symmetric AES-256-CFB-dec not supported!
SHA1                90 KB took 1.005 seconds,   89.530 KB/s
SHA256              90 KB took 1.010 seconds,   89.139 KB/s
RSA     2048 key gen        8 ops took 35.833 sec, avg 4479.152 ms, 0.223 ops/sec
RSA     2048 Public        77 ops took 1.007 sec, avg 13.078 ms, 76.463 ops/sec
RSA     2048 Private        2 ops took 1.082 sec, avg 540.926 ms, 1.849 ops/sec
RSA     2048 Pub  OAEP     53 ops took 1.005 sec, avg 18.961 ms, 52.739 ops/sec
RSA     2048 Priv OAEP      2 ops took 1.088 sec, avg 544.075 ms, 1.838 ops/sec
ECC      256 key gen        7 ops took 1.033 sec, avg 147.608 ms, 6.775 ops/sec
ECDSA    256 sign           6 ops took 1.141 sec, avg 190.149 ms, 5.259 ops/sec
ECDSA    256 verify         4 ops took 1.061 sec, avg 265.216 ms, 3.771 ops/sec
ECDHE    256 agree          6 ops took 1.055 sec, avg 175.915 ms, 5.685 ops/sec
```

Run on Nuvoton NPCT750 at 43MHz:

```
RNG                 16 KB took 1.114 seconds,   14.368 KB/s
Benchmark symmetric AES-128-CBC-enc not supported!
Benchmark symmetric AES-128-CBC-dec not supported!
Benchmark symmetric AES-256-CBC-enc not supported!
Benchmark symmetric AES-256-CBC-dec not supported!
SHA1               120 KB took 1.012 seconds,  118.618 KB/s
SHA256             122 KB took 1.012 seconds,  120.551 KB/s
SHA384             120 KB took 1.003 seconds,  119.608 KB/s
RSA     2048 key gen        5 ops took 17.043 sec, avg 3408.678 ms, 0.293 ops/sec
RSA     2048 Public       134 ops took 1.004 sec, avg 7.490 ms, 133.517 ops/sec
RSA     2048 Private       15 ops took 1.054 sec, avg 70.261 ms, 14.233 ops/sec
RSA     2048 Pub  OAEP    116 ops took 1.002 sec, avg 8.636 ms, 115.797 ops/sec
RSA     2048 Priv OAEP     15 ops took 1.061 sec, avg 70.716 ms, 14.141 ops/sec
ECC      256 key gen       12 ops took 1.008 sec, avg 84.020 ms, 11.902 ops/sec
ECDSA    256 sign          18 ops took 1.015 sec, avg 56.399 ms, 17.731 ops/sec
ECDSA    256 verify        26 ops took 1.018 sec, avg 39.164 ms, 25.533 ops/sec
ECDHE    256 agree         35 ops took 1.029 sec, avg 29.402 ms, 34.011 ops/sec
```

### TPM2 Native Tests

```
./examples/native/native_test
TPM2 Demo using Native API's
TPM2: Caps 0x30000495, Did 0x0000, Vid 0x104a, Rid 0x4e
TPM2_Startup pass
TPM2_SelfTest pass
TPM2_GetTestResult: Size 12, Rc 0x0
TPM2_IncrementalSelfTest: Rc 0x0, Alg 0x1 (Todo 0)
TPM2_GetCapability: Property FamilyIndicator 0x322e3000
TPM2_GetCapability: Property PCR Count 24
TPM2_GetCapability: Property FIRMWARE_VERSION_1 0x004a0008
TPM2_GetCapability: Property FIRMWARE_VERSION_2 0x44a01587
TPM2_GetRandom: Got 32 bytes
TPM2_StirRandom: success
TPM2_PCR_Read: Index 0, Count 1
TPM2_PCR_Read: Index 0, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 1, Count 1
TPM2_PCR_Read: Index 1, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 2, Count 1
TPM2_PCR_Read: Index 2, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 3, Count 1
TPM2_PCR_Read: Index 3, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 4, Count 1
TPM2_PCR_Read: Index 4, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 5, Count 1
TPM2_PCR_Read: Index 5, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 6, Count 1
TPM2_PCR_Read: Index 6, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 7, Count 1
TPM2_PCR_Read: Index 7, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 8, Count 1
TPM2_PCR_Read: Index 8, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 9, Count 1
TPM2_PCR_Read: Index 9, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 10, Count 1
TPM2_PCR_Read: Index 10, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 11, Count 1
TPM2_PCR_Read: Index 11, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 12, Count 1
TPM2_PCR_Read: Index 12, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 13, Count 1
TPM2_PCR_Read: Index 13, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 14, Count 1
TPM2_PCR_Read: Index 14, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 15, Count 1
TPM2_PCR_Read: Index 15, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 16, Count 1
TPM2_PCR_Read: Index 16, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 17, Count 1
TPM2_PCR_Read: Index 17, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 18, Count 1
TPM2_PCR_Read: Index 18, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 19, Count 1
TPM2_PCR_Read: Index 19, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 20, Count 1
TPM2_PCR_Read: Index 20, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 21, Count 1
TPM2_PCR_Read: Index 21, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 22, Count 1
TPM2_PCR_Read: Index 22, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 23, Count 1
TPM2_PCR_Read: Index 23, Digest Sz 32, Update Counter 20
TPM2_PCR_Extend success
TPM2_PCR_Read: Index 0, Count 1
TPM2_PCR_Read: Index 0, Digest Sz 32, Update Counter 21
TPM2_StartAuthSession: sessionHandle 0x3000000
TPM2_PolicyGetDigest: size 32
TPM2_PCR_Read: Index 0, Digest Sz 20, Update Counter 21
wc_Hash of PCR[0]: size 32
TPM2_PolicyPCR failed 0x1c4: TPM_RC_AUTHSIZE
TPM2_PolicyRestart: Done
TPM2_HashSequenceStart: sequenceHandle 0x80000000
Hash SHA256 test success
TPM2_CreatePrimary: Endorsement 0x80000000 (314 bytes)
TPM2_CreatePrimary: Storage 0x80000002 (282 bytes)
TPM2_LoadExternal: 0x80000004
TPM2_MakeCredential: credentialBlob 68, secret 256
TPM2_ReadPublic Handle 0x80000004: pub 314, name 34, qualifiedName 34
Create HMAC-SHA256 Key success, public 48, Private 137
TPM2_Load New HMAC Key Handle 0x80000004
TPM2_PolicyCommandCode: success
TPM2_ObjectChangeAuth: private 137
TPM2_ECC_Parameters: CurveID 3, sz 256, p 32, a 32, b 32, gX 32, gY 32, n 32, h 1
TPM2_Create: New ECDSA Key: pub 88, priv 126
TPM2_Load ECDSA Key Handle 0x80000004
TPM2_Sign: ECC S 32, R 32
TPM2_VerifySignature: Tag 32802
TPM2_Create: New ECDH Key: pub 88, priv 126
TPM2_Load ECDH Key Handle 0x80000004
TPM2_ECDH_KeyGen: zPt 68, pubPt 68
TPM2_ECDH_ZGen: zPt 68
TPM2 ECC Shared Secret Pass
TPM2_Create: New RSA Key: pub 278, priv 222
TPM2_Load RSA Key Handle 0x80000004
TPM2_RSA_Encrypt: 256
TPM2_RSA_Decrypt: 68
RSA Encrypt/Decrypt test passed
TPM2_NV_DefineSpace: 0x1bfffff
TPM2_NV_ReadPublic: Sz 14, Idx 0x1bfffff, nameAlg 11, Attr 0x2020002, authPol 0, dataSz 32, name 34
Create AES128 CFB Key success, public 50, Private 142
TPM2_Load New AES Key Handle 0x80000004
Encrypt/Decrypt test success
```

### TPM2 CSR Example

```
./examples/csr/csr
TPM2 CSR Example
Generated/Signed Cert (DER 860, PEM 1236)
-----BEGIN CERTIFICATE REQUEST-----
MIIDWDCCAkACAQIwgZsxCzAJBgNVBAYTAlVTMQ8wDQYDVQQIDAZPcmVnb24xETAP
BgNVBAcMCFBvcnRsYW5kMQ0wCwYDVQQEDARUZXN0MRAwDgYDVQQKDAd3b2xmU1NM
MQwwCgYDVQQLDANSU0ExGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNvbTEfMB0GCSqG
SIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBANtFRTX9CIW489vdmfy0qoffKtXBIfEGo07XgbvHPqk/KLx9NpK4
fDLRdh5Kh7mDIGQI0hKDQMQ4GRTzRlE+wXlTqGQaQohac1LRxe21RCCKn0ZXvbCJ
Wd1cIAGQyDyOb8WYCquQB79r2pIAKnVbedu+G1jx3tVrwB8ZCosKF86au7cEDxvD
sdmt2vcEIlMcgfWQNo8TkWEKW33qu/rOOfJAUkVOUKENvj8zz/Iw4pX9nImiclMC
/pMcgjpnFUlG5a0Jwg2PR7pXyRYUCciMq20UF5LDZG3NmFirVqigOmBIFsrpVCjt
wf/Ep6DxFgmy7KNJ/0kzQByySvjKrIOqynsCAwEAAaB3MHUGCSqGSIb3DQEJDjFo
MGYwHQYDVR0OBBYEFBHIhJ44Ide+SKGpL2neKuusXBZxMEUGA1UdJQQ+MDwGCCsG
AQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCAYI
KwYBBQUHAwkwDQYJKoZIhvcNAQELBQADggEBACGHTZE5BVonf9OM3bYZvl2SiKdj
fo+f8a5COgBgCiNK8DPXCr+RMfp7jy8+3NP0bUPppi46F6Eq80YIZuQJgoyd0l8l
F+0KXq/FuoHtTLH7joHCKcYta1yPpnvKAG9195aIruAHesXwDxklqTvlVx3/e9No
YtmWUMdrLvTZrI1L1/0OuHbPgCGmdyHOXEh0xY0VTE1I0ff0b8UC3dQCsf8uROhO
fXXYwZz9LLSdO/QuDSxXThEe4m1/AUJkiaQ/T2zNEiR5Imk+jluXLz8bVM7w+HMt
l/076ekjTI+7PwzBZIG2F3nOIDUmHwe0lAWdU8h9IoAlM6kS22fh6gZZqQg=
-----END CERTIFICATE REQUEST-----

Generated/Signed Cert (DER 467, PEM 704)
-----BEGIN CERTIFICATE REQUEST-----
MIIBzzCCAXUCAQIwgZsxCzAJBgNVBAYTAlVTMQ8wDQYDVQQIDAZPcmVnb24xETAP
BgNVBAcMCFBvcnRsYW5kMQ0wCwYDVQQEDARUZXN0MRAwDgYDVQQKDAd3b2xmU1NM
MQwwCgYDVQQLDANFQ0MxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNvbTEfMB0GCSqG
SIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABIokJgsrMSW8f6si4S1saUXABXbqWKWVQn+D6z9LQe/wkPqozP/hV/3qTtpE
I/E3HjcHqRY+nsosjlEz36mzrRagdzB1BgkqhkiG9w0BCQ4xaDBmMB0GA1UdDgQW
BBRyZJhX+sHZEE117OKL0/CPVGbAKzBFBgNVHSUEPjA8BggrBgEFBQcDAQYIKwYB
BQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgGCCsGAQUFBwMJMAoG
CCqGSM49BAMCA0gAMEUCIQCR9cbyRt3cbEZUIOBa4GNSRTlgFdB3X1EOwm+cA5/k
6AIgBm+EU6m5SDsk7BYmxTQAhgJFrelwymOa7m16kAXnFuU=
-----END CERTIFICATE REQUEST-----
```

### TPM2 PKCS 7 Example

```
./examples/pkcs7/pkcs7
TPM2 PKCS7 Example
PKCS7 Signed Container 1625
PKCS7 Container Verified (using TPM)
PKCS7 Container Verified (using software)
```

### TPM TLS Client Example

The wolfSSL TLS client requires loading a public key to indicate mutual authentication is used. The crypto callback uses the TPM for the private key signing.

```
./examples/tls/tls_client
TPM2 TLS Client Example
Write (29): GET /index.html HTTP/1.0


Read (193): HTTP/1.1 200 OK
Content-Type: text/html
Connection: close

<html>
<head>
<title>Welcome to wolfSSL!</title>
</head>
<body>
<p>wolfSSL has successfully performed handshake!</p>
</body>
</html>
```

### TPM TLS Server Example

The wolfSSL TLS server loads the TPM public key and the crypto callback uses the TPM for the private key signing.

```
./examples/tls/tls_server
TPM2 TLS Server Example
Loading RSA certificate and public key
Read (29): GET /index.html HTTP/1.0


Write (193): HTTP/1.1 200 OK
Content-Type: text/html
Connection: close

<html>
<head>
<title>Welcome to wolfSSL!</title>
</head>
<body>
<p>wolfSSL has successfully performed handshake!</p>
</body>
</html>
```

## Device Identity and Attestation Keys

The TCG published a specification for TPM manufacture guidance on setting up keys that can be used for device identiy and attestation.

This feature has been tested with the ST33KTPM and is enabled with `WOLFTPM_MFG_IDENTITY`. The ST33KTPM samples are provisioned with a default master password enabled with `TEST_SAMPLE`. To define your own master password use `TPM2_IAK_SAMPLE_MASTER_PASSWORD`. The master password is hashed along with the device serial number to produce authentication for accessing these keys.

The default keys are ECDSA SECP384R1 with SHA2-384 and stored in NV Index defined by `TPM2_IAK_KEY_HANDLE`, `TPM2_IAK_CERT_HANDLE`, `TPM2_IDEVID_KEY_HANDLE` and `TPM2_IDEVID_CERT_HANDLE`.


### TPM Endorsement Key Certificates

The TCG EK Credential Profile defines how manufacturers provision endorsement certificates in the TCG NV index range (see TPM_20_TCG_NV_SPACE).
The `get_ek_certs` example shows how to retrieve those EK cerificates, validate them and create a primary EK handle for signing.
See `./examples/endorsement/get_ek_certs`.


## Todo

* Update to v1.59 of specification (adding CertifyX509).
* Inner wrap support for SensitiveToPrivate.
* Add support for IRQ (interrupt line)

## Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).
