# wolfTPM (TPM 2.0)

Portable TPM 2.0 project designed for embedded use.


## Project Features

* This implementation provides all TPM 2.0 API’s in compliance with the specification.
* Wrappers provided to simplify Key Generation, RSA encrypt/decrypt, ECC sign/verify, ECDH and NV.
* Testing done using the ST33TP* SPI/I2C and Infineon OPTIGA SLB9670 / LetsTrust TPM modules.
* This uses the TPM Interface Specification (TIS) to communicate over SPI.
* Platform support Raspberry Pi and STM32 with CubeMX.
* The design allows for easy portability to different platforms:
	* Native C code designed for embedded use.
	* Single IO callback for hardware SPI interface.
	* No external dependencies.
	* Compact code size and minimal memory use.
* Includes example code for:
    * Most TPM2 native API’s
    * All TPM2 wrappers
	* PKCS 7
	* Certificate Signing Request (CSR)
	* TLS Client
	* TLS Server

Note: See `examples/README.md` for details on using the examples.


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



## Platform

This example was written for use on Raspberry Pi® 3 or the STM32 with the CubeMX HAL. This was tested using the 

The Raspberry 3 uses the native `spi_dev` interface and defaults to `/dev/spidev0.1`. If you are running the Infineon patches it overrides the kernel SPI interface with their `spi_tis_dev`, which currently causes this demo to fail.

This has only been tested and confirmed working with Rasbian 4.4.x.

### IO Callback

For interfacing to your hardware platform see the example `examples/tpm_io.c` callback function `TPM2_IoCb`. Here you can modify or insert your own IO callback code for the TPM demo.

There are examples here for Linux, STM32 CubeMX and Atmel ASF. The advanced IO option is required for I2C support because it adds the register and read/write flag as parameter to the IO callback.


### Hardware

Tested with:

* Infineon OPTIGA (TM) Trusted Platform Module 2.0 SLB 9670.
* LetsTrust: http://letstrust.de (https://buyzero.de/collections/andere-platinen/products/letstrust-hardware-tpm-trusted-platform-module). Compact Raspberry Pi TPM 2.0 board based on Infineon SLB 9670.
* ST ST33TP* TPM 2.0 module (SPI and I2C)
* Microchip ATTPM20

#### Device Identification

Infineon SLB9670:
TIS: TPM2: Caps 0x30000697, Did 0x001b, Vid 0x15d1, Rid 0x10
Mfg IFX (1), Vendor SLB9670, Fw 7.85 (4555), FIPS 140-2 1, CC-EAL4 1

ST ST33TP SPI
TPM2: Caps 0x1a7e2882, Did 0x0000, Vid 0x104a, Rid 0x4e
Mfg STM  (2), Vendor , Fw 74.8 (1151341959), FIPS 140-2 1, CC-EAL4 0

Microchip ATTPM20
TPM2: Caps 0x30000695, Did 0x3205, Vid 0x1114, Rid 0x 1 
Mfg MCHP (3), Vendor , Fw 512.20481 (0), FIPS 140-2 0, CC-EAL4 0

## Building

Build wolfSSL:

```
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-certgen --enable-certreq --enable-certext --enable-pkcs7 --enable-cryptodev
make
make check
sudo make install
sudo ldconfig
```

autogen.sh requires: automake and libtool: `sudo apt-get install automake libtool`

### Building Infineon SLB9670

Build wolfTPM:

```
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM
./autogen.sh
./configure
make
```

### Building ST ST33TP*

Build wolfTPM:

```
./autogen.sh
./configure --enable-st33 [--enable-i2c]
make
```

For the I2C support on Raspberry Pi you may need to enable I2C. Here are the steps:
1. Edit `sudo vim /boot/config.txt`
2. Uncomment `dtparam=i2c_arm=on`
3. Reboot `sudo reboot`

### Building Microchip ATTPM20

Build wolfTPM:

```
./autogen.sh
./configure --enable-mchp
make
```


### Build options and defines

```
--enable-debug          Add debug code/turns off optimizations (yes|no|verbose) - DEBUG_WOLFTPM, WOLFTPM_DEBUG_VERBOSE, WOLFTPM_DEBUG_IO
--enable-examples       Enable Examples (default: enabled)
--enable-wrapper        Enable wrapper code (default: enabled) - WOLFTPM2_NO_WRAPPER
--enable-wolfcrypt      Enable wolfCrypt hooks for RNG, Auth Sessions and Parameter encryption (default: enabled) - WOLFTPM2_NO_WOLFCRYPT
--enable-advio          Enable Advanced IO (default: disabled) - WOLFTPM_ADV_IO
--enable-st33           Enable ST33 TPM Support (default: disabled) - WOLFTPM_ST33 (requires advio)
--enable-i2c            Enable I2C TPM Support (default: disabled) - WOLFTPM_I2C
--enable-mchp           Enable Microchip TPM Support (default: disabled) - WOLFTPM_MCHP
WOLFTPM_TIS_LOCK        Enable Linux Named Semaphore for locking access to SPI device for concurrent access between processes.
```

## Release Notes


### wolfTPM Release 1.4 (11/13/2018)

* Fixed cryptodev ECC callback to use R and S for the signature verify. (PR #39)
* Fixed printf type warnings with `DEBUG_WOLFTPM` defined. (PR #37)
* Fixed detection of correct hash algorithm in `wolfTPM2_VerifyHash`. (PR #39)
* Fix bug with native example where TPM2_Shutdown failure would loop. (PR #34)
* Fix to decoupled the fixed TPM algorithms/sizes from wolfCrypt build options. (PR #35)
* Fix for building with different wolfCrypt options. (PR #26)
* Fix for byte swap build error. (PR #26)
* Fix CSR example CertName to use designated initializers to resolve use against different wolfSSL versions. (PR #25)
* Improved portability by eliminating the packed TPM2_HEADER. (PR #45)
* Improved stack reduction by eliminating the private section from WOLFTPM2_KEY struct. (PR #31)
* Added TLS server example for wolfTPM. (PR #30)
* Added more RSA and ECC key loading examples. (PR #47)
* Added support for loading an external private keys using new API's `wolfTPM2_LoadPrivateKey`, `wolfTPM2_LoadRsaPrivateKey`, and `wolfTPM2_LoadEccPrivateKey`. (PR #46)
* Added example for reading the firmware version using `TPM2_GetCapability` with `TPM_PT_FIRMWARE_VERSION_1`. (PR #44)
* Added hashing wrappers and tests using new API's: `wolfTPM2_HashStart`, `wolfTPM2_HashUpdate` and `wolfTPM2_HashFinish`. (PR #40)
* Added PKCS7 7 sign/verify example demonstrating large data case using chunked buffer and new `_ex` functions. (PR #32)
* Added Key Generation to benchmark. (PR #33)
* Added ST33TP I2C TPM 2.0 support (`./configure --enable-st33 --enable-i2c`). (PR #33)
* Added ST33TP SPI TPM 2.0 support (`--enable-st33` or `#define WOLFTPM_ST33`). (PR #25)
* Added support for Atmel ASF SPI. (PR #25)
* Added example for IAR EWARM. (PR #27)
* Added ECC verify test using public key and NIST test vectors. (PR #39)
* Added new RNG wrapper API `wolfTPM2_GetRandom`. (PR #36)
* Added macro for hardware RNG max request as `MAX_RNG_REQ_SIZE`. (PR #36)
* Added instructions for enabling SPI and I2C on the Raspberry Pi. (PR #34)
* Added support for symmetric AES encrypt/decrypt. (PR #29)
* Added wrapper to help with creation of symmetric keys. (PR #29)
* Added advanced IO callback support (enabled using `--enable-advio` or `#define WOLFTPM_ADV_IO`). (PR #25)
* Added overridable define `WOLFTPM_LOCALITY_DEFAULT` for the locality used. (PR #28)
* Added `XTPM_WAIT()` macro to enable custom wait between polling. (PR #28)
* Added build option to disable wolfCrypt dependency using `./configure --disable-wolfcrypt` or `#define WOLFTPM2_NO_WOLFCRYPT`. (PR #24)
* Removed unused SET, CLEAR, TRUE, FALSE macros. (PR #28)
* Cleanup DEBUG_WOLFTPM ifdef's around all printfs in library proper. (PR #38)
* Cleanup of line lengths. (PR #37)
* Cleanup of wrapper test to move test data into `tpm_test.h`. (PR #47)
* Cleanup of the packet code to handle determining of size (mark/place). (PR #46)
* Cleanup of the IO callback examples. (PR #25)
* Cleanup of TIS layer improve return code and timeout handling. (PR #28)
* Cleanup to move types and configuration/port specific items into new `tpm2_types.h`. (PR #24)


### wolfTPM Release 1.3 (07/20/2018)

* Fixed the TIS TPM_BASE_ADDRESS to conform to specification. (PR #19)
* Fixed static analysis warnings. (PR #20)
* Fixed minor build warnings with different compilers. (PR #21)
* Fixed TPM failure for RSA exponents less than 7 by using software based RSA. (PR #23)
* Added TPM benchmarking support. (PR #16)
* Added functions to import/export public keys as wolf format. (PR #15)
* Added PKCS7 example to show sign/verify with TPM. (PR #17)
* Added CSR example to generate certificate request based on TPM key. (PR #17)
* Added CSR signing script `./certs/certreq.sh` to create certificate using self-signed CA. (PR #17)
* Added TLS Client example that uses TPM based key for client certificate. (PR #17)
* Added support for wolfSSL `WOLF_CRYPT_DEV` callbacks to enable TPM based ECC and RSA private keys. (PR #17)
* Added ability to clear/reset TPM using `./examples/wrap/wrap_test 1` (PR #17)
* Moved some of the example configuration into `./examples/tpm_io.h`. (PR #17)

### wolfTPM Release 1.1 (03/09/2018)

* Added TPM2 wrapper layer to simplify key creation, RSA encrypt/decrypt, ECC sign/verify and ECDH.
* Added TPM2 wrapper example code.
* Added Linux SPI support for running on Raspberry Pi.
* Fixes for TPM2 command and response assembly and parsing.
* Fixes to support authentication for command and response.
* Progress on supporting parameter encryption/decryption.
* Refactor of TIS and Packet layers into new files.
* Fixes/improvements to `wolfTPM2_GetRCString` for error code and string reporting.
* Added new `TPM2_Cleanup` function.
* New tests for TPM2 native API's (test coverage is about 75%).

### wolfTPM Release 1.0 (02/06/2018)

* Support for all TPM2 native API's using TIS and SPI IO callback.
* Helper for getting TPM return code string `TPM2_GetRCString`.
* TPM 2.0 demo code in `examples/tpm/tpm2_demo.c` with support for STM32 CubeMX SPI as reference.


## Running Examples

These examples demonstrate features of a TPM 2.0 module. The examples create RSA and ECC keys in NV for testing using handles defined in `./examples/tpm_io.h`. The PKCS #7 and TLS examples require generating CSR's and signing them using a test script. See `examples/README.md` for details on using the examples. To run the TLS sever and client on same machine you must build with `WOLFTPM_TIS_LOCK` to enable concurrent access protection.

### TPM2 Wrapper Tests

```
./examples/wrap/wrap_test
TPM2 Demo for Wrapper API's
Mfg IFX (1), Vendor SLB9670, Fw 7.85 (4555), FIPS 140-2 1, CC-EAL4 1
RSA Encrypt/Decrypt Test Passed
RSA Encrypt/Decrypt OAEP Test Passed
RSA Key 0x80000001 Exported to wolf RsaKey
wolf RsaKey loaded into TPM: Handle 0x80000000
RSA Private Key Loaded into TPM: Handle 0x80000001
ECC Sign/Verify Passed
ECC DH Generation Passed
ECC Verify Test Passed
ECC Key 0x80000001 Exported to wolf ecc_key
wolfSSL Entering GetObjectId()
wolf ecc_key loaded into TPM: Handle 0x80000000
wolfSSL Entering GetObjectId()
ECC Private Key Loaded into TPM: Handle 0x80000001
NV Test on index 0x1800200 with 1024 bytes passed
Hash SHA256 test success
Encrypt/Decrypt test success
```

### TPM2 Benchmarks

Note: Key Generation is using existing template from hierarchy seed.
Note: SPI bus speed increased to 10Mhz for these measurements.

Run on Infineon OPTIGA SLB9670:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
RNG                  8 KB took 1.089 seconds,    7.344 KB/s
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
SHA1                28 KB took 1.007 seconds,   27.800 KB/s
SHA256              28 KB took 1.002 seconds,   27.946 KB/s
RSA     2048 key gen        6 ops took 12.175 sec, avg 2029.085 ms, 0.493 ops/sec
RSA     2048 Public        45 ops took 1.019 sec, avg 22.649 ms, 44.151 ops/sec
RSA     2048 Private        6 ops took 1.059 sec, avg 176.565 ms, 5.664 ops/sec
RSA     2048 Pub  OAEP     46 ops took 1.009 sec, avg 21.925 ms, 45.610 ops/sec
RSA     2048 Priv OAEP      6 ops took 1.051 sec, avg 175.166 ms, 5.709 ops/sec
ECC      256 key gen        4 ops took 1.013 sec, avg 253.259 ms, 3.949 ops/sec
ECDSA    256 sign          14 ops took 1.028 sec, avg 73.403 ms, 13.623 ops/sec
ECDSA    256 verify         9 ops took 1.056 sec, avg 117.290 ms, 8.526 ops/sec
ECDHE    256 agree          5 ops took 1.178 sec, avg 235.695 ms, 4.243 ops/sec
```

Run on ST ST33TP SPI:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
RNG                 18 KB took 1.081 seconds,   16.657 KB/s
AES-128-CBC-enc     48 KB took 1.026 seconds,   46.779 KB/s
AES-128-CBC-dec     48 KB took 1.024 seconds,   46.887 KB/s
AES-256-CBC-enc     48 KB took 1.026 seconds,   46.797 KB/s
AES-256-CBC-dec     48 KB took 1.023 seconds,   46.941 KB/s
AES-128-CTR-enc     28 KB took 1.022 seconds,   27.392 KB/s
AES-128-CTR-dec     28 KB took 1.022 seconds,   27.391 KB/s
AES-256-CTR-enc     30 KB took 1.069 seconds,   28.074 KB/s
AES-256-CTR-dec     30 KB took 1.068 seconds,   28.080 KB/s
AES-128-CFB-enc     48 KB took 1.038 seconds,   46.226 KB/s
AES-128-CFB-dec     48 KB took 1.025 seconds,   46.843 KB/s
AES-256-CFB-enc     48 KB took 1.037 seconds,   46.298 KB/s
AES-256-CFB-dec     48 KB took 1.026 seconds,   46.793 KB/s
SHA1               116 KB took 1.013 seconds,  114.504 KB/s
SHA256             108 KB took 1.000 seconds,  107.962 KB/s
RSA     2048 key gen        1 ops took 1.908 sec, avg 1908.493 ms, 0.524 ops/sec
RSA     2048 Public       124 ops took 1.002 sec, avg 8.078 ms, 123.790 ops/sec
RSA     2048 Private        5 ops took 1.234 sec, avg 246.729 ms, 4.053 ops/sec
RSA     2048 Pub  OAEP     87 ops took 1.007 sec, avg 11.569 ms, 86.436 ops/sec
RSA     2048 Priv OAEP      4 ops took 1.004 sec, avg 250.991 ms, 3.984 ops/sec
ECC      256 key gen        5 ops took 1.091 sec, avg 218.226 ms, 4.582 ops/sec
ECDSA    256 sign          24 ops took 1.001 sec, avg 41.718 ms, 23.971 ops/sec
ECDSA    256 verify        14 ops took 1.033 sec, avg 73.771 ms, 13.555 ops/sec
ECDHE    256 agree          5 ops took 1.231 sec, avg 246.112 ms, 4.063 ops/sec
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
TPM2_PCR_Read: Index 0, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 1, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 2, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 3, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 4, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 5, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 6, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 7, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 8, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 9, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 10, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 11, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 12, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 13, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 14, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 15, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 16, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 17, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 18, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 19, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 20, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 21, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 22, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 23, Digest Sz 32, Update Counter 20
TPM2_PCR_Extend success
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

The wolfSSL TLS client requires loading a private key for mutual authentication. We load a "fake" private key and use the `myTpmCheckKey` callback to check for fake key to use the TPM instead.

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

The wolfSSL TLS server requires loading a private key. We load a "fake" private key and use the `myTpmCheckKey` callback to check for fake key to use the TPM instead.

```
./examples/tls/tls_server
TPM2 TLS Server Example
Loading RSA certificate and dummy key
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


## Todo
* Improve overall documentation.
* Add support for encrypting / decrypting parameters.
* Add support for SensitiveToPrivate inner and outer.
* Add `spi_tis_dev` support for Raspberry Pi.
* Add runtime support for detecting module type ST33 or SLB9670.


## Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).
