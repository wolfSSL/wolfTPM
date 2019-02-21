# wolfTPM (TPM 2.0)

Portable TPM 2.0 project designed for embedded use.


## Project Features

* This implementation provides all TPM 2.0 API’s in compliance with the specification.
* Wrappers provided to simplify Key Generation/Loading, RSA encrypt/decrypt, ECC sign/verify, ECDH, NV, Hashing/Hmac and AES.
* Testing done using the STM ST33TP* SPI/I2C, Infineon OPTIGA SLB9670 and Microchip ATTPM20 TPM 2.0 modules.
* This uses the TPM Interface Specification (TIS) to communicate over SPI.
* Platform support for Raspberry Pi, STM32 with CubeMX, Atmel ASF and Barebox.
* The design allows for easy portability to different platforms:
	* Native C code designed for embedded use.
	* Single IO callback for hardware SPI interface.
	* No external dependencies.
	* Compact code size and minimal memory use.
* Includes example code for:
    * Most TPM2 native API’s
    * All TPM2 wrapper API's
	* PKCS 7
	* Certificate Signing Request (CSR)
	* TLS Client
	* TLS Server
	* Benchmarking TPM algorithms and TLS

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

The examples in this library are written for use on a Raspberry Pi and use the `spi_dev` interface.

### IO Callback

For interfacing to your hardware platform see the example `examples/tpm_io.c` callback function `TPM2_IoCb`. Here you can modify or insert your own IO callback code for the TPM demo.

There are examples here for Linux, STM32 CubeMX, Atmel ASF and BareBox. The advanced IO option is required for I2C support because it adds the register and read/write flag as parameter to the IO callback.


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

### Building wolfSSL

```
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-certgen --enable-certreq --enable-certext --enable-pkcs7 --enable-cryptodev
make
sudo make install
sudo ldconfig
```

autogen.sh requires: automake and libtool: `sudo apt-get install automake libtool`

### Build options and defines

```
--enable-debug          Add debug code/turns off optimizations (yes|no|verbose) - DEBUG_WOLFTPM, WOLFTPM_DEBUG_VERBOSE, WOLFTPM_DEBUG_IO
--enable-examples       Enable Examples (default: enabled)
--enable-wrapper        Enable wrapper code (default: enabled) - WOLFTPM2_NO_WRAPPER
--enable-wolfcrypt      Enable wolfCrypt hooks for RNG, Auth Sessions and Parameter encryption (default: enabled) - WOLFTPM2_NO_WOLFCRYPT
--enable-advio          Enable Advanced IO (default: disabled) - WOLFTPM_ADV_IO
--enable-st33           Enable ST33 TPM Support (default: disabled) - WOLFTPM_ST33
--enable-i2c            Enable I2C TPM Support (default: disabled, requires advio) - WOLFTPM_I2C
--enable-mchp           Enable Microchip TPM Support (default: disabled) - WOLFTPM_MCHP
WOLFTPM_TIS_LOCK        Enable Linux Named Semaphore for locking access to SPI device for concurrent access between processes.
WOLFTPM_USE_SYMMETRIC   Enables symmetric AES/Hashing/HMAC support for TLS examples.
TLS_BENCH_MODE          Enables TLS benchmarking mode.
NO_TPM_BENCH            Disables the TPM benchmarking example.
```

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

## Running Examples

These examples demonstrate features of a TPM 2.0 module. The examples create RSA and ECC keys in NV for testing using handles defined in `./examples/tpm_io.h`. The PKCS #7 and TLS examples require generating CSR's and signing them using a test script. See `examples/README.md` for details on using the examples. To run the TLS sever and client on same machine you must build with `WOLFTPM_TIS_LOCK` to enable concurrent access protection.

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

Run on ST ST33TP SPI at 33MHz:

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
* Add support for encrypting / decrypting parameters.
* Add support for SensitiveToPrivate inner and outer.
* Add `spi_tis_dev` support for Raspberry Pi.
* Add runtime support for detecting module type ST33, SLB9670 or ATTPM20.


## Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).
