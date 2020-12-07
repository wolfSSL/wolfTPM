## Release Notes

### wolfTPM Release 2.0 (12/07/2020)

**Summary**

Added AES CFB parameter encryption, HMAC sessions, TPM simulator, Windows TPM (TBSI) support and more examples for time/keys.

**Detail**

* Refactor of the session authentication. New struct `TPM2_AUTH_SESSION`  and `wolfTPM2_SetAuth_*` API's. (PR #129 and #133)
* Added Windows TPM TBSI support (PR #127)
* Added TPM simulator support using TPM TCP protocol (PR #121)
* Added minGW support (PR #127)
* Added AES CFB parameter encryption support (PR #129)
* Added XOR parameter encryption support (PR #122)
* Added "-aes" or "-xor" option to some examples to enable parameter encryption. (PR #129)
* Added HMAC session support (PR #129)
* Added support for encrypted RSA salt for salted-unbounded session (PR #129)
* Added innerWrap and outerWrap support for sensitive to private. (PR #129)
* Improvements to the KDFa (PR #129)
* Improved the param encryption to use buffers inline (PR #129)
* Added Key generation and loading examples using disk to store the key (PR #131)
* Added support for importing external private key to get a key blob for easy re-loading. (PR #132)
* Add TPM clock increment example (PR #117)
* Add test vectors for AES CFB and make it the default for tests (PR #125)
* Improved documentation and code comments (PR #126)
* Add script to run unit tests with software TPM (PR #124)


### wolfTPM Release 1.9 (08/24/2020)

**Summary**

Added NPCT75x Nuvoton support, dynamic module detection, and attestation key wrappers.

**Detail**

* Fix when building wolfSSL with old names `NO_OLD_WC_NAMES`. (PR #113)
* Fix for TPM2 commands with more than one auth session. (PR #95)
* Bugfixes for TPM2_Packet_AppendSymmetric and TPM2_Packet_ParseSymmetric. (PR #111)
* TPM attestation fixes. (PR #103)
* If creating an NV and it already exists, set auth and handle anyways. (PR #99)
* Cleanups, removed unused code from the PCR examples. (PR #112)
* Improvements to the signed timestamp example. (PR #108)
* Add example of a TPM2.0 Quote using wolfTPM. (PR #107)
* Added NPCT75x Nuvoton support and dynamic module detection support. (PR #102)
* Added RSA sign/verify support and expanded RSA key loading API's. (PR #101)
* Attestation key wrappers. (PR #100)
* Add missing xor overload to TPMU_SYM_KEY_BITS. (PR #97)
* Signed timestamp example (AIK and Attestation). (PR #96)
* Adding more testing. (PR #93)
* Add TPM benchmarking results for Nuvoton NPCT650 TPM2.0 module. (PR #92)


### wolfTPM Release 1.8 (04/28/2020)

**Summary**

Added Xilinx Zynq UltraScale+ MPSoC, Linux TIS kernel driver, Nuvoton and Nations Tech TPM module support.

**Detail**

* Fixed obsolete workaround for ST33 and TIS header size. (PR #85)
* Fixes for building with older wolfSSL versions not supporting `wc_HashFree`. (PR #87)
* Fixes for building without wolfCrypt RSA (when `NO_RSA` is defined). (PR #89)
* Fixes for ECC verify in crypto callback to try software if the curve is not supported (`TPM_RC_CURVE`) by the TPM hardware. (PR #89)
* Fixes for building with `WOLFTPM2_USE_SW_ECDHE`. (PR #86)
* Added support for using `/dev/tpmX`. (PR #91)
* Added example for using an ECC primary storage key (root owner). (PR #84)
* Added Xilinx Zynq MPSoC bare-metal SPI support. (PR #85)
* Added support for Nuvoton TPM 2.0 NPCT650. (PR #91)
* Added support for Nations Technologies Inc. TPM 2.0 module (Z32H330). (PR #88)
* Cleanup of the session auth, so after being set it is also cleared. (PR #84)
* Moved the chip specific settings to `tpm2_types.h`. (PR #85)


### wolfTPM Release 1.7 (12/27/2019)

**Summary**

Adds new wrappers for Non-Volatile (NV), changing auth for a key and shutdown.

**Detail**

* Fixes for coverity checks on buffers. (PR #78)
* Fix visibility warnings in Cygwin. (PR #80)
* Added wrapper for changing a key's authentication `wolfTPM2_ChangeAuthKey`. (PR #77)
* Added support for using authentication with NV. (PR #79)
* Adds new wrapper API's: `wolfTPM2_NVWriteAuth`, `wolfTPM2_NVReadAuth` and `wolfTPM2_NVDeleteAuth`. (PR #79)
* Added new wrappers for shutdown and handle cleanup. (PR #81)


### wolfTPM Release 1.6 (08/01/2019)

**Summary**

Improvements for compatibility, chip detection, initialization options and small stack. Adds new wrapper API's for PCR extend. Adds support for using HMAC with existing key.

**Detail**
* Fix for wolfCrypt init/cleanup issue with reference count. (PR #75)
* Fix to restore existing TPM context after calling `wolfTPM2_Test`. (PR #74)
* Fix to resolve handling of unsupported ECC curves with the TPM module and ECDHE. (PR #69)
* Fix for `wolfTPM2_SetCommand` to ensure auth is cleared. (PR #69)

* Added `--enable-smallstack` build options for reducing stack usage. (PR #73)
* Added support for keeping an HMAC key loaded. (PR #72)
* Added API unit test framework. (PR #71)
* Added new wrapper API `wolfTPM2_OpenExisting` for accessing device that's already started. (PR #71)
* Added new `wolfTPM2_ExtendPCR` wrapper. (PR #70)
* Added crypto callback flags for FIPS mode and Use Symmetric options. (PR #69)
* Added `WOLFTPM_DEBUG_TIMEOUT` macro for debugging the timeout checking. (PR #69)
* Added support for ST33 `TPM2_SetMode` command for disabling power saving. (PR #69)
* Improvements for chip detection, compatibility and startup performance (PR #67)
	* Added support for `XPRINTF`.
	* Fix printf type warnings.
	* Moved the TPM hardware type build macro detection until after the `user_settings.h` include.
	* Optimization to initialize Mutex and RNG only when use is required.
	* Added missing stdio.h for printf in examples.
	* Added new API's `TPM2_SetActiveCtx`, `TPM2_ChipStartup`, `TPM2_SetHalIoCb` and `TPM2_Init_ex`.
	* Allowed way to indicate `BOOL` type already defined.
	* Added C++ support.
* Added new API `wolfTPM2_Test` for testing for TPM and optionally returning capabilities. (PR #66)
* Added way to include generated `wolftpm/options.h` (or customized one) using `WOLFTPM_USER_SETTINGS`. (PR #63)


### wolfTPM Release 1.5 (02/20/2019)

**Summary**

Adds support for the Microchip ATTPM20 TPM 2.0 module and Barebox bootloader. Improvements for TLS client/server examples and overall performance. Adds TPM wrappers for HMAC, AES Key Loading and Benchmarking support for RNG/AES/Hashing/TLS.

**Detail**

* Fixed issue with cleanup not unregistering the crypto callback. (PR #60)
* Added support for Microchip ATTPM20 part. (PR #59)
* Added support for Barebox (experimental). (PR #52)
* Added TLS benchmarking for CPS and KB/Sec. Enabled with `TLS_BENCH_MODE`. (PR #56)
* Added TLS client/server support for symmetric AES/HMAC/RNG. Enabled with `WOLFTPM_USE_SYMMETRIC`. (PR #56)
* Added TLS client/server support for mutual authentication. (PR #56)
* Added TIS locking protection for concurrent process access. Enabled using `WOLFTPM_TIS_LOCK`. (PR #56)
* Added symmetric AES encrypt and decrypt wrappers and examples. (PR #54 and PR #55)
* Added HMAC wrappers and examples. (PR #56)
* Added wrappers and examples for loading external HMAC and AES keys. (PR #56)
* Added delete key wrapper and example. (PR #58)
* Added ECDH support for ephemeral key generation and shared secret. (PR #50)
* Added benchmark support for RNG, AES (CTR, CBC, CFB) 128/256 and SHA-1, SHA-256, SHA-384 and SHA-512. (PR #54)
* Added new `wolfTPM2_GetCapabilities` wrapper API for getting chip info. (PR #51)
* Added command and response logging using `./configure --enable-debug=verbose` or `#define WOLFTPM_DEBUG_VERBOSE`. (PR #54)
* Added option to enable raw IO logging using `WOLFTPM_DEBUG_IO`. (PR #54)
* Added option to disable TPM Benchmark code using `NO_TPM_BENCH`. (#60)
* Added examples/README.md for setup instructions.
* Tuned max SPI clock and performance for supported TPM 2.0 chips. (PR #56)
* Cleanup to move common test parameters into examples/tpm_test.h. (PR #54)
* Updated benchmarks and console output for examples in README.md.


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
