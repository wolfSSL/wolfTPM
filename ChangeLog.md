# Release Notes

## wolfTPM Release 3.10.0 (Dec 4, 2025)

**Summary**

This release includes important bug fixes for password handling, hash algorithm selection, and TLS shutdown. Enhanced CMake support with TPM module selection. Improved Linux TPM resource manager handling. Security improvements for HMAC validation and payload length checks. Various build system improvements and test enhancements.

**Detail**

* Fixes for minor Coverity reports (PR #441)
* Fixed critical bug in password handling (PR #439)
  - Fixed `wolfTPM2_SetKeyAuthPassword` that was truncating password to 2 bytes (bug introduced in PR #427 and release v3.9.2)
  - Added test to catch this and verified no other similar issues exist
* Added Espressif HAL SPI support (PR #386)
* Enhanced CMake support and TPM module selection (PR #438)
  - Added CMake support for choosing a TPM module
  - Finished CMake options to sync with configure
  - Further improvements to CMake interfaces and test scripts
* Security improvements for TPM response validation (PR #437)
  - Validate `TPM2_GetProductInfo` payload length to avoid signed underflow and out-of-bounds access
  - Enforce TPM response HMAC length checks to reject zero-length or mismatched response HMACs for authenticated sessions
* Added Linux TPM Resource Manager support (PR #435, #434)
  - Added persistent access to `/dev/tpmrmX` (enabled with `WOLFTPM_USE_TPMRM`)
  - Fixed TPM Linux `read()` error return code handling
* Fixed crypto callback and hash algorithm selection (PR #433)
  - Fixed crypto callback to return CRYPTOCB_UNAVAILABLE when a TPM key is not set
  - Fixed to use curve type to determine hash type not digest size
* Improved signature verification hash detection (PR #432)
  - Fixed `TPM2_VerifySignature` to detect correct hash algorithm
  - Added more test cases for signature verification
* Improved TLS bidirectional shutdown (PR #431)
  - Improved the TLS bidirectional shutdown
  - Fixed for missing `WC_PK_TYPE_RSA_GET_SIZE` in older releases
* Fixed CMake lock options (PR #430)
  - Fixed backward yes/no logic of `WOLFTPM_NO_LOCK_DEFAULT`
  - Fixed if check statement of `WOLFTPM_NO_LOCK`
  - Updated default logic for `WOLFTPM_NO_LOCK` depending on state of `WOLFTPM_SINGLE_THREADED`
* Build system and testing improvements
  - Added new `make cppcheck` option with fixes for cppcheck
  - Fixed issue with possible use of uninitialized `rc` in `TPM2_GetNonceNoLock`
  - Fixed for build and testing with `--enable-infineon=9670` with additional build tests
  - Support for swtpm port arguments
  - Split up the make tests into matrix (improve test time)
* Various spelling fixes and code cleanup


## wolfTPM Release 3.9.2 (July 30, 2025)

**Summary**

This release includes a security fix for possible buffer overflow in RSA key export functionality. It also adds new key wrapping API's to support exporting the encrypted private key along with crypto callback improvements. Fixes to support TPM2 signing/verification with smaller digest input sizes. Addition of a new HMAC example. Switch to GPLv3.

**Vulnerabilities**

[Medium CVE-2025-7844]: wolfTPM library wrapper function `wolfTPM2_RsaKey_TpmToWolf` copies external data to a fixed-size stack buffer without length validation potentially causing stack-based buffer overflow

Exporting a TPM based RSA key larger than 2048 bits from the TPM could overrun a stack buffer if the default `MAX_RSA_KEY_BITS=2048` is used. If your TPM 2.0 module supports RSA key sizes larger than 2048 bit and your applications supports creating or importing an RSA private or public key larger than 2048 bits and your application calls `wolfTPM2_RsaKey_TpmToWolf` on that key, then a stack buffer could be overrun. If the `MAX_RSA_KEY_BITS` build-time macro is set correctly (RSA bits match what TPM hardware is capable of) for the hardware target, then a stack overrun is not possible.

Fixed in PR #427 (https://github.com/wolfSSL/wolfTPM/pull/427)

**Detail**

* Improvements for key creation and exporting encrypted private key (PR #428)
  - Added helpers for importing external private keys and creating encrypted key blobs (see `wolfTPM2_CreateRsaKeyBlob` and `wolfTPM2_CreateEccKeyBlob`)
  - Added support for crypto callback key generation that exports encrypted private portion (see `TpmCryptoDevCtx.ecdsaKey`)
  - Added a few missing FIPS unlock/lock on private key access (required with wolfCrypt FIPS)
  - Improved crypto callback key generation hash algorithm selection
  - Fixed `WOLFTPM2_USE_SW_ECDHE` build option and added CI tests
  - Cleaned up the user_settings.h logic between wolfTPM and wolfSSL.
* Fixed buffer overrun and security issues (PR #427)
  - Fixed possible buffer overrun issues with RSA key export where wolfCrypt max key size doesn't match TPM support (see CVE-2025-7844)
  - Fixed RSA encrypt/decrypt buffer size check logic
  - Fixed `TPM2_GetWolfRng` to ensure NULL is set on RNG init error
  - Added better defaults for SLB9672/SLB9673
  - Fixed LABEL_MAX_BUFFER and removed duplicate `MAX_ECC_KEY_BYTES`
  - Implemented address sanitizer CI test
* Improved the detection of maximum HASH_COUNT (PR #426 and #427)
* Enhanced HMAC support with persistent keys (PR #422)
  - Added example for HMAC with persistent key (see `examples/wrap/hmac`)
* Improved crypto callback functionality (PR #421)
  - Added support for crypto callback `WC_PK_TYPE_RSA_GET_SIZE`
  - Fixed crypto callback fallback to software when no TPM key is setup
  - Fixed for WC_RNG change to add `pid_t` and added detection of `HAVE_GETPID`
* Enhanced thread safety and CMake support (PR #417, #420)
  - Fixed missing `TPM2_ReleaseLock` in `TPM2_GetProductInfo`
  - Refactored `TPM2_GetNonce` to support non-locking version for internal use
  - Improved CMake support for single threading, mutex locking and active thread local storage
  - Fixed CMake logic for `WOLFTPM_NO_ACTIVE_THREAD_LS`
  - Improved `gActiveTPM` detection for needing thread local
* Improved TPM signing and verification (PR #418)
  - Fixed logic for signing with input digest smaller than key size
  - Improved input digest size logic for TPM2_Sign and TPM2_Verify
  - Added test case with interop for signing
  - Exposed `TPM2_ASN_TrimZeros`
* Enhanced parsing and testing (PR #419)
  - Fixed `TPM2_ParsePublic` size argument
* Improved documentation (PR #424, #425)
  - Added TCG TPM to the SWTPM documentation
* Fixed build system issues (PR #423)
  - Fixed bug in configure.ac which breaks in Alpine


## wolfTPM Release 3.9.1 (May 21, 2025)

* Post release fixes (PR #415)
  - Fixed commercial release bundle (missing `tpm2_asn.h`).
  - Fixed wolfTPM DLL revision (was not updated in v3.9.0).
  - Added `make distcheck` to GitHub CI.


## wolfTPM Release 3.9.0 (May 14, 2025)

**Summary**

Added Zephyr Project support, U-Boot bootloader support, improved thread safety with mutex protection, and various bug fixes. Added support for optional authentication password in keygen and improved ASN.1 certificate parsing.

**Detail**

* Added Zephyr Project Port support (PR #395)
  - Added support for Zephyr RTOS integration
  - Added example for Zephyr TPM usage
* Added U-Boot bootloader support (PR #398)
  - Added support for Das U-Boot bootloader integration
  - Added documentation for U-Boot usage
* Improved thread safety and mutex protection (PR #410)
  - Added global mutex for concurrent thread usage
  - Added support for pthread static mutex with older wolfSSL versions
  - Added build option `WOLFTPM_NO_ACTIVE_THREAD_LS` to remove thread local on `gActiveTPM`
* Added keygen optional authentication password support (PR #409)
  - Added `-auth=<yourpassword>` option to keygen
  - Added test cases for AIK and default key generation
* Improved ASN.1 certificate parsing (PR #404, #408)
  - Added `WOLFTPM2_NO_ASN` build option
  - Refactored ASN.1 parsing for RSA certificates
  - Fixed ASN.1 certificate parsing issues
* Added EK Certificate Verification with TPM only (PR #394)
  - Added support for verifying EK certificates without wolfCrypt
  - Added example for ST33KTPM2X
* Fixed various issues:
  - Fixed possible handle leak in bench example (PR #412)
  - Fixed issue with `wolfTPM2_Init_ex` handling of TPM_RC_INITIALIZE (PR #401)
  - Fixed CSR version handling (PR #406)
  - Fixed location for TPM simulator `/tmp` (PR #398)
  - Fixed spelling and debug issues (PR #398)
  - Fixed run_examples.sh run.out location variable (PR #401)
* Added new API `TPM2_GetHierarchyDesc` for getting hierarchy descriptions (PR #410)
* Added test case for `TPM2_GetAlgId` (PR #398)
* Added missing doxygen documentation for public APIs (PR #401)
* Cleanups for autogen.sh and build system improvements (PR #396)


## wolfTPM Release 3.8.0 (Jan 7, 2025)

**Summary**

Fixes for session auth on key bind and password policy. Added NV extend example used with Bus_Protection_Guidance. New wolfTPM2_NVExtend wrapper and example. Added new NV policy write/read wrapper API's used with policy auth

**Detail**

* Fixed issue with auth session binding. (PR #389)
* Fixed possible missing `wc_GetPkcs8TraditionalOffset`. (PR #392)
* Fixed issue with `wolfTPM2_PolicyHash` where input digest could be too large. (PR #389)
* Added example for NV extend based on the TCG "bus protection guidance". (PR #389)
* Added support for building wolfTPM against older wolfCrypt (like v4.7.0) including CI test. (PR #390)
* Added HAL IO support for Microchip I2C bit-bang (PR #340)
* Created separate tool (./examples/management/tpmclear) for performing the TPM2_Clear (don't use args in wrap_test). (PR #391)
* Switched `wolfTPM2_LoadSymmetricKey` to default to the `WOLFTPM2_WRAP_DIGEST` for hash algorithm and not default to SHA1 for some sizes. (PR #388)
* Improved TPM NV write debug logging to show before. (PR #392)
* Cleanup the `SensitiveToPrivate` function stack variables. (PR #388)
* Cleanup comments on EK/SRK. (PR #388)
* Various spellings, tabs, execute bit on .c and formatting. (PR #386, #388, #392)


## wolfTPM Release 3.6.0 (Nov 5, 2024)

**Summary**

Release includes minor bug fixes and new features such as TPM provisioning of IDevID/IAK, improved capabilities parsing, new TPM2_Certify example, new wolfTPM2_CreatePrimaryKey_ex API for creation ticket and tested support with Nations NS350 TPM.

**Detail**

* Fixed issue with `TPM2_SetupPCRSel` and added test cases. (PR #372)
* Fixed `RC_WARN` error codes (broken in commit f983525f56c245a8bc998bb20f1f6a8cc7ec748f). (PR #378)
* Fixed issue with RSA/ECC symmetric field (should only be populated with restricted/decrypt) (PR #375)
* Fixed examples/keygen/keygen `-sym=` argument. (PR #372)
* Fixed building wolfCrypt/wolfTPM without ECC or RSA and added tests. (PR #371)
* Fixed file descriptor check for `/dev/tpm0` (PR #366)
* Fixed STM32 GPIO SPI CS control to use pin number as bit offset, not direct value (PR #380)
* Fixed issues building with no filesystem. (PR #374)
* Added support for parsing all capabilities from (TPM2_GetCapability) (PR #383)
* Added support for creation of IDevID or IAK with `examples/keygen/create_primary`. (PR #369)
* Added support for Nations NS350. (PR #382)
* Added example for `TPM2_Certify` (see examples/attestation/certify) (PR #369)
* Added new `wolfTPM2_CreatePrimaryKey_ex` and `WOLFTPM2_PKEY` that supports returning creation ticket/hash. (PR #369)
* Added key templates for initial device (IDevID) and attestation keys (IAK). (PR #369)
* Added new build option for TPM provisioning (`--enable-provisioning` on by default). (PR #369)
* Added simple capabilities example (`examples/wrap/caps`) (PR #382)
* Added example to manual verify quote with ECC signature. (PR #379)
* Added tests for policy seal/unseal with multiple PCR's. (PR #377)
* Added `-alg` argument for PCR extend (PR #383)
* Added helper to get wolfCrypt hash type `TPM2_GetTpmHashType` (PR #384)
* Added new policy hash helper API `wolfTPM2_PolicyHash` (PR #369)
* Added documentation for `/dev/tpm0` permissions (PR #366)
* Improved the TPM TLS examples for use with `WOLFTPM_MFG_IDENTITY` (PR #376)
* Moved PTHREAD definition from options.h to config.h (avoids possible re-declaration issue) PR (#381)
* Switched `handle`/`nvIndex` string parsing to use `strtoul`.	(PR #369)
* Various spelling and documentation cleanups. (PR #366 / PR #373)


## wolfTPM Release 3.4.0 (July 30, 2024)

**Summary**

Added Endorsement Key Certificate support. Added support for NV read/write with policy. Added policy password support. Refactor of the session authentication structures.

**Detail**

* Added EK Certificate Support (PR #360)
  - Added new API's `wolfTPM2_GetKeyTemplate_EK` and `wolfTPM2_GetKeyTemplate_EK` for getting EK public templates used for generating the EK primary key.
  - Added `examples/endorsement/get_ek_certs` for showing how to retrieve and validate the manufacturers endorsement key certificates.
* Improvements to auth handling to support Policy Password and Policy Auth Value (PR #350)
  - Refactor to eliminate confusing cast between TPMS_AUTH_COMMAND and TPM2_AUTH_SESSION.
  - Support for policy auth value and policy password.
  - Add new NV policy write/read API's `wolfTPM2_NVWriteAuthPolicy` and `wolfTPM2_NVReadAuthPolicy`.
* Fixed ST33KTPM IAK/IDevID provisioning NV indexes. (PR #361)
* Fixed TLS example build issues with wolfSSL not having crypto callback or PK callback enabled. (PR #360)
* Fixed CSR version (use version 0) (PR #359)
* Fixed issue with Doxygen generation of wolfTPM due to doxybook2 crashing on unnamed enum. (PR #357)
* Fixed HMAC session save last (not typically used) (PR #355)
* Fixed Infineon I2C HAL gating logic (PR #347)
* Added documentation for IAK/IDevID build options. (PR #361)
* Added support for Espressif IDE (see IDE/Espressif) (PR #321)
* Added tests for create_primary (PR #345)
* Improved software TPM (docs/SWTPM.md) documentation (PR #348)


## wolfTPM Release 3.2.0 (Apr 24, 2024)

**Summary**

Added TPM Firmware update support (Infineon SLB9672/SLB9673). Added support for pre-provisioned device identity keys/certificates (STMicro ST33). Fixed issue with sealing secret to prevent `userWithAuth` by default. Expanded the TPM get capabilities support.

**Detail**

* Added new API `wolfTPM2_NVCreateAuthPolicy` for allowing NV creation with policy (PR #344)
* Added Infineon firmware update recovery support (PR #342)
* Added support for Infineon Firmware upgrade (PR #339)
  - Added support for Infineon SLB9672/SLB9673 Firmware upgrade (see examples/firmware/README.md)
  - Added Infineon Modus Toolbox support. See `wolfssl/IDE/Infineon/README.md` for setup instructions.
  - Added support for Infineon CyHal I2C support.
  - Added Firmware extraction tool
  - Added Firmware update example application `examples/firmware/ifx_fw_update`.
  - Added support for vendor capabilities `TPM_CAP_VENDOR_PROPERTY`.
  - Added `XSLEEP_MS` macro for firmware update delay.
  - Added support for getting key group id, operational mode and update counts.
  - Added support for abandoning an update.
  - Added support for firmware update done, but not finalized
  - Added Infineon CyHal SPI support.
  - Fixed auto-detect to not define SLB9672/SLB9673.
* Fixed TLS examples to not use openssl compatibility macros (PR #341)
* Added ST33 support for pre-provisioned device identity key and certificate (PR #336)
  - Added support for pre-provisioned TPM using the "TPM 2.0 Keys for Device Identity and Attestation" specification. See build macro: `WOLFTPM_MFG_IDENTITY`.
  - Added example for using TPM pre-provisioned device identity to TLS client example.
  - Fixed ST33 vendor command to enable command codes (TPM2_SetCommandSet) (it requires platform auth to be set).
  - Added benchmarks for new ST33KTPM2XI2C.
  - Fixed 0x1XX error code parsing.
  - Fixed ST33 part descriptions.
  - Updated example certificates.
* Fixes for building wolfTPM examples with `NO_FILESYSTEM` (PR #338)
* Fixed crypto callback hashing return code initialization (PR #334)
* Updated documentation for Infineon SLB9673 (I2C) (PR #337)
* Fixed Documentation references for generated user manual (PR #335)
* Fixed netdb.h include (PR #333)
* Fixes for building with "-Wpedantic" (PR #332)
* Added new API `wolfTPM2_GetHandles` to get list of handles from the TPM capabilities. (PR #328)
* Fixed config.h, which should only be included from .c files, not headers. (PR #330/#331)
* Fixed CMake tests (PR #329)
* Fixed and improved secret sealing/unsealing (PR #327)
  - Do not set userWithAuth by default when creating sealed objects. That flag allows password auth for the sealed object. Without the flag it only allows policy auth.
  - Allow setting policy auth with flags.
  - Fix secret_unseal to use policy session and valid sealed name.
  - Added expected failure test cases for seal/unseal with policy.
  - Improve the run_examples.sh script
* Improved types for htons and byte swap (PR #326)
  - Match byte swap logic with wolfSSL (use WOLF_ALLOW_BUILTIN).
  - Remove unused `XHTONS` and `arpa/inet.h`.
* Improved STMicro product naming (PR #325)
* Improved the STM32Cube template (PR #324)
  - Setup so next pack can add small stack and transport options: `WOLFTPM_CONF_SMALL_STACK` and `WOLFTPM_CONF_TRANSPORT` (0=SPI, 1=I2C).
* Fixed build error with missing `wc_RsaKeyToPublicDer_ex` (PR #323)
* Improved the ECC macro checks for `wc_EccPublicKeyToDer` (PR #323)
* Added PKCS7 ECC support to example (PR #322)
  - Added wrapper function to export TPM public key as DER/ASN.1 or PEM.
  - Fixed for crypto callback ECC sign to handle getting keySz for unknown cases (like PKCS7 without privateKey set).
* Added expanded key template and cleanups (PR #321)
  - Fixed mixed variable declaration.
  - Added _ex version for GetKeyTemplate RSA/ECC to allow setting all template parameters.


## wolfTPM Release 3.1.0 (Dec 29, 2023)

**Summary**

Support for using TLS PK callbacks with TPM for ECC and RSA. Improved the crypto callback support and added RSA Key generation. Fixed issues with endorsement hierarchy. Added Windows Visual Studio solution and project for wolfTPM. Improved the STM32 HAL IO callback options and logging.

**Detail**

* Removed use of `error-ssl.h` in library proper. (PR #308)
* Fixed CSR crypto callback to use a different (not default) `devId` to avoid conflict. (PR #310)
* Added TPM crypto callback support for RSA key generation (PR #311)
* Fixed and improved for ECC crypto callbacks (PR #311)
  - Allow import of wolf ECC marked as private only (`ECC_PRIVATEKEY_ONLY`).
  - Improve the ECC key import scheme for signing.
  - Improve logic for finding TPM curve in ECC key generation. A call to wc_ecc_make_key can use curve_id 0 (to detect), but we can get it from the "dp".
  - Properly translate a TPM ECC signature verify error for compatibility.
  - Support ECC KeyGen for signing or derive based on callback context `eccKey` or `ecdhKey` population.
  - Fix to make sure leading ECC sign leading zeros are removed when not required.
  - Fix leading zero issue on ECC verify.
* Cleanup KDF function return code checking to avoid scan-build warning. (PR #311)
* Fixed ECC encrypt secret integrity check failed due to zero pad issue. (PR #311)
* Fixed `wolfTPM2_GetRng` possibly not returning an initialized WC_RNG. (PR #311)
* Fixed TLS bidirectional shutdown socket issue due to port collision with SWTPM. (PR #311)
* Fixed `policy_sign` issue when `r` or `s` is less than key size (needs zero padding). (PR #311)
* Fixed building wolfCrypt without PEM to DER support. (PR #311)
* Added support for TLS PK callbacks with ECC and RSA Sign using PKCSv1.5 and PSS padding (PR #312)
  - Fixed building wolfTPM without crypto callbacks.
  - Fixed building/running with FIPS.
  - Cleanup TLS PK callback RSA PSS padding.
  - Cleanup TLS server/client.
  - Added server `-i` option to keep running unless failure.
  - Added TLS server option `-self` to use the self signed certs.
  - Added tests for the TLS PK with TPM.
* Added `CMakeList.txt` to autoconf, so its in the "make dist" commercial bundles. (PR #313)
* Fixed HAL IO prototype to match (`TPM2HalIoCb` and `TPM2_IoCb`) and cast warnings. (PR #313)
* Added support for getting the keyblob sizes if buffer is NULL. (PR #315)
* Added tests for keyblob buffer export/import. (PR #315)
* Added Windows Visual Studio project for wolfTPM. Added GitHub Actions to test it. (PR #316)
* Added support for overriding the PORT/PIN for the STM32 Cube HAL. (PR #314)
* Fixed ECC sign with key that is marked for sign and decrypt detect the ECDSA hash algorithm. (PR #317)
* Fixes for compiler type warnings. (PR #318)
* Added `WOLFTPM_NO_LOCK`. (PR #318)
* Improved STM IO options/logging. (PR #318)
* Fixed attestation with endorsement key (PR #320)
  - Enabled the broken endorsement tests.
  - Improved `TPM2_GetRCString` error rendering to correctly resolve `RC_WARN`.
    - Added error debug for parameter, session and handle number.
    - Refactor line length / alignment.
    - Removed duplicate "success".
  - Removed the `WOLFTPM2_KEYBLOB.name` (deprecated). It is/has been moved to `handle.name`.
  - Fixed native test `TPM2_PolicyPCR`.
  - Fixed CMake build broken, since cryptocb refactor in PR #304.
  - Added CI tests for CMake.


## wolfTPM Release 3.0.0 (Oct 31, 2023)

**Summary**

Refactor of command authentication. Support for ECC sessions and secrets. Support for policy sealing/unsealing. Examples for secure boot.

**Detail**
* Refactor of the command authentication. If command does not require auth do not supply it (PR #305)
* Refactor HAL and added Microchip Harmony SPI HAL support (PR #251)
* Relocate crypto callback code to its own code file (PR #304)
* Fixed using a custom wolfTPM CSR sigType (PR #307)
* Fixed support for ECC 384-bit only support (PR #307)
* Fixed issue with using struct assignment (switched to memcpy) (PR #303)
* Fixed various issues building with C++ compiler (PR #303)
* Fixed issues with STM32 I2C build and improved performance (PR #302)
* Fixed seal with RSA and PCR extend auth. (PR #296)
* Fixed issue including user_settings.h when `--disable-wolfcrypt` set (PR #285)
* Fixed TPM private key import with custom seed (PR #281)
* Fixed autogen.sh (autoconf) to generate without warnings (PR #279)
* Fixed TPM2 create with decrypt or restricted flag set (PR #275)
* Fixed and improved low resource build options (PR #269)
* Fixed the TPM_E_COMMAND_BLOCKED macro to have the correct value (PR #257)
* Fixed casting and unused variable problems on windows (PR #255)
* Fixed Linux usage of `cs_change` and added config overrides (PR #268)
* Fixed and improved the NV auth and session auth set/unset (PR #299)
* Fixed capability to handle unknown `TPM2_GetCapability` type and fix bad printf (PR #293)
* Fixed macros for file IO XFEOF and XREWIND to make sure they are available (PR #277)
* Fixed seal/unseal example (PR #306)
* Fixed TLS examples with param enc enabled (PR #306)
* Fixed signed_timestamp with ECC  (PR #306)
* Added CI tests for CSharp wrappers (PR #307)
* Added support for sealing/unsealing based on a PCR that is signed externally (PR #294)
* Added examples for Secure Boot solution to store root of trust in NV (PR's #276, #289, #291 and #292)
* Added support for importing and loading public ECC/RSA keys formatted as PEM or DER (PR #290)
* Added new policy_nv example (PR #298)
* Added `-nvhandle` argument to nvram examples (PR #296)
* Added code to test external import between two TPM's (PR #288)
* Added support for STM32 Cube Expansion Pack (PR #287)
* Added support memory mapped (MMIO) TPM's (PR #271)
* Added `wc_SetSeed_Cb` call for FIPS ecc (PR #270)
* Added wrapper support for setting key usage (not just extended key usage) (PR #307)
* Added RSA key import methods to handle PEM and DER encoding directly (PR #252)
* Added thread local storage macro and make gActiveTPM local to the thread (PR #253)
* Added Microchip macro names and Support for bench with MPLABX Harmony (PR #256)
* Improvements to cmake build (PR's #280, #283 and #284)

## wolfTPM Release 2.7.0 (Dec 27, 2022)

**Summary**

Added Infineon TriCore HAL support and examples for Keyed Hash / NV counter increment. Minor fixes for NV auth and Keyed Hash.

**Detail**
* Support for Infineon TriCore (TC2XX/TC3XX) using macro `WOLFTPM_INFINEON_TRICORE` (PR #229)
* Added NV counter increment example (PR #243)
* Added Key Generation example for Keyed Hash. (PR #245)
* Fixed for Keyed Hash with HMAC (PR #243)
* Fixed for NV auth handling (PR #243)
* Fixed missing call to `Close()`, since Windows won't flush unless its called (PR #242)
* Fixed `tpm2.c` issue with variable declarations not being at top of function (PR #246)


## wolfTPM Release 2.6 (09/01/2022)

**Summary**

Fix for CSharp wrapper when setting a custom OID for a CSR. Added CSharp wrapper documentation and improved a few others. Added CSharp function to set key password for blob.

**Detail**

* Fix for CSharp `SetCustomExtension` to use allocated byte buffer instead of passing string (PR #239)
* Fixed for CMake `wolftpm/options.h` generation to support disabled source tree changes (`CMAKE_DISABLE_SOURCE_CHANGES`) (PR #235)
* Fixed CMake / vcpkg issue with options.h output location (PR #235)
* Added CSharp `KeyBlob.SetKeyAuthPassword` and test case (PR #237)
* Added API documentation for the CSharp wrappers (PR #234)
* Fixed documentation error on `wolfTPM2_GetKeyBlobAsBuffer` (PR #234)
* Fixed documentation for encDecAlg with authenticated session (PR #236)
* Fixed software TPM (docs/SWTPM.md) example argument for `-rm` (PR #238)


## wolfTPM Release 2.5 (07/22/2022)

**Summary**

Major expansion of the C# wrapper for key handling, CSR/Cert generation, RSA enc/dec and sign/verify.
Added Infineon SLB9672 support.
Enhancements to the CMake support.
Added new keygen example for creating a primary key.

**Detail**

* Fixed issue with sign signature buffer size checking (PR #232)
* Fixed support for using nonce from TPM (when using no wolfCrypt RNG `WOLFTPM2_USE_HW_RNG`) (PR #216)
* Fixed workaround for Windows TBS self test (PR #224)
* Fixed issue with CSharp handle unloading (PR #212)
* Fixed TPM support for using the public key with TLS (PR #210)
* Added crypto callback support for seeding RNG with TPM (PR #216)
* Added Infineon SLB9672 support (PR #214)
* Added support for using a unique template with create and create primary (PR #215)
* Added CSharp wrapper support for RSA encrypt/decrypt and Sign/Verify. (PR #232)
* Added CSharp wrapper documentation for CSR functions (PR #232)
* Added CSharp support for handling TPM errors with exception (PR #224)
* Added CSR wrappers and tests to assist with TPM based CSR/Self-Signed-Cert generation (including CSharp wrappers) (PR #219)
  - Support for subject, key usage, custom request extensions and output as PEM or DER
  - New structure `WOLFTPM2_CSR`, new API's `wolfTPM2_CSR_*` and new CSharp class `Csr`
* Added CSharp create primary key example (PR #215)
* Added CSharp wrapper and tests for `wolfTPM2_CreatePrimaryKey()` (PR #213)
* Added CSharp tests for authenticated sessions (PR #212)
* Added CSharp wrappers `wolfTPM2_SetAuthSession` and `wolfTPM2_NVStoreKey` (PR #209)
* Added CSharp `IDisposable` in classes for cleanup of unmanaged resources (PR #225)
* Added support for wolfTPM CMake to output the options.h (PR #211)
* Added CMake `WOLFTPM_DEBUG` option (PR #211)
* Improved the byte swapping logic for GCC (PR #231)


## wolfTPM Release 2.4 (05/06/2022)

**Summary**

Add CMake support. Add C# wrappers. Add ST33 GetRandom2. Improve
`TPM2_SetupPCRSel`. Fixes for C++ compilers, example install and writing PEM.

**Detail**

* Fixes for c++ compiler (PR #206)
* Adding a C# wrappers (PR #203)
* CMake support (PR #202, #204, #205)
* Add support for ST33 vendor specific command `TPM_CC_GetRandom2` (PR #200)
* Fix writing PEM in `wolfTPM2_RsaKey_TpmToPemPub` (PR #201)
* Improve `TPM2_SetupPCRSel` (multiple calls) (PR #198)
* Fix for a few spelling errors and whitespace cleanup (PR #199)

## wolfTPM Release 2.3.1 (11/18/2021)

**Summary**

Fix for `make install`

**Detail**

* Fix for installing example code on linux builds (PR #196)

## wolfTPM Release 2.3 (11/08/2021)

**Summary**

Fixes for minor build issues, refactor of GPIO configure to combine and new PCR Read example.

**Detail**

* Refactor GPIO support (single gpio_config) (PR #194)
* Fix for Linux HAL IO try again timeout logic  (PR #194)
* Fix for big endian in TIS layer (PR #191)
* Fix for RSAES padding (RSA_Encrypt) (PR #187)
* Fix in tests to allow command code error for CreateLoaded (not supported on hardware) (PR #184)
* Fix for compiler warning for file read in make_credential.c (PR #182)
* Fixes for Windows builds (PR #181)
* Fixes for RSA RNG in edge case builds (fixes wolfBoot build error) (PR #180)
* Added PCR Read example (PR #185)


## wolfTPM Release 2.2 (07/13/2021)

**Summary**

Added new examples for remote attestation, make credential and GPIO support. Added Endorsement hierarchy support to many examples. Refactored the reference HAL IO code into separate files.

**Detail**

* Fixed total auth area size when multiple auth sessions are used (PR #174)
* Fixed `TPM2_SetupPCRSel` to only allow valid pcrIndex values (PR #165 and PR #167)
* Fixed `TPM2_MakeCredential` to work without auth as TCG spec defines (PR #174)
* Fixed `TPM2_MakeCredential` to support using EK pub to encrypt challenge (PR #174)
* Fixed `TPM2_ActivateCredential` to work with EK pub to decrypt challenge (PR #174)
* Fix to only enable `printf` in library proper if `DEBUG_WOLFTPM` is set (PR #154)
* Added support for QNX with wolfTPM (PR #156)
* Added credential examples for remote attestation (PR #161)
* Added new example for sealing a secret using TPM key (PR #157)
* Added GPIO config, read and set examples (PR #155 and #172)
* Added GPIO support and examples for ST33 (PR #155)
* Added GPIO support and examples for Nuvoton NPCT75x (PR #172)
* Added Endorsement support for keygen and attestation examples using `-eh` (PR #174)
* Added missing `TPM2_CreateLoaded` command and added wrapper `wolfTPM2_CreateLoadedKey` (PR #174)
* Added new wrappers for public PEM support `wolfTPM2_RsaKey_TpmToPemPub` and `wolfTPM2_RsaKey_PemPubToTpm` (PR #174)
* Added keygen option to output PEM files for TPM public keys (PR #174)
* Added saving of EK's TPM2B_PUBLIC for attestation purposes (PR #174)
* Added new wrapper for satisfying EK policy (PR #174)
* Added unit test for `TPM2_CertifyCreation` (PR #169)
* Added support for `--with-wolfcrypt=/dir/` (PR #166)
* Added documentation for using QEMU with `--enable-devtpm` for testing (PR #146)
* Modified keygen to use new `wolfTPM2_CreateLoaded` wrapper to acquire correct AK name (PR #174)
* Modified keyload to be able to load keys created under the EK/EH (PR #174)
* Cleanup the ECC point code to appease some coverity warnings (PR #168)
* Cleanup obsolete `txBuf[4] = 0x00;` because handled with SPI check wait state logic (PR #162)
* Improved API documentation using Doxygen for wolfTPM wrappers and proprietary API's (PR #164)
* Improved the Windows TBS documentation (PR #163)
* Refactor the assignment of structs to use memcpy (PR #176)
* Refactor of the TPM IO code to separate files (PR #171)


## wolfTPM Release 2.1 (03/17/2021)

* Fixed possible KDFa buffer overrun (PR #147)
* Fixed typo on `WOLFTPM_USER_SETTINGS` (PR #140)
* Improved examples to use the key templates. (PR #136)
* Added symmetric key support for key generation examples (PR #143)
* Added NVRAM examples (PR #145)
* Added STM32 CubeMX I2C support (PR #142)
* Added details for TPM 2.0 with Windows TBS (PR #144)
* Added alternate subject name to example certificates for TLS (PR #141)
* Updated expired wolfSSL certs (PR #139)
* Removed EK from the attestation and signed timestamp examples (PR #152)


## wolfTPM Release 2.0 (12/07/2020)

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


## wolfTPM Release 1.9 (08/24/2020)

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


## wolfTPM Release 1.8 (04/28/2020)

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


## wolfTPM Release 1.7 (12/27/2019)

**Summary**

Adds new wrappers for Non-Volatile (NV), changing auth for a key and shutdown.

**Detail**

* Fixes for coverity checks on buffers. (PR #78)
* Fix visibility warnings in Cygwin. (PR #80)
* Added wrapper for changing a key's authentication `wolfTPM2_ChangeAuthKey`. (PR #77)
* Added support for using authentication with NV. (PR #79)
* Adds new wrapper API's: `wolfTPM2_NVWriteAuth`, `wolfTPM2_NVReadAuth` and `wolfTPM2_NVDeleteAuth`. (PR #79)
* Added new wrappers for shutdown and handle cleanup. (PR #81)


## wolfTPM Release 1.6 (08/01/2019)

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


## wolfTPM Release 1.5 (02/20/2019)

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


## wolfTPM Release 1.4 (11/13/2018)

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


## wolfTPM Release 1.3 (07/20/2018)

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


## wolfTPM Release 1.1 (03/09/2018)

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


## wolfTPM Release 1.0 (02/06/2018)

* Support for all TPM2 native API's using TIS and SPI IO callback.
* Helper for getting TPM return code string `TPM2_GetRCString`.
* TPM 2.0 demo code in `examples/tpm/tpm2_demo.c` with support for STM32 CubeMX SPI as reference.
