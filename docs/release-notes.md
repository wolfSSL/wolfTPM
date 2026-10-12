# Release Notes

This page tracks recent wolfTPM releases. It reproduces the Unreleased section and the two most recent releases from the repository ChangeLog. The complete history, back to the first release, is in [ChangeLog.md](https://github.com/wolfSSL/wolfTPM/blob/master/ChangeLog.md) at the top of the repository.

## Unreleased

* Added `wolfTPM2_AllocatePCRBanks` for changing which PCR banks a TPM allocates.
  - Added `examples/pcr/allocate` to report and re-provision the banks.
  - Fixed the fwTPM applying the allocation immediately instead of at the next
    `Startup(CLEAR)` per TPM 2.0 Part 3 22.5, accepting a selection that would
    leave it with no PCR banks, ignoring the `pcrSelect` bitmap, and reporting
    no allocated banks after a restart against an existing NV file.

## wolfTPM Release 4.2.0 (Sep 14, 2026)

**Summary**

Feature and maintenance release centered on TCG TPM 2.0 v1.85 specification
compliance in the firmware TPM (fwTPM), expanded post-quantum support, and new
platform backends. Highlights: a broad set of fwTPM v1.85 compliance fixes
(command attributes, PolicyAuthorize, context-blob authentication, NV
authorization, ticket HMAC ordering), plus SPDM responder corrections;
ML-DSA authentication for post-quantum TLS 1.3 and SealSQ QVault post-quantum
TPM support; wolfHAL I2C/SPI backends and NVIDIA Jetson Orin OP-TEE fwTPM
support; ST33 firmware-update corrections; transport and NV/hash performance
improvements; and extensive security hardening (Coverity, static analysis, and
negative tests).

**Detail**

* Firmware TPM (fwTPM) TCG v1.85 specification compliance
  - Command-code masking and vendor-bit return-code fix (PR #556)
  - Corrected auth-entry handling (PR #566)
  - PolicyAuthorize compliance fixes and corrected response codes for the
    keySign name ticket and approvedPolicy (PRs #567, #572)
  - Authenticate object context blobs on ContextSave/ContextLoad (PR #568)
  - Reject unsupported LoadExternal private types, fix creation-ticket HMAC
    ordering, and validate ML-DSA / ML-KEM templates in LoadExternal and
    CreateLoaded (PRs #573, #578)
  - Validate NV space authorization and report the v1.85 revision (PR #575)
  - Fix hierarchy and policy-authorization gaps and SPDM responder version
    negotiation (PR #577)
  - Correct command-attribute reporting and the verified-ticket HMAC algorithm
    (PR #579)
  - Additional TCG v1.85 fwTPM and SPDM compliance fixes (PR #584)
* Post-quantum and TLS
  - TPM-backed ML-DSA authentication for post-quantum TLS 1.3, with an example
    and tests (PR #559)
  - SealSQ QVault post-quantum TPM support (PR #570)
  - ML-KEM credential activation and ML-DSA quotes in the fwTPM (PR #592)
* New platform and HAL support
  - wolfHAL I2C and SPI backends, enabled with `--enable-wolfhal` and an
    application-supplied `board.h` (PR #562)
  - NVIDIA Jetson Orin (Tegra234) OP-TEE firmware TPM, reached through the
    Linux TPM kernel driver as `/dev/tpmrm0` (PR #576)
  - Finer per-command-group gating macros in the fwTPM (PR #574)
  - Caller-supplied policy authorization for firmware upgrade (PR #560)
* ST33 firmware update
  - Fix Generation 1 manifest size and refuse oversized commands (PR #583)
  - Select ST33 field-upgrade commands from the TPM command set (PR #586)
* Performance
  - Reuse transport connections and reduce NV-write and hash-cache overhead
    (PR #563)
* Security hardening (Coverity, static analysis, input validation)
  - Harden the crypto callback, ASN.1 parsing, parameter encryption, and
    marshalling, with negative tests (PR #551)
  - Bound the TPM2 response decrypt-parameter size, zeroize primary-key auth,
    and expand marshalling/import test coverage (PR #555)
  - Guard a tainted PCR-select copy in the fwTPM properties path (PR #558)
  - Fix a fwTPM response buffer overflow and an SPDM clear-frame command bypass
    (PR #561)
  - Harden wolfTPM2 PCR/hash wrapper validation (PR #554)
  - Strengthen TPM input validation and memory handling (PR #565)
  - Fix a wolfCrypt refcount race in P521 primary derivation and a policy-session
    authorization bypass (PR #571)
  - Harden PCR policy bounds checks (PR #581)
  - Harden wolfTPM validation and data handling (PR #582)
  - Harden fwTPM protocol handling and SPDM authentication (PR #588)
  - Make fwTPM state changes transactional and harden PolicyPCR and
    private-blob wrapping (PR #593)
  - Additional Coverity fixes across the TPM bounds and configuration paths,
    including bounded fwTPM child-blob copies, a guarded public-name buffer
    allocation, and restricted unsealed-output file permissions
    (PRs #591, #595, #603, #605)
  - Harden fwTPM key derivation and command validation (PR #596)
  - Fix TPM2 core key-import parsing and response handling and improve core
    zeroization and robustness (PRs #597, #600)
  - Harden error handling and secret zeroization in the examples, SPI transfer,
    and SPDM version parsing (PRs #598, #599, #604)
  - Reject truncated fwTPM Rewrap input, require bound authorization for policy
    sessions over empty-policy objects, bind the full keyed-hash secret into the
    public name, fail public-area parsing on overflow, normalize the TIS
    locality return, and clear residual request bytes from the shared command
    buffer (PR #608)
* Build fixes
  - Fix AES_BLOCK_SIZE undeclared under OPENSSL_COEXIST wolfSSL (PR #552)
  - Fix an edge-case build with TIS lock and no wolfCrypt (PR #564)
  - Fix the --enable-pqc build with --disable-wolfcrypt (PR #606)
  - Refresh the expired wolfSSL example CA certificates and add a refresh
    script (PR #601)
* Documentation and licensing
  - Add contribution guidance (CONTRIBUTING.md) (PR #569)
  - GPLv2 exception to the base GPLv3 license: wolfTPM combined with U-Boot
    from Cisco Systems, Inc. may be licensed under GPLv2 (PR #557)

## wolfTPM Release 4.1.0 (Jul 10, 2026)

**Summary**

Feature release centered on TPM locality control and expanded post-quantum support. Highlights: runtime locality selection (`wolfTPM2_SetLocality`) with a corrected fwTPM per-PCR locality enforcement table and an optional GPIO nRST reset HAL; TPM 2.0 v1.85 post-quantum (ML-DSA / ML-KEM) support brought into the firmware TPM with fine-grained build macros; fwTPM Dictionary Attack hardening, transparent `TPM_RC_RETRY` handling, and SPDM secured transport for the fwTPM; FIPS 140-3 capability reporting; freestanding (no-libc) build support; SBOM (CycloneDX / SPDX) generation for EU Cyber Resilience Act (CRA) compliance; and extensive security hardening (Coverity, CodeQL).

**Detail**

* Runtime TPM locality control (PR #546)
  - New `wolfTPM2_SetLocality(dev, locality)` selects locality 0-4 at runtime, and `examples/pcr/reset` takes a `-loc=n` flag. Works on the built-in TIS/SPI driver (with release-and-retry for non-preempting chips) and the fwTPM over both socket and TIS/SHM; returns `NOT_COMPILED_IN` where locality is not selectable (I2C, Linux kernel driver, Windows TBS)
  - fwTPM per-PCR locality enforcement replaced with one source-of-truth table (TCG PC Client profile): corrects the reset map, adds the missing PCR-extend check, and reports proper `RESET_L*`/`EXTEND_L*`/`DRTM_RESET` bitmaps. Behavior change: DRTM PCRs 17-22 can no longer be extended from locality 0 (now `TPM_RC_LOCALITY`)
  - Fixed `TPM_CAP_ALGS`/`TPM_CAP_COMMANDS` paging to honor the property cursor so clients that follow `moreData` make progress
  - Optional hardware-reset HAL: `--enable-hal-reset[=LINE]` adds `TPM2_IoCb_Reset()`, pulsing the nRST line via the Linux GPIO char device (default ST33 GPIO24, Nuvoton GPIO4)
* TPM 2.0 v1.85 post-quantum (PQC) support in the fwTPM: ML-DSA sign/verify, ML-KEM encap/decap, and seed handling to TCG Phase B, with PQC CI and fuzz coverage (PR #445)
  - Fine-grained build macros to trim the footprint: `WOLFTPM_PQC` (the new lean `--enable-pqc`), per-algorithm `WOLFTPM_MLDSA`/`WOLFTPM_MLKEM`, and per-operation gates, plus `--enable-mldsa[=...]` / `--enable-mlkem[=...]` / `--disable-hash-mldsa` (PRs #527, #533)
  - wolfSSL v5.8.0+ PQC floor and upstream-drift CI; ML-DSA `TPM2_CreateLoaded` primary and PQC parameter encryption in the examples; new `_ex` session/OAEP/PQC-hash wrappers (PRs #501, #509, #531, #539, #520)
* fwTPM Dictionary Attack (DA) hardening to the TCG spec (PR #541): `noDA` honored on objects, `failedTries` persisted with the non-orderly-shutdown penalty, `recoveryTime`/`lockoutRecovery` self-heal, and DA properties reported via `TPM2_GetCapability`. Adds `wolfTPM2_DictionaryAttackLockReset`/`wolfTPM2_DictionaryAttackParameters`, an `examples/management/da_check` example, and the `tests/fwtpm_da_retry.sh` harness
* Optional transparent `TPM_RC_RETRY` handling for TPMs that momentarily report busy; opt in via `TPM2_SetCommandRetries` or `-DWOLFTPM_MAX_RETRIES=N`, or compile out with `WOLFTPM_NO_RETRY` (PR #537)
* SPDM secured transport extended to the fwTPM (PR #510), and FIPS 140-3 capability reporting (PR #502)
* fwTPM session, policy, and NV fixes: transient state kept across command-port reconnects, `continueSession` set in the password-auth response, PolicyAuthorize zero-ticket handling, and an append-only NV journal for write-once flash ports (PRs #518, #530, #517, #540)
* New examples and options: crypto-primitive examples (getrandom, hash, AES, ECDH), a `WOLFTPM2_ECC_DEFAULT_CURVE` option (ZD 21780), and native_test ECC P-384 coverage (PRs #532, #519, #492)
* Nations NS350 example-suite fixes: RSA-4096 buffer sizing and SRK algorithm selection from the stored key type (PR #494)
* Freestanding build support: `WOLFTPM_NO_STD_HEADERS` keeps the standard C headers out of `tpm2_types.h` for bare-metal integrators, with a `freestanding-build.yml` CI job (PR #549)
* Software Bill of Materials (SBOM) generation for EU Cyber Resilience Act (CRA) compliance: new `make sbom` / `install-sbom` autotools targets and a CMake `sbom` target emit CycloneDX and SPDX documents for the built library, recording wolfSSL as a dependency (PR #536)
* Security hardening: automated security review (bounds/OOB fixes in the TPM2 packet parsers and marshaling, secret zeroization, policy/ticket bypass fixes), Coverity fixes across the fwTPM PCR/seed/hash/seal paths, CodeQL/Semgrep/Copilot review gates, and a heap out-of-bounds read fix in `TPM2_ASN_RsaUnpadPkcsv15` (PRs #496, #503, #511, #512, #518, #523, #535, #545, #547, #548, #543, #542, #544, #538, #513, #514, #524, #528, #507, #516)
* CI and build improvements: expanded CMake test cases, a GHCR container image, nightly fuzzing, wolfSSL latest-stable auto-resolve, and preflight smoke tests (PRs #495, #534, #522, #525, #508, #526, #521)
* Bug fixes
  - Fixed the wolfCrypt crypto callback to propagate `ALREADY_E` for wolfSSL PR 10604 (PR #546)
  - Ensured the wolfCrypt DRBG is used with crypto callbacks and made `TPM2_StirRandom` a TCG-compliant no-op on HW-RNG-backed TPMs (PRs #498, #493)
  - Added a note on using the TPM RNG for the StartAuth session nonce (ZD 21476, PR #478)


## Full History

Older releases are not repeated here. See `ChangeLog.md` in the repository root for every release.

## See Also

- [Testing and CI](testing.md)
- [SBOM and Compliance](sbom-and-compliance.md)
- [API Reference](api-reference.md)
