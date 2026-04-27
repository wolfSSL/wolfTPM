# wolfTPM Firmware TPM (fwTPM / fTPM / swtpm) Server

A portable firmware TPM 2.0 implementation built entirely on wolfCrypt. The
fwTPM provides a standards-compliant TPM 2.0 command processor that can replace
a hardware TPM on embedded platforms without a discrete TPM chip, or serve as a
drop-in development and CI/CD replacement for external simulators. Supports TCP
socket transport (Microsoft TPM simulator protocol, compatible with wolfTPM
examples and tpm2-tools) and TIS register-level transport over shared memory or
SPI/I2C for bare-metal integration. Implements 105 of 113 TPM 2.0 v1.38 commands
(93% coverage) with HAL abstractions for IO and NV storage portability.

Post-quantum cryptography support is available with `--enable-pqc` (alias for
`--enable-v185`), adding ML-DSA (FIPS 204) signing and ML-KEM (FIPS 203) key
encapsulation per TCG TPM 2.0 Library Specification v1.85. Configure
auto-detects PQC and enables it when `--enable-fwtpm` is built against a
wolfCrypt that has both. See [`docs/FWTPM.md`](../../docs/FWTPM.md#tpm-20-v185-post-quantum-support)
for algorithm and command details.

## Building

wolfSSL must be built with `--enable-keygen` and `WC_RSA_NO_PADDING`:

```bash
cd wolfssl
./configure --enable-wolftpm --enable-pkcallbacks --enable-keygen CFLAGS="-DWC_RSA_NO_PADDING"
make && make install
```

Then build wolfTPM with the fwTPM server:

```bash
cd wolftpm
./configure --enable-fwtpm --enable-swtpm
make
```

## Running

```bash
# Listens on localhost:2321 (cmd) and :2322 (platform)
src/fwtpm/fwtpm_server

# Optionally start with clear NV
src/fwtpm/fwtpm_server --clear
```

## Testing with tpm2-tools

In socket mode (`--enable-swtpm`), the fwTPM server supports both the **mssim**
(Microsoft TPM simulator) and **swtpm** (Stefan Berger) TCTI protocols via
auto-detection on the command port. Either TCTI works:

```bash
# Using mssim TCTI (default for wolfTPM test scripts)
export TPM2TOOLS_TCTI="mssim:host=localhost,port=2321"
tpm2_startup -c

# Using swtpm TCTI (also works — auto-detected)
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"
tpm2_getrandom 8
```

The `--port` and `--platform-port` options are socket-mode only and not
available in TIS builds (`--enable-fwtpm` without `--enable-swtpm`).

## Testing with wolfTPM examples

wolfTPM examples use the built-in swtpm client which speaks the mssim protocol
automatically:

```bash
./examples/wrap/caps
./examples/keygen/keygen
```

## Test Suite

```bash
# Full test: unit.test + run_examples.sh + tpm2-tools (311 tests)
make check

# tpm2-tools only
scripts/tpm2_tools_test.sh
```

`make check` runs `tests/fwtpm_check.sh`, which manages the
`fwtpm_server` lifecycle automatically.

## CI Tests (fwtpm-test.yml)

All tests below run in GitHub Actions CI. Run manually before PR submission.

### Runtime Tests (build + run_examples.sh + make check)

| Name | wolfTPM Config | Extra | Notes |
|------|---------------|-------|-------|
| fwtpm-socket | `--enable-fwtpm --enable-swtpm --enable-debug` | | Primary test |
| fwtpm-tis | `--enable-fwtpm --enable-debug` | | TIS/SHM transport |
| fwtpm-asan | `--enable-fwtpm --enable-swtpm --enable-debug` | `-fsanitize=address` | Memory errors |
| fwtpm-ubsan | `--enable-fwtpm --enable-swtpm --enable-debug` | `-fsanitize=undefined` | UB detection |

### Build-Only Tests

| Name | wolfTPM Config | wolfSSL Config | Extra CFLAGS |
|------|---------------|---------------|-------------|
| fwtpm-no-rsa | `--enable-fwtpm --enable-swtpm` | `--disable-rsa` | |
| fwtpm-no-ecc | `--enable-fwtpm --enable-swtpm` | `--disable-ecc` | |
| fwtpm-only | `--enable-fwtpm-only --enable-swtpm` | | No client library |
| fwtpm-minimal | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_ATTESTATION -DFWTPM_NO_NV -DFWTPM_NO_POLICY -DFWTPM_NO_CREDENTIAL -DFWTPM_NO_DA -DFWTPM_NO_PARAM_ENC` |
| fwtpm-no-policy | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_POLICY` |
| fwtpm-no-nv | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_NV` |
| fwtpm-no-attestation | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_ATTESTATION` |
| fwtpm-no-credential | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_CREDENTIAL` |
| fwtpm-no-da | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_DA` |
| fwtpm-no-param-enc | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_PARAM_ENC` |
| fwtpm-no-rsa-no-policy | `--enable-fwtpm --enable-swtpm` | `--disable-rsa` | `-DFWTPM_NO_POLICY` |
| fwtpm-no-ecc-no-nv | `--enable-fwtpm --enable-swtpm` | `--disable-ecc` | `-DFWTPM_NO_NV` |
| fwtpm-small-stack | `--enable-fwtpm --enable-swtpm` | | `-DWOLFTPM_SMALL_STACK` |

### Pedantic Builds (build-only, -Werror)

| Name | Compiler | Config |
|------|----------|--------|
| fwtpm-pedantic-gcc | gcc | `--enable-fwtpm --enable-swtpm` |
| fwtpm-pedantic-clang | clang | `--enable-fwtpm --enable-swtpm` |
| fwtpm-pedantic-only | gcc | `--enable-fwtpm-only` |

### Separate Job: tpm2-tools (311 tests)

```bash
scripts/tpm2_tools_test.sh
```

## Build Options and Feature Macros

See [docs/FWTPM.md](../../docs/FWTPM.md) for the full list of configure options,
compile-time macros (feature groups, algorithm flags, size limits, stack/heap
control), spec version targeting, and HAL abstraction details.

Key options: `--enable-fwtpm`, `--enable-fwtpm-only`, `--enable-swtpm`,
`--enable-fwtpm-small-ctx`, `--enable-fuzz`. Feature disable macros:
`FWTPM_NO_ATTESTATION`, `FWTPM_NO_NV`, `FWTPM_NO_POLICY`, `FWTPM_NO_CREDENTIAL`,
`FWTPM_NO_DA`, `FWTPM_NO_PARAM_ENC`.

## TPM 2.0 Command Coverage

### Currently Implemented (105 commands)

The fwTPM implements 105 of 113 commands from the v1.38 baseline (93% coverage).

**Always enabled (47 commands):**
Startup, Shutdown, SelfTest, IncrementalSelfTest, GetTestResult, GetRandom,
StirRandom, GetCapability, TestParms, PCR\_Read, PCR\_Extend, PCR\_Reset,
PCR\_Event, PCR\_Allocate, PCR\_SetAuthPolicy, PCR\_SetAuthValue,
ReadClock, ClockSet, ClockRateAdjust, CreatePrimary, FlushContext,
ContextSave, ContextLoad, ReadPublic, Clear, ClearControl, ChangeEPS, ChangePPS, HierarchyControl,
HierarchyChangeAuth, SetPrimaryPolicy, EvictControl, Create, ObjectChangeAuth,
Load, Sign, VerifySignature, Hash, HMAC, HMAC\_Start, HashSequenceStart,
SequenceUpdate, SequenceComplete, EventSequenceComplete, StartAuthSession,
Unseal, LoadExternal, Import, Duplicate, Rewrap, CreateLoaded,
Vendor\_TCG\_Test

**Conditional on algorithm (`NO_RSA` / `HAVE_ECC` / `NO_AES`):**
RSA\_Encrypt, RSA\_Decrypt, ECDH\_KeyGen, ECDH\_ZGen, ECC\_Parameters,
EC\_Ephemeral, ZGen\_2Phase,
EncryptDecrypt, EncryptDecrypt2

**Conditional on feature macros:**
- `FWTPM_NO_POLICY`: PolicyGetDigest, PolicyRestart, PolicyPCR, PolicyPassword,
  PolicyAuthValue, PolicyCommandCode, PolicyOR, PolicySecret, PolicyAuthorize,
  PolicyLocality, PolicySigned, PolicyNV, PolicyPhysicalPresence, PolicyCpHash,
  PolicyNameHash, PolicyDuplicationSelect, PolicyNvWritten, PolicyTemplate,
  PolicyCounterTimer, PolicyTicket, PolicyAuthorizeNV (21 commands)
- `FWTPM_NO_NV`: NV\_DefineSpace, NV\_UndefineSpace, NV\_UndefineSpaceSpecial,
  NV\_ReadPublic, NV\_Write, NV\_Read, NV\_Extend, NV\_Increment, NV\_WriteLock,
  NV\_ReadLock, NV\_SetBits, NV\_ChangeAuth, NV\_GlobalWriteLock (13 commands).
  Also gates PolicyNV and PolicyAuthorizeNV when policy is enabled.
- `FWTPM_NO_ATTESTATION`: Quote, Certify, CertifyCreation, GetTime, NV\_Certify
- `FWTPM_NO_CREDENTIAL`: MakeCredential, ActivateCredential
- `FWTPM_NO_DA`: DictionaryAttackLockReset, DictionaryAttackParameters (2 commands)
- `FWTPM_NO_PARAM_ENC`: Disables parameter encryption/decryption for command and
  response parameters. Sessions still work for HMAC auth, but encrypted transport
  is disabled. Reduces code size by removing AES-CFB and XOR param encryption.

### Missing Commands -- TODO

#### v1.38 Baseline (8 missing commands)

##### Medium (moderate logic, builds on existing infrastructure)

| Command | Spec Section | Difficulty | Notes |
|---------|-------------|------------|-------|
| `TPM2_SetCommandCodeAuditStatus` | 21.2 | Medium | Manage list of commands that are audited. Needs audit bitmap in context |
| `TPM2_PP_Commands` | 26.2 | Medium | Manage physical presence command list. Needs PP command bitmap |

##### Hard (complex crypto or new subsystems)

| Command | Spec Section | Difficulty | Notes |
|---------|-------------|------------|-------|
| `TPM2_GetSessionAuditDigest` | 18.5 | Hard | Sign session audit digest. Requires session audit tracking (running hash of all commands in session). New subsystem |
| `TPM2_GetCommandAuditDigest` | 18.6 | Hard | Sign command audit digest. Requires command audit log with running hash. New subsystem |
| `TPM2_Commit` | 19.2 | Hard | DAA/anonymous attestation ephemeral key. Complex ECC point math (K,L,E generation). Needs DAA support in wolfCrypt |
| `TPM2_SetAlgorithmSet` | 26.3 | Hard | Vendor-specific algorithm configuration. Rarely implemented, can return TPM_RC_COMMAND_CODE |
| `TPM2_FieldUpgradeStart` | 27.2 | Hard | Firmware upgrade initiation. Vendor-specific, requires secure update infrastructure |
| `TPM2_FieldUpgradeData` | 27.3 | Hard | Firmware upgrade data blocks. Vendor-specific |
| `TPM2_FirmwareRead` | 27.4 | Hard | Read firmware for backup. Vendor-specific |

#### v1.59 Additions (7 commands)

| Command | Spec Section | Difficulty | Notes |
|---------|-------------|------------|-------|
| `TPM2_MAC` | 15.6 | Medium | Block cipher MAC (CMAC). Like HMAC but uses symmetric key. Needs wolfCrypt CMAC |
| `TPM2_MAC_Start` | 17.3 | Medium | Start MAC sequence. Mirrors HMAC_Start for CMAC |
| `TPM2_CertifyX509` | 18.8 | Hard | Generate partial X.509 certificate. Complex ASN.1 construction, caller provides tbsCert template. Deprecated in v1.84 |
| `TPM2_AC_GetCapability` | 32.2 | Hard | Attached component capability query. Hardware-specific, rarely needed for software TPM |
| `TPM2_AC_Send` | 32.3 | Hard | Send data to attached component. Hardware-specific |
| `TPM2_Policy_AC_SendSelect` | 32.4 | Medium | Policy for AC_Send. Like other policy commands |
| `TPM2_ACT_SetTimeout` | 33.2 | Medium | Set authenticated countdown timer. Needs ACT state + timer infrastructure |

#### v1.84 Additions (9 commands)

| Command | Spec Section | Difficulty | Notes |
|---------|-------------|------------|-------|
| `TPM2_ECC_Encrypt` | 14.8 | Medium | ECC-based encryption (ECIES/ElGamal). wolfCrypt ECIES support available |
| `TPM2_ECC_Decrypt` | 14.9 | Medium | ECC-based decryption. Paired with ECC_Encrypt |
| `TPM2_PolicyCapability` | 23.x | Easy | Assert TPM capability value in policy session |
| `TPM2_PolicyParameters` | 23.x | Easy | Assert command parameters in policy session |
| `TPM2_SetCapability` | 30.x | Medium | Modify TPM capability settings. Platform auth required |
| `TPM2_NV_DefineSpace2` | 31.x | Medium | Extended NV space definition (larger attribute field). Extends existing NV_DefineSpace |
| `TPM2_NV_ReadPublic2` | 31.x | Easy | Extended NV public read. Extends existing NV_ReadPublic |
| `TPM2_ReadOnlyControl` | 24.x | Easy | Toggle TPM read-only mode. Simple flag |
| `TPM2_PolicyTransportSPDM` | 23.x | Hard | SPDM transport policy. Requires SPDM protocol support |

### Coverage Summary

The eight v1.85 PQC commands (`TPM2_Encapsulate`, `TPM2_Decapsulate`,
`TPM2_SignDigest`, `TPM2_VerifyDigestSignature`, `TPM2_SignSequenceStart`,
`TPM2_SignSequenceComplete`, `TPM2_VerifySequenceStart`,
`TPM2_VerifySequenceComplete`) are implemented under `--enable-pqc`
(alias `--enable-v185`). See "v1.85 Limitations / Scope" below for the
documented PQC-only restriction.

| Spec Version | Total Commands | Implemented | Missing | Coverage |
|-------------|---------------|-------------|---------|----------|
| v1.38 | 113 | 105 | 8  | 93% |
| v1.59 | 120 | 105 | 15 | 88% |
| v1.84 | 129 | 105 | 24 | 81% |
| v1.85 | 137 | 113 | 24 | 82% |

### v1.85 Limitations / Scope

The following v1.85 commands are implemented for **post-quantum keys only**;
non-PQC key types are rejected with `TPM_RC_KEY` / `TPM_RC_SCHEME` even when
the v1.85 spec defines them generically:

- `TPM2_Encapsulate` / `TPM2_Decapsulate` — ML-KEM only. ECC DHKEM (Table 100
  `ecdh` arm with non-NULL KDF) is not implemented.
- `TPM2_SignSequenceStart` / `VerifySequenceStart` /
  `SignSequenceComplete` / `VerifySequenceComplete` — ML-DSA and Hash-ML-DSA
  only. Classical schemes (RSASSA, RSAPSS, ECDSA, SM2, ECSCHNORR, HMAC) that
  the spec also permits via these commands are not supported.
- `TPM2_SignDigest` / `TPM2_VerifyDigestSignature` — ML-DSA and Hash-ML-DSA
  only. Classical digest signing (RSASSA, RSAPSS, ECDSA) over these new
  commands is not supported; use the existing `TPM2_Sign` /
  `TPM2_VerifySignature` commands for those schemes.
