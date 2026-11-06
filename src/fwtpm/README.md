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

The script picks a free port, but a machine-wide `killall fwtpm_server` from
another shell still stops its server by process name, and every example after
that point fails at `wolfTPM2_Init` with `TPM_RC_FAILURE`. On a machine where
more than one copy of the suite may run, isolate it instead:

```bash
unshare -rn sh -c 'ip link set lo up && make check'
```

A fresh network namespace starts with `lo` down, so bringing it up is required;
without it every socket test fails with `Network is unreachable`.

## CI Tests (fwtpm-test.yml)

All tests below run in GitHub Actions CI. Run manually before PR submission.

### Runtime Tests (build + run_examples.sh + make check)

| Name | wolfTPM Config | Extra | Notes |
|------|---------------|-------|-------|
| fwtpm-socket | `--enable-fwtpm --enable-swtpm --enable-debug` | | Primary test |
| fwtpm-tis | `--enable-fwtpm --enable-debug` | | TIS/SHM transport |
| fwtpm-v185 | `--enable-fwtpm --enable-v185` | | PQC: wrapper + handler unit tests |
| fwtpm-macos-socket | `--enable-fwtpm --enable-swtpm --enable-debug` | | macOS runner |

ASan / UBSan / LeakSan coverage lives in `sanitizer.yml`, not this workflow.

### Runtime Tests, gated builds (`fwtpm-gated-runtime` job)

These configurations remove commands, so `make check` (which drives the
examples and tpm2-tools) does not apply. The job builds and runs only
`tests/fwtpm_unit.test`, whose `test_fwtpm_command_gates` /
`test_fwtpm_total_commands` / `test_fwtpm_pcr_bounds` cases assert that a gated
command is rejected with `TPM_RC_COMMAND_CODE`, is absent from
`TPM_CAP_COMMANDS`, and is not counted in `TPM_PT_TOTAL_COMMANDS`.

| Name | wolfTPM Config | wolfSSL Config | Extra CFLAGS |
|------|---------------|---------------|-------------|
| all-gates-ecc-only | `--enable-fwtpm --enable-swtpm` | `--disable-rsa` | the eleven command-group `-DFWTPM_NO_*` gates together (NV retained) |
| all-gates-mldsa | `--enable-fwtpm --enable-swtpm --enable-v185 --enable-mldsa` | `--enable-dilithium --enable-mlkem` | the same eleven gates; proves SequenceUpdate survives for ML-DSA while SequenceComplete does not |
| reduced-pcr | `--enable-fwtpm --enable-swtpm` | | `-DIMPLEMENTATION_PCR=8 -DPLATFORM_PCR=8` |

### Build-Only Tests

| Name | wolfTPM Config | wolfSSL Config | Extra CFLAGS |
|------|---------------|---------------|-------------|
| fwtpm-no-rsa | `--enable-fwtpm --enable-swtpm` | `--disable-rsa` | |
| fwtpm-no-ecc | `--enable-fwtpm --enable-swtpm` | `--disable-ecc` | |
| fwtpm-no-sha384 | `--enable-fwtpm --enable-swtpm` | `--disable-sha384` | |
| fwtpm-no-sha1 | `--enable-fwtpm --enable-swtpm` | `--disable-sha` | `-DNO_SHA` |
| fwtpm-v185-build-only | `--enable-fwtpm --enable-v185` | | `-DDEBUG_WOLFTPM` |
| fwtpm-only | `--enable-fwtpm-only --enable-swtpm` | | No client library |
| fwtpm-minimal | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_ATTESTATION -DFWTPM_NO_NV -DFWTPM_NO_POLICY -DFWTPM_NO_CREDENTIAL -DFWTPM_NO_DA -DFWTPM_NO_PARAM_ENC` |
| fwtpm-no-policy | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_POLICY` |
| fwtpm-no-nv | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_NV` |
| fwtpm-no-attestation | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_ATTESTATION` |
| fwtpm-no-credential | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_CREDENTIAL` |
| fwtpm-no-da | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_DA` |
| fwtpm-no-param-enc | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_PARAM_ENC` |
| fwtpm-no-key-migration | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_KEY_MIGRATION` |
| fwtpm-no-ecdh | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_ECDH` |
| fwtpm-no-hash-cmds | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_HASH_CMDS` |
| fwtpm-no-context | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_CONTEXT` |
| fwtpm-no-sym-encrypt | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_SYM_ENCRYPT` |
| fwtpm-no-clock | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_CLOCK` |
| fwtpm-reduced-pcr | `--enable-fwtpm --enable-swtpm` | | `-DIMPLEMENTATION_PCR=8 -DPLATFORM_PCR=8` |
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
`FWTPM_NO_DA`, `FWTPM_NO_PARAM_ENC`, `FWTPM_NO_KEY_MIGRATION`, `FWTPM_NO_ECDH`,
`FWTPM_NO_HASH_CMDS`, `FWTPM_NO_CONTEXT`, `FWTPM_NO_SYM_ENCRYPT`,
`FWTPM_NO_CLOCK`. Feature enable macros:
`WOLFTPM_FWTPM_TCG_TEST` (optional `Vendor_TCG_Test` echo command, off by default).

Command codes with reserved bits set (only the 16-bit index plus the `CC_VEND` V bit are valid), or codes not in the dispatch table, are rejected with `TPM_RC_COMMAND_CODE`.

## SPDM Responder Mode

`fwtpm_server` ships an SPDM 1.3 responder so the SPDM stack (TCG cert
handshake + DSP0274 PSK) can be tested without real silicon. When SPDM
is on, the responder sits above the existing transport HAL and dispatches
TCG-framed messages (tags `0x8101` clear, `0x8201` secured) into the SPDM
state machine; plaintext TPM frames fall through to the regular dispatcher
until the requester issues `SPDMONLY LOCK`, after which only `GetCapability`
is allowed through in plaintext (matching Nuvoton/Nations silicon).

Build with `--enable-fwtpm --enable-spdm` plus at least one of
`--enable-tcg` / `--enable-psk`. Start in one of two modes:

```bash
./src/fwtpm/fwtpm_server --spdm-tcg              # TCG cert handshake
./src/fwtpm/fwtpm_server --spdm-psk \
    --spdm-psk-hex dbc2192291d807742441b963f6712841...   # PSK handshake
./src/fwtpm/fwtpm_server --no-spdm               # plaintext only (default)
```

The responder generates a fresh P-384 identity keypair at startup (used
for `GET_PUBK`/`KEY_EXCHANGE` signing); the private key never leaves
`fwtpm_server` memory and the stack copy is zeroed with `wc_ForceZero`
after handoff to the responder context. In TCG mode, the server prints the
public half during startup so the local test harness can pass it to the
requester through the responder-key pinning API. This process-owned log is a
test bootstrap channel, not a substitute for authenticated device provisioning.

End-to-end coverage runs via the same script that drives real silicon:

```bash
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl fwtpm-tcg
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl fwtpm-psk
```

CI exercises 7 build-only configure permutations + the two e2e modes on
`ubuntu-latest` via `spdm-test.yml`, against the fwTPM SPDM responder.

## TPM 2.0 Command Coverage

### Currently Implemented

Two different totals are in play and are easy to conflate. Against the **v1.38
baseline** the fwTPM implements 105 of 113 commands (93%). Counting the later
additions it also implements, the dispatch table reaches **113 of the 129
commands defined through v1.84** (88%), and 121 of 137 through v1.85 with
`--enable-pqc`. The per-group lists below are the v1.38 baseline plus the
v1.84 additions noted against their gates.

**Core set -- never gated (37 commands):**
Startup, Shutdown, SelfTest, IncrementalSelfTest, GetTestResult, GetRandom,
StirRandom, GetCapability, TestParms, PCR\_Read, PCR\_Extend, PCR\_Reset,
PCR\_Event, PCR\_Allocate, PCR\_SetAuthPolicy, PCR\_SetAuthValue,
CreatePrimary, FlushContext, ReadPublic, Clear, ClearControl, ChangeEPS,
ChangePPS, HierarchyControl, HierarchyChangeAuth, SetPrimaryPolicy,
EvictControl, Create, ObjectChangeAuth, Load, Sign, VerifySignature,
StartAuthSession, Unseal, LoadExternal, CreateLoaded,
SetCapability (v1.84)

These are present in every build. A default build (no `FWTPM_NO_*` macro set)
additionally enables every group listed under **Conditional on feature macros**
below; setting a gate macro removes that group's commands from the dispatch
table, from `TPM2_GetCapability(TPM_CAP_COMMANDS)`, and from the
`TPM_PT_TOTAL_COMMANDS` count.

**Optional vendor command (off by default, `WOLFTPM_FWTPM_TCG_TEST`):**
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
  PolicyCounterTimer, PolicyTicket, PolicyAuthorizeNV, plus PolicyCapability
  and PolicyParameters (v1.84) (23 commands). Also gates
  PolicyTransportSPDM when `WOLFTPM_SPDM` is enabled
- `FWTPM_NO_NV`: NV\_DefineSpace, NV\_UndefineSpace, NV\_UndefineSpaceSpecial,
  NV\_ReadPublic, NV\_Write, NV\_Read, NV\_Extend, NV\_Increment, NV\_WriteLock,
  NV\_ReadLock, NV\_SetBits, NV\_ChangeAuth, NV\_GlobalWriteLock, plus
  NV\_ReadPublic2 and NV\_DefineSpace2 (v1.84) (15 commands).
  Also gates PolicyNV and PolicyAuthorizeNV when policy is enabled and removes
  the `FWTPM_CTX` in-memory NV index slots.
- `FWTPM_NO_ATTESTATION`: Quote, Certify, CertifyCreation, GetTime, NV\_Certify
- `FWTPM_NO_CREDENTIAL`: MakeCredential, ActivateCredential
- `FWTPM_NO_DA`: DictionaryAttackLockReset, DictionaryAttackParameters (2 commands)
- `FWTPM_NO_PARAM_ENC`: Disables parameter encryption/decryption for command and
  response parameters. Sessions still work for HMAC auth, but encrypted transport
  is disabled. Reduces code size by removing AES-CFB and XOR param encryption.
- `FWTPM_NO_KEY_MIGRATION`: Import, Duplicate, Rewrap (3 commands). Shared key
  helpers (used by Create/Load) are retained.
- `FWTPM_NO_ECDH`: ECDH\_KeyGen, ECDH\_ZGen, EC\_Ephemeral, ZGen\_2Phase,
  ECC\_Parameters (5 commands). ECDSA sign/verify are retained. Also drops the
  `ecEphemeral*` commit state from `FWTPM_CTX`.
- `FWTPM_NO_HASH_CMDS`: Hash, HMAC, HMAC\_Start, HashSequenceStart,
  SequenceUpdate, SequenceComplete, EventSequenceComplete (7 commands). When
  `WOLFTPM_MLDSA` is built, only SequenceUpdate is retained -- the MLDSA
  verify sequences stream their message through it. SequenceComplete is not
  shared: MLDSA sequences finalize through SignSequenceComplete /
  VerifySequenceComplete, so advertising it in a gated build would expose a
  command that can never succeed. Also drops the per-instance hash-sequence
  slots (`hashSeq[FWTPM_MAX_HASH_SEQ]`) from `FWTPM_CTX`.
- `FWTPM_NO_CONTEXT`: ContextSave, ContextLoad (2 commands). FlushContext is
  retained. Also drops the per-boot context protection key and the saved-context
  replay list from `FWTPM_CTX`.
- `FWTPM_NO_SYM_ENCRYPT`: EncryptDecrypt, EncryptDecrypt2 (2 commands). Nests
  inside `NO_AES`; AES itself is retained for session parameter encryption,
  AES-GCM, and (unless `FWTPM_NO_CONTEXT` is also set) context protection.
- `FWTPM_NO_CLOCK`: ReadClock, ClockSet, ClockRateAdjust (3 commands). GetTime is
  under `FWTPM_NO_ATTESTATION`, not this flag.
- `FWTPM_NO_ECC_ENCRYPT`: ECC\_Encrypt, ECC\_Decrypt (2 commands, v1.84).
  Set automatically unless wolfCrypt exports its RNG-blinded ECC scalar
  multiplication, on the same terms as `FWTPM_NO_ZGEN_2PHASE`.
- `FWTPM_NO_READONLY`: ReadOnlyControl (1 command, v1.84). Also removes the
  dispatcher enforcement, the conditional NV checks, the `readOnly` bit of
  `TPMA_STARTUP_CLEAR` and the `readOnly` field of `FWTPM_CTX`, and reverts
  the NV orderly-shutdown marker to its shorter legacy form.
These gates are independent and there is intentionally no umbrella macro: pick
exactly the groups your fTPM does not need. Applying all of them plus the earlier
`FWTPM_NO_POLICY/ATTESTATION/CREDENTIAL/DA/PARAM_ENC` (keeping NV, or adding
`FWTPM_NO_NV` to drop it) leaves a core fTPM (Startup/GetCapability/GetRandom/
PCR/Create/Load/Sign/VerifySignature/NV/sessions) - see the MicroBlaze V example
in wolftpm-examples for a worked selection.

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

#### v1.84 Additions

None outstanding. All nine v1.84 command additions are implemented, though
`TPM2_ECC_Encrypt`/`TPM2_ECC_Decrypt` require a wolfSSL that exports its
RNG-blinded ECC point multiplication and `TPM2_NV_DefineSpace2` accepts only
the `TPM_HT_NV_INDEX` handle type. See "ECC Encryption (v1.84)" and
"Settable Feature Configuration (v1.84)" below.

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
| v1.84 | 129 | 113 | 16 | 88% |
| v1.85 | 137 | 121 | 16 | 88% |

Counts are for a default build, which has neither SPDM nor the vendor test
command. `TPM2_PolicyTransportSPDM` is implemented whenever `WOLFTPM_SPDM` is
enabled, so that build has one more implemented command than the v1.84 row
shows; it is not an unimplemented gap.

### Read-Only Mode (v1.84)

Built by default; set `FWTPM_NO_READONLY` to compile the whole feature out.

`TPM2_ReadOnlyControl` requires Platform authorization and takes a single
`TPMI_YES_NO`. The current state is the `readOnly` bit (bit 4) of
`TPMA_STARTUP_CLEAR`, readable with
`TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_STARTUP_CLEAR)`.

While the mode is on, the dispatcher refuses the commands Part 3 Table 190
lists as Not Permitted with `TPM_RC_READ_ONLY`, ahead of authorization
processing so a refused command cannot consume dictionary-attack tries. Of the
commands the fwTPM implements that is: Create, CreateLoaded, ObjectChangeAuth,
CreatePrimary, HierarchyControl, SetPrimaryPolicy, ChangePPS, ChangeEPS,
Clear, ClearControl, HierarchyChangeAuth, EvictControl, PCR\_Allocate,
PCR\_SetAuthPolicy, PCR\_SetAuthValue, DictionaryAttackParameters, ClockSet,
ClockRateAdjust, SetCapability, NV\_DefineSpace, NV\_UndefineSpace,
NV\_UndefineSpaceSpecial, NV\_Increment, NV\_GlobalWriteLock and
NV\_ChangeAuth.

`NV_Write`, `NV_Extend`, `NV_SetBits`, `NV_WriteLock` and `NV_ReadLock` are
permitted only on an index defined with **both** `TPMA_NV_ORDERLY` and
`TPMA_NV_CLEAR_STCLEAR`, so the write cannot outlive the power cycle that
clears the mode; any other index returns `TPM_RC_READ_ONLY`. `NV_Increment` is
refused outright because one global increment counter is shared across every
index. Reads, cryptographic operations, PCR extends, signing, quoting and
context save/load stay available.

Table 190 also makes `TPM2_PolicySecret` conditional on the authorizing entity
not being a PIN Pass/Fail NV index. That case cannot arise here:
`TPM2_NV_DefineSpace` accepts only `TPM_NT_ORDINARY`, `TPM_NT_COUNTER`,
`TPM_NT_BITS` and `TPM_NT_EXTEND`, so a PIN index cannot be created, and no
check is implemented for it.

The bit is CLEAR on TPM Reset and TPM Restart and preserved by TPM Resume. It
rides the NV orderly-shutdown marker rather than the flags byte, which is
full, so it survives an orderly `Shutdown(STATE)` and a process restart. That
marker gains a fourth byte; older firmware rejects the longer record, the same
downgrade consideration as the earlier two extensions to it.

### Settable Feature Configuration (v1.84)

`TPM2_SetCapability` writes one `TPMS_TAGGED_CONFIG` at a time under Platform
authorization. `TPMU_SET_CAPABILITIES` has no normative member list -- Part 2
Table 137 defers it to a TCG Registry -- so the only capability accepted is
`TPM_CAP_CONFIGS` (`0x81C90001`), matching the structure wolfTPM's client side
already sends. Any other capability, an unknown `TPM_PT_CONFIG_*`, or a write
to a configuration whose `lock` is already SET returns `TPM_RC_VALUE`; there
is no `TPM_RC_LOCKED` to report the last case more precisely.

The four configurations (`ENCRYPTDECRYPT2`, `CHANGEEPS`, `TPMID_NV`,
`SPDM_PSK`) are stored with their `enable` and `lock` flags, persisted in NV
under their own journal tag, and reported back by
`TPM2_GetCapability(TPM_CAP_CONFIGS)`. A `lock` is for the lifetime of the
part and survives `TPM2_Clear`.

The configurations are recorded and reported but do not gate command
availability: the fwTPM's feature set is selected at build time by the
`FWTPM_NO_*` macros. Treat the configuration state as provisioning metadata,
not as a runtime switch.

### ECC Encryption (v1.84)

`TPM2_ECC_Encrypt` and `TPM2_ECC_Decrypt` implement GB/T 32918.4-2016 as
given in TPM 2.0 Part 1 Annex C.2.4, which generalizes it to any ECC key
whose restricted attribute is CLEAR:

```
C1 = x1 || y1                        where P1 = [k]G
t  = KDF(x2 || y2, len(M))           where P2 = (x2, y2) = [k]P_B
C2 = M XOR t
C3 = H(x2 || M || y2)
```

Annex C states that only `TPM_ALG_KDF2` is supported, so any other KDF
scheme returns `TPM_RC_SCHEME`. KDF2 from ISO/IEC 18033-2 is X9.63 with an
empty SharedInfo, so `wc_X963_KDF` supplies it directly and no new primitive
is needed. Note `C3` covers the plaintext between the two shared-point
coordinates; it is not a MAC over the ciphertext, so decryption recovers the
plaintext first and then checks the integrity value before returning
anything.

Decryption additionally requires decrypt SET, per Part 3 Sec.14.9, and
rejects a point that is not on the key's curve with `TPM_RC_ECC_POINT`.

**Build requirement.** Both commands need the full shared point, not just
its x coordinate, so they use the same RNG-blinded multiplication as
`TPM2_ZGen_2Phase`. That API is only exported when wolfSSL is built with
`WOLFSSL_PUBLIC_ECC_ADD_DBL` (`--enable-wpas` sets it, or define it
directly). Without it, `FWTPM_NO_ECC_ENCRYPT` is set automatically and the
commands are absent, exactly as `FWTPM_NO_ZGEN_2PHASE` behaves, so the
operation can never silently fall back to an unblinded multiply.

A hash outside the SHA family may be refused by the KDF even when the fwTPM
itself supports it: `wc_X963_KDF` accepts SHA-3 only on a wolfSSL new enough
to allow it, and never in a FIPS build, where the validated X9.63 algorithm
list applies. That case surfaces as `TPM_RC_HASH`.

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

Clock persistence requires a clock HAL returning milliseconds since the current
power-on. The standalone server registers a monotonic host clock. Server loops
checkpoint Clock while idle. Embedded integrations must call `FWTPM_Clock_Update()` at least every `FWTPM_CLOCK_POLL_MS` milliseconds;
custom transport waits, reads and writes must return within that interval.
`TPM_PT_CLOCK_UPDATE` reports the maximum NV checkpoint interval. Clock's `safe` flag stays clear after
an unclean shutdown until the prior boot's potentially reported range has passed
and the new value is committed. Orderly NV counters checkpoint on modulo-2
rollover and at shutdown, and round forward on an unclean startup.
An orderly shutdown preserves Clock's safety flag separately; shutdown and
library cleanup cannot make an unsafe Clock safe before recovery.

Existing NV journals remain readable. Legacy shutdown markers lack a Clock
safety flag and restore Clock conservatively as unsafe. Older firmware rejects
journals containing the extended orderly-shutdown marker; downgrades need a
compatible journal conversion.
