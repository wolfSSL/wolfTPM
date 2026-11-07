# fwTPM Overview

The wolfTPM fwTPM (also called fTPM) is a firmware TPM 2.0 built on wolfCrypt cryptographic primitives. It is not only an emulator for tests. It is a portable TPM 2.0 command processor that runs as a standalone server process (`fwtpm_server`) or is linked into an embedded firmware image. A default build with RSA, ECC, AES, and every feature group enabled has 103 of the 112 TPM 2.0 Revision 1.38 command codes in its dispatch table, plus eight Version 184 additions, for 111. The eight Version 185 post-quantum commands raise that to 119. See Command Coverage below for the counting convention and the documented limitations, such as the minimal self-test and the missing `SU_STATE` resume support.

The fwTPM can be used for testing, and it can also be used in production, security-critical, and isolated deployments where a discrete TPM chip is not available or not wanted. In those deployments the security of the TPM depends on the platform that hosts it. A firmware TPM does not provide the physical isolation of a discrete TPM chip on its own, so the integrator must supply the isolation (a separate core, a TrustZone secure world, or similar) and must protect the NV storage. The default file-based NV store keeps hierarchy seeds, authorization values, and private keys in plaintext, and `fwtpm_server` itself is a development and test tool. The fwTPM also brings post-quantum cryptography and SPDM to platforms without TPM silicon.

Example integration models:

- **Embedded and IoT platforms** without a discrete TPM chip (bare-metal via an SPI or I2C TIS HAL)
- **Isolated deployments**, such as a TPM running on a separate core, a TrustZone secure world, or a lock-step real-time core next to a Linux application processor. The isolation comes from the platform, not from the fwTPM.
- **Development and testing** of TPM-dependent applications (drop-in for swtpm or the Microsoft TPM simulator)
- **CI/CD pipelines** that need TPM functionality (socket transport compatible with tpm2-tools)
- **Prototyping** TPM workflows before hardware is available
- **Post-quantum and SPDM work** without TPM silicon (see [Post-Quantum Support](post-quantum.md) and [SPDM Responder](spdm.md))

## Features

- TPM 2.0 command processor covering 103 of the 112 Revision 1.38 command codes in a default build, with the limitations listed in Command Coverage.
- TCP socket transport using the Microsoft TPM simulator protocol, compatible with wolfTPM examples and tpm2-tools. Both the mssim and swtpm TCTI protocols are auto-detected on the command port.
- TIS register-level transport over POSIX shared memory, or over SPI or I2C for bare-metal integration.
- HAL abstractions for I/O and NV storage, so the core logic does not change when porting. See [HAL and Porting](hal-and-porting.md).
- Post-quantum cryptography with `--enable-pqc`: ML-DSA (FIPS 204) signing and ML-KEM (FIPS 203) key encapsulation per TCG TPM 2.0 Library Specification Version 185. `--enable-pqc` and `--enable-v185` are distinct project-wide modes, but configure promotes `--enable-pqc` to the full Version 185 mode when building the fwTPM, so the two behave the same for the fwTPM. Configure auto-detects PQC when `--enable-fwtpm` is built against a wolfCrypt that has both. See [Post-Quantum Support](post-quantum.md).
- SPDM 1.3 responder for testing the SPDM stack without silicon. See [SPDM Responder](spdm.md).
- Compile-time feature gates (`FWTPM_NO_*`) to shrink the build for constrained targets. See [Building](building.md).

## Architecture

```
+---------------------+     +-------------------------------+
| wolfTPM Client App  |     |  fwtpm_server (or embedded)   |
| (examples, tests)   |     |                               |
+----------+----------+     |  +-------------------------+  |
           |                |  | Transport Layer         |  |
     TCP (SWTPM protocol)   |  | (socket or TIS)         |  |
     or TIS shared memory   |  +------------+------------+  |
     or SPI/I2C TIS         |               |               |
           |                |  +------------v------------+  |
           +--------------->|  | FWTPM_ProcessCommand    |  |
                            |  | (fwtpm_command.c)       |  |
                            |  +------+-----------+------+  |
                            |         |           |         |
                            |  +------v-----+ +---v------+  |
                            |  | wolfCrypt  | | NV       |  |
                            |  | (RSA, ECC, | | backend  |  |
                            |  |  SHA, HMAC,| | (fwtpm_  |  |
                            |  |  RNG, AES) | |  nv.c)   |  |
                            |  +------------+ +----------+  |
                            +-------------------------------+
```

Both the socket and TIS transports pass each command to `FWTPM_ProcessCommand`. The command handlers then use wolfCrypt and the NV backend. The flow is the same for the standalone server and for an embedded integration.

**Components:**

| File | Role |
|------|------|
| `fwtpm_command.c` | TPM 2.0 command processor and dispatch table |
| `fwtpm_io.c` | Transport layer: SWTPM TCP socket protocol (enabled by the swtpm configuration; builds without it use the TIS path) |
| `fwtpm_nv.c` | NV storage: file-based (default); HAL-abstracted, with a built-in append-only mode for write-once flash |
| `fwtpm_tis.c` | TIS register state machine (transport-agnostic) |
| `fwtpm_tis_shm.c` | POSIX shared memory and semaphore TIS transport |
| `fwtpm_main.c` | Server entry point, CLI argument parsing |
| `tpm2_util.c` | Shared utilities (hash helpers, ForceZero, PrintBin) |
| `tpm2_packet.c` | TPM packet marshaling and unmarshaling |
| `tpm2_param_enc.c` | Parameter encryption (XOR and AES session encryption) |

## Supported TPM 2.0 Commands

This section lists representative commands and is not exhaustive. It omits supported commands such as `PCR_Event`, `PCR_Allocate`, `ClockRateAdjust`, several policy commands, and some algorithm-dependent commands. The Command Coverage section below has the dispatch-table breakdown. A default build (no `FWTPM_NO_*` macro set) includes every group below. Setting a gate macro removes that group's commands from the dispatch table, from `TPM2_GetCapability(TPM_CAP_COMMANDS)`, and from the `TPM_PT_TOTAL_COMMANDS` count. See [Building](building.md) for the gates.

### Startup and Self-Test

| Command | Description |
|---------|-------------|
| `TPM2_Startup` | Initialize TPM (SU_CLEAR or SU_STATE) |
| `TPM2_Shutdown` | Save state and prepare for power-off |
| `TPM2_SelfTest` | Minimal self-test: a SHA-256 known-answer test and an RNG check. The source calls this nonconformant. |
| `TPM2_IncrementalSelfTest` | No-op stub that returns an empty to-do list |
| `TPM2_GetTestResult` | Return self-test result |

### Random Number Generation

| Command | Description |
|---------|-------------|
| `TPM2_GetRandom` | Generate random bytes (max 48 per call) |
| `TPM2_StirRandom` | Add entropy to RNG state |

### Capability

| Command | Description |
|---------|-------------|
| `TPM2_GetCapability` | Query TPM properties, algorithms, handles |

### Key Management

| Command | Description |
|---------|-------------|
| `TPM2_CreatePrimary` | Create primary key under a hierarchy |
| `TPM2_Create` | Create child key under a parent |
| `TPM2_CreateLoaded` | Create and load key in one command |
| `TPM2_Load` | Load key from private and public parts |
| `TPM2_LoadExternal` | Load external (software) key |
| `TPM2_Import` | Import externally wrapped key |
| `TPM2_Duplicate` | Export key for transfer (inner and outer wrapping) |
| `TPM2_Rewrap` | Re-wrap a duplicated object from the old parent to a new parent |
| `TPM2_FlushContext` | Unload a transient object or session |
| `TPM2_ContextSave` | Save object or session context |
| `TPM2_ContextLoad` | Restore saved context |
| `TPM2_ReadPublic` | Read public area of a loaded key |
| `TPM2_ObjectChangeAuth` | Change authorization of a key |
| `TPM2_EvictControl` | Make transient key persistent (or remove) |
| `TPM2_HierarchyControl` | Enable or disable a hierarchy |
| `TPM2_HierarchyChangeAuth` | Change hierarchy authorization value |
| `TPM2_Clear` | Regenerate the storage primary seed, reset owner and endorsement authorization and policy state, and schedule eligible objects for removal. Does not regenerate the platform seed or the endorsement seed. |
| `TPM2_ChangePPS` | Replace platform primary seed |
| `TPM2_ChangeEPS` | Replace endorsement primary seed |

### Cryptographic Operations

| Command | Description |
|---------|-------------|
| `TPM2_Sign` | Sign digest with loaded key |
| `TPM2_VerifySignature` | Verify signature against loaded key |
| `TPM2_RSA_Encrypt` | RSA encryption (OAEP, PKCS1) |
| `TPM2_RSA_Decrypt` | RSA decryption |
| `TPM2_EncryptDecrypt` | Symmetric encrypt and decrypt |
| `TPM2_EncryptDecrypt2` | Symmetric encrypt and decrypt (alternate) |
| `TPM2_Hash` | Single-shot hash computation |
| `TPM2_HMAC` | Single-shot HMAC computation |
| `TPM2_ECDH_KeyGen` | Generate ephemeral ECC key pair |
| `TPM2_ECDH_ZGen` | Compute ECDH shared secret |
| `TPM2_ECC_Parameters` | Get ECC curve parameters |
| `TPM2_TestParms` | Validate algorithm parameter support |

### Hash Sequences

| Command | Description |
|---------|-------------|
| `TPM2_HashSequenceStart` | Start a hash sequence |
| `TPM2_HMAC_Start` | Start an HMAC sequence |
| `TPM2_SequenceUpdate` | Add data to a hash or HMAC sequence |
| `TPM2_SequenceComplete` | Finalize hash or HMAC sequence and get result |
| `TPM2_EventSequenceComplete` | Finalize hash sequence and extend PCR |

### Sealing

| Command | Description |
|---------|-------------|
| `TPM2_Unseal` | Unseal data from a sealed object |

### PCR (Platform Configuration Registers)

| Command | Description |
|---------|-------------|
| `TPM2_PCR_Read` | Read PCR values |
| `TPM2_PCR_Extend` | Extend a PCR with a digest |
| `TPM2_PCR_Reset` | Reset a resettable PCR |

### Clock

| Command | Description |
|---------|-------------|
| `TPM2_ReadClock` | Read TPM clock values |
| `TPM2_ClockSet` | Set TPM clock |

### Sessions and Authorization

| Command | Description |
|---------|-------------|
| `TPM2_StartAuthSession` | Create HMAC, policy, or trial session |

### Policy

| Command | Description |
|---------|-------------|
| `TPM2_PolicyGetDigest` | Get current policy session digest |
| `TPM2_PolicyRestart` | Reset policy session digest |
| `TPM2_PolicyPCR` | Bind policy to PCR values |
| `TPM2_PolicyPassword` | Include password in policy |
| `TPM2_PolicyAuthValue` | Include auth value in policy |
| `TPM2_PolicyCommandCode` | Restrict policy to specific command |
| `TPM2_PolicyOR` | Logical OR of policy branches |
| `TPM2_PolicySecret` | Authorization with secret |
| `TPM2_PolicyAuthorize` | Approve policy with signing key |
| `TPM2_PolicyNV` | Policy based on NV index comparison |
| `TPM2_PolicyLocality` | Restrict policy to specific locality |
| `TPM2_PolicySigned` | Authorize policy with external signing key |

### Dictionary Attack (DA) Protection

| Command | Description |
|---------|-------------|
| `TPM2_DictionaryAttackParameters` | Set `maxTries`, `recoveryTime`, `lockoutRecovery` |
| `TPM2_DictionaryAttackLockReset` | Reset the failed-tries counter (lockoutAuth) |

The fwTPM implements dictionary-attack protection modeled on the TPM 2.0 specification (Part 1, Section 19.8). A failed authorization of a DA-protected entity increments `failedTries`. Once it reaches `maxTries` the TPM returns `TPM_RC_LOCKOUT`. `failedTries` is persisted in NV on every failure, so a power cycle cannot reset it.

When a clock HAL is registered (`FWTPM_Clock_SetHAL`), the counter self-heals one try per `recoveryTime` seconds, and a non-orderly shutdown adds a one-try penalty. On clockless builds neither applies: the persisted `failedTries` counter does not self-heal, and recovery is only through `DictionaryAttackLockReset` or `Clear`, so routine unclean power-off cannot accumulate into lockout.

A failed `lockoutAuth` locks the lockout hierarchy. On a build with a clock HAL, that lock persists across reboot and clears after `lockoutRecovery` seconds, except when `lockoutRecovery` is 0 (reboot-only recovery). On a clockless build, the failed-`lockoutAuth` lock is cleared on every startup. With a clock HAL, the clock HAL reports milliseconds since boot, so this timer measures continuous post-boot uptime, not wall-clock time across reboots. A device that reboots more often than `lockoutRecovery` extends its effective recovery window.

There are two separate gates. A failed `lockoutAuth` blocks later uses of `lockoutAuth` (`DictionaryAttackLockReset`, `DictionaryAttackParameters`, and lockout-authorized `Clear`). Reaching `maxTries` blocks authorization of DA-protected objects, NV indices, and bound entities, and the TPM returns `TPM_RC_LOCKOUT`. The platform hierarchy is always an escape hatch: `TPM2_ClearControl(platformAuth, clearDisable=NO)` followed by `TPM2_Clear(platformAuth)` recovers even when `disableClear` was set. `Startup` and `Shutdown` are never DA-gated, so a reboot in lockout can always recover. Entities marked `noDA` (`TPMA_OBJECT_noDA` on objects, `TPMA_NV_NO_DA` on NV indices) never feed the counter and stay usable during lockout.

`TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)` reports `TPM_PT_MAX_AUTH_FAIL`, `TPM_PT_LOCKOUT_INTERVAL`, `TPM_PT_LOCKOUT_RECOVERY`, `TPM_PT_LOCKOUT_COUNTER`, and the `inLockout` bit of `TPM_PT_PERMANENT`.

Durable accounting writes the NV FLAGS entry on each DA-protected failure (and on the first DA-protected auth use per boot). The counter stops increasing while it is at `maxTries`, but clock-based self-healing can lower it, which allows further failed attempts and NV writes in the same boot, so the number of writes per boot is not strictly bounded. On flash-backed targets it still adds wear and makes failed-auth latency NV-bound, so size the NV backend accordingly.

The first use of a DA-protected (non-`noDA`) authorization after startup can make a TPM persist a `daUsed` flag to NV and return `TPM_RC_RETRY` ("resubmit the identical command") while it writes. The TCG architecture describes this as one possible implementation approach, not a requirement for every TPM. Build with `FWTPM_DA_USED_RETRY` to emulate it so clients exercise their resubmit and retry handling. It is off by default, and DA accounting and persistence are active regardless. Compile out all DA logic with `FWTPM_NO_DA`.

Coverage: DA, noDA, lockout, self-heal, and persistence unit tests in `tests/fwtpm_unit_tests.c`, the `examples/management/da_check` end-to-end example (add `-lockout` for the destructive lockout and recovery path), and the `tests/fwtpm_da_retry.sh` harness that exercises the `TPM_RC_RETRY` path against a `FWTPM_DA_USED_RETRY` build.

### Non-Volatile Storage (NV)

| Command | Description |
|---------|-------------|
| `TPM2_NV_DefineSpace` | Create an NV index |
| `TPM2_NV_UndefineSpace` | Delete an NV index |
| `TPM2_NV_ReadPublic` | Read NV index public metadata |
| `TPM2_NV_Write` | Write data to NV index |
| `TPM2_NV_Read` | Read data from NV index |
| `TPM2_NV_Extend` | Extend NV index (hash-extend) |
| `TPM2_NV_Increment` | Increment NV counter |
| `TPM2_NV_WriteLock` | Lock NV index for writes |
| `TPM2_NV_ReadLock` | Lock NV index for reads |
| `TPM2_NV_SetBits` | OR bits into NV bit field index |
| `TPM2_NV_ChangeAuth` | Change NV index authorization value |

### Attestation and Credentials

| Command | Description |
|---------|-------------|
| `TPM2_Quote` | Generate signed PCR quote |
| `TPM2_Certify` | Certify a loaded key |
| `TPM2_CertifyCreation` | Prove key was created by this TPM |
| `TPM2_GetTime` | Signed attestation of TPM clock |
| `TPM2_NV_Certify` | Certify NV index contents |
| `TPM2_MakeCredential` | Create credential blob for a key |
| `TPM2_ActivateCredential` | Unwrap credential blob |

## Command Coverage

### Implemented (103 Revision 1.38 command codes, plus 8 Version 184 additions)

This page counts command codes, not command names, and excludes `TPM_CC_Vendor_TCG_Test` from standard totals. Revision 1.38 defines 112 standard command codes. With RSA, ECC, AES, and all feature groups enabled, the dispatch table holds 103 of them, which is about 92% of the Revision 1.38 set. The Version 184 additions add 8 and the Version 185 post-quantum commands add 8. Reaching 121 entries requires `WOLFTPM_SPDM` (one more command, `PolicyTransportSPDM`) and the test-only vendor command as well.

**Core set, never gated (37 commands):**
Startup, Shutdown, SelfTest, IncrementalSelfTest, GetTestResult, GetRandom, StirRandom, GetCapability, TestParms, PCR_Read, PCR_Extend, PCR_Reset, PCR_Event, PCR_Allocate, PCR_SetAuthPolicy, PCR_SetAuthValue, CreatePrimary, FlushContext, ReadPublic, Clear, ClearControl, ChangeEPS, ChangePPS, HierarchyControl, HierarchyChangeAuth, SetPrimaryPolicy, EvictControl, Create, ObjectChangeAuth, Load, Sign, VerifySignature, StartAuthSession, Unseal, LoadExternal, CreateLoaded, SetCapability (Version 184)

These are present in every build.

**Optional vendor command (off by default, `WOLFTPM_FWTPM_TCG_TEST`):**
Vendor_TCG_Test

**Conditional on algorithm (`NO_RSA`, `HAVE_ECC`, `NO_AES`):**
RSA_Encrypt, RSA_Decrypt, ECDH_KeyGen, ECDH_ZGen, ECC_Parameters, EC_Ephemeral, ZGen_2Phase, EncryptDecrypt, EncryptDecrypt2

**Conditional on feature macros:**

- `FWTPM_NO_POLICY`: PolicyGetDigest, PolicyRestart, PolicyPCR, PolicyPassword, PolicyAuthValue, PolicyCommandCode, PolicyOR, PolicySecret, PolicyAuthorize, PolicyLocality, PolicySigned, PolicyNV, PolicyPhysicalPresence, PolicyCpHash, PolicyNameHash, PolicyDuplicationSelect, PolicyNvWritten, PolicyTemplate, PolicyCounterTimer, PolicyTicket, PolicyAuthorizeNV, PolicyCapability (Version 184), PolicyParameters (Version 184) (23 commands). Also gates the conditional `PolicyTransportSPDM` command.
- `FWTPM_NO_NV`: NV_DefineSpace, NV_UndefineSpace, NV_UndefineSpaceSpecial, NV_ReadPublic, NV_Write, NV_Read, NV_Extend, NV_Increment, NV_WriteLock, NV_ReadLock, NV_SetBits, NV_ChangeAuth, NV_GlobalWriteLock, NV_ReadPublic2 and NV_DefineSpace2 (Version 184) (15 commands). Also gates PolicyNV and PolicyAuthorizeNV when policy is enabled and removes the in-memory NV index slots from `FWTPM_CTX`. NV_Certify is gated by `FWTPM_NO_NV` as well as `FWTPM_NO_ATTESTATION`.
- `FWTPM_NO_ATTESTATION`: Quote, Certify, CertifyCreation, GetTime, NV_Certify (NV_Certify is also removed by `FWTPM_NO_NV`)
- `FWTPM_NO_CREDENTIAL`: MakeCredential, ActivateCredential
- `FWTPM_NO_DA`: DictionaryAttackLockReset, DictionaryAttackParameters (2 commands)
- `FWTPM_NO_PARAM_ENC`: Disables parameter encryption and decryption for command and response parameters. Sessions still work for HMAC auth, but encrypted transport is disabled. Reduces code size by removing AES-CFB and XOR parameter encryption.
- `FWTPM_NO_KEY_MIGRATION`: Import, Duplicate, Rewrap (3 commands). Shared key helpers used by Create and Load are retained.
- `FWTPM_NO_ECDH`: ECDH_KeyGen, ECDH_ZGen, EC_Ephemeral, ZGen_2Phase, ECC_Parameters (5 commands). ECDSA sign and verify are retained. Also drops the `ecEphemeral*` commit state from `FWTPM_CTX`.
- `FWTPM_NO_HASH_CMDS`: Hash, HMAC, HMAC_Start, HashSequenceStart, SequenceUpdate, SequenceComplete, EventSequenceComplete (7 commands). When `WOLFTPM_MLDSA` is built, only SequenceUpdate is retained, because the ML-DSA verify sequences stream their message through it. SequenceComplete is not shared: ML-DSA sequences finalize through SignSequenceComplete and VerifySequenceComplete, so advertising it in a gated build would expose a command that can never succeed. Also drops the per-instance hash-sequence slots (`hashSeq[FWTPM_MAX_HASH_SEQ]`) from `FWTPM_CTX`.
- `FWTPM_NO_CONTEXT`: ContextSave, ContextLoad (2 commands). FlushContext is retained. Also drops the per-boot context protection key and the saved-context replay list from `FWTPM_CTX`.
- `FWTPM_NO_SYM_ENCRYPT`: EncryptDecrypt, EncryptDecrypt2 (2 commands). Nests inside `NO_AES`. AES itself is retained for session parameter encryption, AES-GCM, and (unless `FWTPM_NO_CONTEXT` is also set) context protection.
- `FWTPM_NO_ECC_ENCRYPT`: ECC_Encrypt, ECC_Decrypt (Version 184). Set automatically unless wolfCrypt exports its RNG-blinded ECC scalar multiplication, on the same terms as `FWTPM_NO_ZGEN_2PHASE`.
- `FWTPM_NO_READONLY`: ReadOnlyControl (Version 184). Also removes the dispatcher Read-Only enforcement, the conditional NV checks, the `readOnly` bit of `TPMA_STARTUP_CLEAR` and the `readOnly` field of `FWTPM_CTX`.
- `FWTPM_NO_CLOCK`: ReadClock, ClockSet, ClockRateAdjust (3 commands). GetTime is under `FWTPM_NO_ATTESTATION`, not this flag.
- `FWTPM_NO_PP`: PolicyPhysicalPresence and physical-presence enforcement. Drops the physical-presence HAL, the platform latch, and `FWTPM_PP_SetHAL`.

These gates are independent and there is intentionally no umbrella macro: pick exactly the groups your fTPM does not need. Applying every gate leaves the core set of 36 always-present commands, plus whatever the algorithm configuration keeps (keeping NV, or adding `FWTPM_NO_NV` to drop it). See the MicroBlaze V example in the `wolftpm-examples` repository (listed in [Usage](usage.md)) for a worked selection.

### Missing Commands

#### Revision 1.38 baseline (9 missing command codes)

Medium (moderate logic, builds on existing infrastructure):

| Command | Spec Section | Difficulty | Notes |
|------------------------------------------|--------|--------|------------------------------------------|
| `TPM2_SetCommandCodeAuditStatus` | 21.2 | Medium | Manage list of commands that are audited. Needs audit bitmap in context |
| `TPM2_PP_Commands` | 26.2 | Medium | Manage physical presence command list. Needs PP command bitmap |

Hard (complex crypto or new subsystems):

| Command | Spec Section | Difficulty | Notes |
|------------------------------------------|--------|--------|------------------------------------------|
| `TPM2_GetSessionAuditDigest` | 18.5 | Hard | Sign session audit digest. Requires session audit tracking (running hash of all commands in session). New subsystem |
| `TPM2_GetCommandAuditDigest` | 18.6 | Hard | Sign command audit digest. Requires command audit log with running hash. New subsystem |
| `TPM2_Commit` | 19.2 | Hard | DAA and anonymous attestation ephemeral key. Complex ECC point math (K, L, E generation). Needs DAA support in wolfCrypt |
| `TPM2_SetAlgorithmSet` | 26.3 | Hard | Vendor-specific algorithm configuration. Rarely implemented, can return TPM_RC_COMMAND_CODE |
| `TPM2_FieldUpgradeStart` | 27.2 | Hard | Firmware upgrade initiation. Vendor-specific, requires secure update infrastructure |
| `TPM2_FieldUpgradeData` | 27.3 | Hard | Firmware upgrade data blocks. Vendor-specific |
| `TPM2_FirmwareRead` | 27.4 | Hard | Read firmware for backup. Vendor-specific |

#### Revision 1.59 additions (5 new command codes)

`TPM2_MAC` shares command code 0x155 with `TPM2_HMAC`, and `TPM2_MAC_Start` shares 0x15B with `TPM2_HMAC_Start`, so they add no new codes. The source shows only the HMAC form (no CMAC handling was found), so the symmetric-key MAC form is not confirmed as supported.

| Command | Spec Section | Difficulty | Notes |
|------------------------------------------|--------|--------|------------------------------------------|
| `TPM2_MAC` | 15.6 | Medium | Block cipher MAC (CMAC). Like HMAC but uses symmetric key. Needs wolfCrypt CMAC |
| `TPM2_MAC_Start` | 17.3 | Medium | Start MAC sequence. Mirrors HMAC_Start for CMAC |
| `TPM2_CertifyX509` | 18.8 | Hard | Generate partial X.509 certificate. Complex ASN.1 construction, caller provides tbsCert template. Deprecated in Version 184 |
| `TPM2_AC_GetCapability` | 32.2 | Hard | Deprecated in Version 184. Attached component capability query. Hardware-specific, rarely needed for software TPM |
| `TPM2_AC_Send` | 32.3 | Hard | Deprecated in Version 184. Send data to attached component. Hardware-specific |
| `TPM2_Policy_AC_SendSelect` | 32.4 | Medium | Deprecated in Version 184. Policy for AC_Send. Like other policy commands |
| `TPM2_ACT_SetTimeout` | 33.2 | Medium | Set authenticated countdown timer. Needs ACT state and timer infrastructure |

#### Version 184 additions (9 command codes, none missing)

Version 184 marks `CreateLoaded`, `AC_GetCapability`, `AC_Send`, `Policy_AC_SendSelect`, and `CertifyX509` as deprecated. `CreateLoaded` is still implemented here.

All nine additions are implemented. `TPM2_ECC_Encrypt` and `TPM2_ECC_Decrypt` need a wolfSSL that exports its RNG-blinded ECC point multiplication, and `TPM2_NV_DefineSpace2` accepts only the `TPM_HT_NV_INDEX` handle type; see ECC Encryption below.

#### Conditionally implemented

`TPM2_PolicyTransportSPDM` has a handler and a dispatch-table entry whenever `WOLFTPM_SPDM` is enabled, and it is removed by `FWTPM_NO_POLICY`. It is not missing. See [SPDM Responder](spdm.md).

`TPM2_ReadOnlyControl`, `TPM2_SetCapability`, `TPM2_NV_ReadPublic2`, `TPM2_PolicyCapability` and `TPM2_PolicyParameters` are implemented; see Read-Only Mode and Settable Feature Configuration below.

### Coverage Summary

The eight Version 185 PQC commands (`TPM2_Encapsulate`, `TPM2_Decapsulate`, `TPM2_SignDigest`, `TPM2_VerifyDigestSignature`, `TPM2_SignSequenceStart`, `TPM2_SignSequenceComplete`, `TPM2_VerifySequenceStart`, `TPM2_VerifySequenceComplete`) are implemented under `--enable-pqc`. See [Post-Quantum Support](post-quantum.md) for the PQC-only restriction on these commands.

| Spec Version | Total Command Codes | Implemented (default build) | Missing | Coverage |
|-------------|---------------------|-----------------------------|---------|----------|
| Revision 1.38 | 112 | 103 | 9 | 92% |
| Revision 1.59 | 117 | 103 | 14 | 88% |
| Version 184 | 126 | 111 | 15 | 88% |
| Version 185 | 134 | 119 | 15 | 89% |

Implemented counts assume RSA, ECC, AES, and all feature groups, with SPDM, PQC (except in the Version 185 row), and the vendor test command disabled. Enabling `WOLFTPM_SPDM` adds `PolicyTransportSPDM` (one more implemented code). The Version 185 row includes the eight PQC commands.

Known limitations: `TPM2_SelfTest` is a minimal smoke test and `TPM2_IncrementalSelfTest` is a stub, as noted above, `SU_STATE` resume is not supported (see the lifecycle section), `TPM2_PolicySecret` rejects nonzero expiration because expiring policy tickets are not supported, and `TPM2_DictionaryAttackParameters` limits `newMaxTries` to 65535. The command coverage above should not be read as full conformance with the TCG specification.

## Read-Only Mode (Version 184)

Built by default. Set `FWTPM_NO_READONLY` to compile the feature out entirely; see [Building](building.md).

`TPM2_ReadOnlyControl` requires Platform authorization and takes a single `TPMI_YES_NO`. The state is reported as the `readOnly` bit (bit 4) of `TPMA_STARTUP_CLEAR`, read with `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_STARTUP_CLEAR)`.

While the mode is on, the dispatcher refuses every command Part 3 Table 190 lists as Not Permitted with `TPM_RC_READ_ONLY`. The refusal happens before authorization processing, so a refused command cannot consume dictionary-attack tries or a session. Of the commands this implementation has, the refused set is Create, CreateLoaded, ObjectChangeAuth, CreatePrimary, HierarchyControl, SetPrimaryPolicy, ChangePPS, ChangeEPS, Clear, ClearControl, HierarchyChangeAuth, EvictControl, PCR_Allocate, PCR_SetAuthPolicy, PCR_SetAuthValue, DictionaryAttackParameters, ClockSet, ClockRateAdjust, SetCapability, NV_DefineSpace, NV_UndefineSpace, NV_UndefineSpaceSpecial, NV_Increment, NV_GlobalWriteLock and NV_ChangeAuth.

`NV_Write`, `NV_Extend`, `NV_SetBits`, `NV_WriteLock` and `NV_ReadLock` are conditional rather than refused outright: they succeed only on an index defined with both `TPMA_NV_ORDERLY` and `TPMA_NV_CLEAR_STCLEAR`, so the modification cannot outlive the power cycle that clears the mode. Any other index returns `TPM_RC_READ_ONLY`. `NV_Increment` is refused on every index because the TPM keeps one global increment counter across all of them. Reads, cryptographic operations, PCR extends, signing, quoting, and context save and load remain available.

Table 190 also makes `TPM2_PolicySecret` conditional on the authorizing entity not being a PIN Pass/Fail NV index. That case cannot arise in this implementation: `TPM2_NV_DefineSpace` accepts only `TPM_NT_ORDINARY`, `TPM_NT_COUNTER`, `TPM_NT_BITS` and `TPM_NT_EXTEND`, so a PIN index cannot be defined, and no check for it is implemented.

The bit is CLEAR on TPM Reset and TPM Restart and preserved by TPM Resume. It is carried in the NV orderly-shutdown marker rather than the flags byte, which has no spare bit, so it survives an orderly `Shutdown(STATE)` and a process restart. That marker gains a fourth byte; older firmware rejects the longer record, the same downgrade consideration as the two earlier extensions to it.

## ECC Encryption (Version 184)

`TPM2_ECC_Encrypt` and `TPM2_ECC_Decrypt` implement GB/T 32918.4-2016 as given in TPM 2.0 Part 1 Annex C.2.4, which generalizes it to any ECC key whose restricted attribute is CLEAR. The ephemeral public point is returned as `C1`, the plaintext is masked with a keystream derived from both coordinates of the shared point, and the integrity value is `C3 = H(x2 || M || y2)`.

Annex C states that only `TPM_ALG_KDF2` is supported, so any other KDF scheme returns `TPM_RC_SCHEME`. KDF2 from ISO/IEC 18033-2 is X9.63 with an empty SharedInfo, so `wc_X963_KDF` supplies it directly and no new primitive is required. Because `C3` covers the plaintext rather than the ciphertext, decryption recovers the plaintext first and verifies the integrity value before returning any of it. Decryption also requires decrypt SET, and a point that is not on the key's curve is refused with `TPM_RC_ECC_POINT`.

Both commands need the full shared point rather than only its x coordinate, so they use the same RNG-blinded multiplication as `TPM2_ZGen_2Phase`. That API is exported only when wolfSSL is built with `WOLFSSL_PUBLIC_ECC_ADD_DBL`, which `--enable-wpas` sets. Without it `FWTPM_NO_ECC_ENCRYPT` is set automatically and the commands are absent, so the operation can never silently fall back to an unblinded multiply. A hash the fwTPM supports may still be refused by the KDF, since `wc_X963_KDF` accepts SHA-3 only on a new enough wolfSSL and never in a FIPS build; that surfaces as `TPM_RC_HASH`.

## Settable Feature Configuration (Version 184)

`TPM2_SetCapability` writes one `TPMS_TAGGED_CONFIG` per call under Platform authorization. `TPMU_SET_CAPABILITIES` has no normative member list, since Part 2 Table 137 defers it to a TCG Registry, so the only capability accepted is `TPM_CAP_CONFIGS` (`0x81C90001`), which matches the structure wolfTPM's client side already sends. Any other capability, an unrecognized `TPM_PT_CONFIG_*`, or a write to a configuration whose `lock` is already SET returns `TPM_RC_VALUE`; there is no `TPM_RC_LOCKED` with which to distinguish the last case.

The four configurations (`ENCRYPTDECRYPT2`, `CHANGEEPS`, `TPMID_NV`, `SPDM_PSK`) are stored with their `enable` and `lock` flags, persisted under their own NV journal tag, and reported by `TPM2_GetCapability(TPM_CAP_CONFIGS)` as a `TPML_TAGGED_CONFIG`. A `lock` lasts for the lifetime of the part and survives `TPM2_Clear`.

The configurations are recorded and reported but do not gate command availability: this implementation selects its feature set at build time through the `FWTPM_NO_*` macros. Treat the configuration state as provisioning metadata rather than a runtime switch.

## Startup and Shutdown Lifecycle

1. **First boot:** `FWTPM_NV_Init` finds no NV file, generates random hierarchy seeds, and saves the initial state.
2. **`TPM2_Startup(SU_CLEAR)`:** Flushes transient objects and sessions and resets PCRs. Required before most other TPM commands. `TPM2_GetCapability` is accepted before `Startup`.
3. **Normal operation:** Commands are processed through `FWTPM_ProcessCommand`.
4. **`TPM2_Shutdown`:** Saves NV state but does not clear the "started" flag. The TPM remains logically powered on.
5. **Server restart** (process exit and relaunch) constitutes a power cycle. Only after a power cycle can `TPM2_Startup` be called again.

Calling `TPM2_Startup` on an already-started TPM returns `TPM_RC_INITIALIZE`.

Known limitation: `Startup(SU_STATE)` is accepted without checking that a matching `Shutdown(SU_STATE)` came before it, and a process restart zeroes `FWTPM_CTX` and reloads only NV-backed state. Transient objects and sessions are therefore not preserved across a restart, which a conforming TPM Resume requires. This stays a limitation until volatile state serialization and the shutdown and startup sequence checks are implemented.

## Primary Key Derivation

Primary keys are deterministically derived from the hierarchy seed from the hierarchy seed using KDFa-based formulas that are specific to this implementation. The same seed, the same public template, and the same `sensitiveCreate.data` always produce the same key. Revision 1.38 discusses primary-object creation in Clause 27.

- **RSA:** Primes p and q are derived by iterative KDFa with the labels `"RSA p"` and `"RSA q"`, then primality testing, then CRT computation.
- **ECC:** The private scalar d is derived with `KDFa(nameAlg, seed, "ECC", hashUnique, counter)`, and the public point is Q = d*G.
- **KEYEDHASH and SYMCIPHER:** Key bytes are derived with `KDFa(nameAlg, seed, label, hashUnique)`. For KEYEDHASH, nonempty `sensitiveCreate.data` is used directly and is not derived.
- **hashUnique:** `H(sensitiveCreate.data || inPublic.unique)`. Because `sensitiveCreate.data` feeds `hashUnique` and the cache digest, a different value gives a different key.

A primary key cache (SHA-256 of the template, `FWTPM_MAX_PRIMARY_CACHE` slots) avoids re-deriving expensive RSA keys on repeated `CreatePrimary` calls.

Hierarchy seeds are managed by `ChangePPS` (platform) and `ChangeEPS` (endorsement). `Clear` regenerates the owner (storage primary) seed and resets endorsement authorization and policy state, but it leaves the endorsement seed and the platform seed unchanged; use `ChangeEPS` to replace the endorsement seed. The null seed is re-randomized on every `Startup(CLEAR)`. For post-quantum primary keys, see [Post-Quantum Support](post-quantum.md).

## See Also

- [Building](building.md)
- [Usage](usage.md)
- [HAL and Porting](hal-and-porting.md)
- [Post-Quantum Support](post-quantum.md)
- [SPDM Responder](spdm.md)
- [Post-Quantum (library-wide)](../post-quantum.md)
- [SPDM (library-wide)](../spdm.md)
