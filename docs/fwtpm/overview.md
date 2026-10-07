# fwTPM Overview

The wolfTPM fwTPM (also called fTPM or swtpm-compatible) is a real firmware TPM 2.0 built entirely on wolfCrypt cryptographic primitives. It is not only an emulator for tests. It is a portable, standards-compliant TPM 2.0 command processor that runs as a standalone server process (`fwtpm_server`) or is linked into an embedded firmware image. It implements 105 of the 113 commands in the TPM 2.0 v1.38 specification (93% coverage), rising to 113 commands once the v1.85 post-quantum commands are enabled.

Because it is a complete TPM implementation and not a stub, the fwTPM can be used for testing and also for production, security-critical, and isolated deployments where a discrete TPM chip is not available or not wanted. It also brings post-quantum cryptography and SPDM to platforms without TPM silicon.

The fwTPM can replace a hardware TPM for:

- **Embedded and IoT platforms** without a discrete TPM chip (bare-metal via an SPI or I2C TIS HAL)
- **Isolated deployments**, such as a TPM running on a separate core, a TrustZone secure world, or a lock-step real-time core next to a Linux application processor
- **Development and testing** of TPM-dependent applications (drop-in for swtpm or the Microsoft TPM simulator)
- **CI/CD pipelines** that need TPM functionality (socket transport compatible with tpm2-tools)
- **Prototyping** TPM workflows before hardware is available
- **Post-quantum and SPDM work** without TPM silicon (see [Post-Quantum Support](post-quantum.md) and [SPDM Responder](spdm.md))

## Features

- Standards-compliant TPM 2.0 command processor (105 of 113 v1.38 commands).
- TCP socket transport using the Microsoft TPM simulator protocol, compatible with wolfTPM examples and tpm2-tools. Both the mssim and swtpm TCTI protocols are auto-detected on the command port.
- TIS register-level transport over POSIX shared memory, or over SPI or I2C for bare-metal integration.
- HAL abstractions for IO and NV storage, so the core logic does not change when porting. See [HAL and Porting](hal-and-porting.md).
- Post-quantum cryptography with `--enable-pqc` (alias `--enable-v185`): ML-DSA (FIPS 204) signing and ML-KEM (FIPS 203) key encapsulation per TCG TPM 2.0 Library Specification v1.85. Configure auto-detects PQC when `--enable-fwtpm` is built against a wolfCrypt that has both. See [Post-Quantum Support](post-quantum.md).
- SPDM 1.3 responder for testing the SPDM stack without silicon. See [SPDM Responder](spdm.md).
- Compile-time feature gates (`FWTPM_NO_*`) to shrink the build for constrained targets. See [Building](building.md).

## Architecture

```
+---------------------+          +---------------------------+
| wolfTPM Client App  |          |  fwtpm_server             |
| (examples, tests)   |          |                           |
+----------+----------+          |  +---------------------+  |
           |                     |  | fwtpm_command.c      | |
     TCP (SWTPM protocol)        |  | (command processor)  | |
     or TIS shared memory        |  +----------+----------+  |
           |                     |             |             |
+----------v----------+          |  +----------v----------+  |
| Transport Layer     +--------->+  | wolfCrypt           |  |
| (socket or TIS HAL) |          |  | (RSA, ECC, SHA,     |  |
+---------------------+          |  |  HMAC, RNG, AES)    |  |
                                 |  +---------------------+  |
                                 |             |             |
                                 |  +----------v----------+  |
                                 |  | fwtpm_nv.c           | |
                                 |  | (persistent storage) | |
                                 |  +---------------------+  |
                                 +---------------------------+
```

**Components:**

| File | Role |
|------|------|
| `fwtpm_command.c` | TPM 2.0 command processor and dispatch table (~9500 lines) |
| `fwtpm_io.c` | Transport layer: SWTPM TCP socket protocol (default) |
| `fwtpm_nv.c` | NV storage: file-based (default); HAL-abstracted, with a built-in append-only mode for write-once flash |
| `fwtpm_tis.c` | TIS register state machine (transport-agnostic) |
| `fwtpm_tis_shm.c` | POSIX shared memory and semaphore TIS transport |
| `fwtpm_main.c` | Server entry point, CLI argument parsing |
| `tpm2_util.c` | Shared utilities (hash helpers, ForceZero, PrintBin) |
| `tpm2_packet.c` | TPM packet marshaling and unmarshaling |
| `tpm2_param_enc.c` | Parameter encryption (XOR and AES session encryption) |

## Supported TPM 2.0 Commands

This section is a command-coverage reference. A default build (no `FWTPM_NO_*` macro set) includes every group below. Setting a gate macro removes that group's commands from the dispatch table, from `TPM2_GetCapability(TPM_CAP_COMMANDS)`, and from the `TPM_PT_TOTAL_COMMANDS` count. See [Building](building.md) for the gates.

### Startup and Self-Test

| Command | Description |
|---------|-------------|
| `TPM2_Startup` | Initialize TPM (SU_CLEAR or SU_STATE) |
| `TPM2_Shutdown` | Save state and prepare for power-off |
| `TPM2_SelfTest` | Execute full self-test |
| `TPM2_IncrementalSelfTest` | Incremental algorithm self-test |
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
| `TPM2_Rewrap` | Re-wrap key under new parent (placeholder) |
| `TPM2_FlushContext` | Unload a transient object or session |
| `TPM2_ContextSave` | Save object or session context |
| `TPM2_ContextLoad` | Restore saved context |
| `TPM2_ReadPublic` | Read public area of a loaded key |
| `TPM2_ObjectChangeAuth` | Change authorization of a key |
| `TPM2_EvictControl` | Make transient key persistent (or remove) |
| `TPM2_HierarchyControl` | Enable or disable a hierarchy |
| `TPM2_HierarchyChangeAuth` | Change hierarchy authorization value |
| `TPM2_Clear` | Clear hierarchy (Owner or Platform) |
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

The fwTPM follows the TPM 2.0 spec (Part 1 Sec.19.8). A failed authorization of a DA-protected entity increments `failedTries`. Once it reaches `maxTries` the TPM returns `TPM_RC_LOCKOUT`. `failedTries` is persisted in NV on every failure, so a power cycle cannot reset it.

When a clock HAL is registered (`FWTPM_Clock_SetHAL`), the counter self-heals one try per `recoveryTime` seconds, and a non-orderly shutdown adds a one-try penalty. On clockless builds neither applies: recovery is only through `DictionaryAttackLockReset` or `Clear`, so routine unclean power-off cannot accumulate into lockout.

A failed `lockoutAuth` locks the lockout hierarchy. That lock persists across reboot and clears after `lockoutRecovery` seconds, except when `lockoutRecovery` is 0 (reboot-only recovery). The clock HAL reports milliseconds since boot, so this timer measures continuous post-boot uptime, not wall-clock time across reboots. A device that reboots more often than `lockoutRecovery` extends its effective recovery window.

The lock only blocks commands authorized through `lockoutAuth` (`DictionaryAttackLockReset`, `DictionaryAttackParameters`, and lockout-authorized `Clear`). The platform hierarchy is always an escape hatch: `TPM2_ClearControl(platformAuth, clearDisable=NO)` followed by `TPM2_Clear(platformAuth)` recovers even when `disableClear` was set. `Startup` and `Shutdown` are never DA-gated, so a reboot in lockout can always recover. Entities marked `noDA` (`TPMA_OBJECT_noDA` on objects, `TPMA_NV_NO_DA` on NV indices) never feed the counter and stay usable during lockout.

`TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)` reports `TPM_PT_MAX_AUTH_FAIL`, `TPM_PT_LOCKOUT_INTERVAL`, `TPM_PT_LOCKOUT_RECOVERY`, `TPM_PT_LOCKOUT_COUNTER`, and the `inLockout` bit of `TPM_PT_PERMANENT`.

Durable accounting writes the NV FLAGS entry on each DA-protected failure (and on the first DA-protected auth use per boot). This is bounded per boot, because the lockout gate stops counting once locked. On flash-backed targets it still adds wear and makes failed-auth latency NV-bound, so size the NV backend accordingly.

The first use of a DA-protected (non-`noDA`) authorization after startup makes a real TPM persist a `daUsed` flag to NV and return `TPM_RC_RETRY` ("resubmit the identical command") while it writes. Build with `FWTPM_DA_USED_RETRY` to emulate this so clients exercise their resubmit and retry handling. It is off by default, and DA accounting and persistence are active regardless. Compile out all DA logic with `FWTPM_NO_DA`.

Coverage: DA, noDA, lockout, self-heal, and persistence unit tests in `tests/fwtpm_unit_tests.c`, the `examples/management/da_check` end-to-end example (add `-lockout` for the destructive lockout and recovery path), and the `tests/fwtpm_da_retry.sh` harness that exercises the `TPM_RC_RETRY` path against a `FWTPM_DA_USED_RETRY` build.

### NV RAM

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
| `TPM2_NV_Certify` | Certify NV index contents |

### Attestation and Credentials

| Command | Description |
|---------|-------------|
| `TPM2_Quote` | Generate signed PCR quote |
| `TPM2_Certify` | Certify a loaded key |
| `TPM2_CertifyCreation` | Prove key was created by this TPM |
| `TPM2_GetTime` | Signed attestation of TPM clock |
| `TPM2_MakeCredential` | Create credential blob for a key |
| `TPM2_ActivateCredential` | Unwrap credential blob |

## Command Coverage

### Implemented (105 commands)

The fwTPM implements 105 of the 113 commands in the v1.38 baseline (93% coverage).

**Core set, never gated (36 commands):**
Startup, Shutdown, SelfTest, IncrementalSelfTest, GetTestResult, GetRandom, StirRandom, GetCapability, TestParms, PCR_Read, PCR_Extend, PCR_Reset, PCR_Event, PCR_Allocate, PCR_SetAuthPolicy, PCR_SetAuthValue, CreatePrimary, FlushContext, ReadPublic, Clear, ClearControl, ChangeEPS, ChangePPS, HierarchyControl, HierarchyChangeAuth, SetPrimaryPolicy, EvictControl, Create, ObjectChangeAuth, Load, Sign, VerifySignature, StartAuthSession, Unseal, LoadExternal, CreateLoaded

These are present in every build.

**Optional vendor command (off by default, `WOLFTPM_FWTPM_TCG_TEST`):**
Vendor_TCG_Test

**Conditional on algorithm (`NO_RSA`, `HAVE_ECC`, `NO_AES`):**
RSA_Encrypt, RSA_Decrypt, ECDH_KeyGen, ECDH_ZGen, ECC_Parameters, EC_Ephemeral, ZGen_2Phase, EncryptDecrypt, EncryptDecrypt2

**Conditional on feature macros:**

- `FWTPM_NO_POLICY`: PolicyGetDigest, PolicyRestart, PolicyPCR, PolicyPassword, PolicyAuthValue, PolicyCommandCode, PolicyOR, PolicySecret, PolicyAuthorize, PolicyLocality, PolicySigned, PolicyNV, PolicyPhysicalPresence, PolicyCpHash, PolicyNameHash, PolicyDuplicationSelect, PolicyNvWritten, PolicyTemplate, PolicyCounterTimer, PolicyTicket, PolicyAuthorizeNV (21 commands)
- `FWTPM_NO_NV`: NV_DefineSpace, NV_UndefineSpace, NV_UndefineSpaceSpecial, NV_ReadPublic, NV_Write, NV_Read, NV_Extend, NV_Increment, NV_WriteLock, NV_ReadLock, NV_SetBits, NV_ChangeAuth, NV_GlobalWriteLock (13 commands). Also gates PolicyNV and PolicyAuthorizeNV when policy is enabled and removes the in-memory NV index slots from `FWTPM_CTX`.
- `FWTPM_NO_ATTESTATION`: Quote, Certify, CertifyCreation, GetTime, NV_Certify
- `FWTPM_NO_CREDENTIAL`: MakeCredential, ActivateCredential
- `FWTPM_NO_DA`: DictionaryAttackLockReset, DictionaryAttackParameters (2 commands)
- `FWTPM_NO_PARAM_ENC`: Disables parameter encryption and decryption for command and response parameters. Sessions still work for HMAC auth, but encrypted transport is disabled. Reduces code size by removing AES-CFB and XOR parameter encryption.
- `FWTPM_NO_KEY_MIGRATION`: Import, Duplicate, Rewrap (3 commands). Shared key helpers used by Create and Load are retained.
- `FWTPM_NO_ECDH`: ECDH_KeyGen, ECDH_ZGen, EC_Ephemeral, ZGen_2Phase, ECC_Parameters (5 commands). ECDSA sign and verify are retained. Also drops the `ecEphemeral*` commit state from `FWTPM_CTX`.
- `FWTPM_NO_HASH_CMDS`: Hash, HMAC, HMAC_Start, HashSequenceStart, SequenceUpdate, SequenceComplete, EventSequenceComplete (7 commands). When `WOLFTPM_MLDSA` is built, only SequenceUpdate is retained, because the ML-DSA verify sequences stream their message through it. SequenceComplete is not shared: ML-DSA sequences finalize through SignSequenceComplete and VerifySequenceComplete, so advertising it in a gated build would expose a command that can never succeed. Also drops the per-instance hash-sequence slots (`hashSeq[FWTPM_MAX_HASH_SEQ]`) from `FWTPM_CTX`.
- `FWTPM_NO_CONTEXT`: ContextSave, ContextLoad (2 commands). FlushContext is retained. Also drops the per-boot context protection key and the saved-context replay list from `FWTPM_CTX`.
- `FWTPM_NO_SYM_ENCRYPT`: EncryptDecrypt, EncryptDecrypt2 (2 commands). Nests inside `NO_AES`. AES itself is retained for session parameter encryption, AES-GCM, and (unless `FWTPM_NO_CONTEXT` is also set) context protection.
- `FWTPM_NO_CLOCK`: ReadClock, ClockSet, ClockRateAdjust (3 commands). GetTime is under `FWTPM_NO_ATTESTATION`, not this flag.

These gates are independent and there is intentionally no umbrella macro: pick exactly the groups your fTPM does not need. Applying all of them plus `FWTPM_NO_POLICY`, `FWTPM_NO_ATTESTATION`, `FWTPM_NO_CREDENTIAL`, `FWTPM_NO_DA`, and `FWTPM_NO_PARAM_ENC` (keeping NV, or adding `FWTPM_NO_NV` to drop it) leaves a core fTPM: Startup, GetCapability, GetRandom, PCR, Create, Load, Sign, VerifySignature, NV, and sessions. See the MicroBlaze V example in the `wolftpm-examples` repository (listed in [Usage](usage.md)) for a worked selection.

### Missing Commands

#### v1.38 baseline (8 missing commands)

Medium (moderate logic, builds on existing infrastructure):

| Command | Spec Section | Difficulty | Notes |
|---------|-------------|------------|-------|
| `TPM2_SetCommandCodeAuditStatus` | 21.2 | Medium | Manage list of commands that are audited. Needs audit bitmap in context |
| `TPM2_PP_Commands` | 26.2 | Medium | Manage physical presence command list. Needs PP command bitmap |

Hard (complex crypto or new subsystems):

| Command | Spec Section | Difficulty | Notes |
|---------|-------------|------------|-------|
| `TPM2_GetSessionAuditDigest` | 18.5 | Hard | Sign session audit digest. Requires session audit tracking (running hash of all commands in session). New subsystem |
| `TPM2_GetCommandAuditDigest` | 18.6 | Hard | Sign command audit digest. Requires command audit log with running hash. New subsystem |
| `TPM2_Commit` | 19.2 | Hard | DAA and anonymous attestation ephemeral key. Complex ECC point math (K, L, E generation). Needs DAA support in wolfCrypt |
| `TPM2_SetAlgorithmSet` | 26.3 | Hard | Vendor-specific algorithm configuration. Rarely implemented, can return TPM_RC_COMMAND_CODE |
| `TPM2_FieldUpgradeStart` | 27.2 | Hard | Firmware upgrade initiation. Vendor-specific, requires secure update infrastructure |
| `TPM2_FieldUpgradeData` | 27.3 | Hard | Firmware upgrade data blocks. Vendor-specific |
| `TPM2_FirmwareRead` | 27.4 | Hard | Read firmware for backup. Vendor-specific |

#### v1.59 additions (7 commands)

| Command | Spec Section | Difficulty | Notes |
|---------|-------------|------------|-------|
| `TPM2_MAC` | 15.6 | Medium | Block cipher MAC (CMAC). Like HMAC but uses symmetric key. Needs wolfCrypt CMAC |
| `TPM2_MAC_Start` | 17.3 | Medium | Start MAC sequence. Mirrors HMAC_Start for CMAC |
| `TPM2_CertifyX509` | 18.8 | Hard | Generate partial X.509 certificate. Complex ASN.1 construction, caller provides tbsCert template. Deprecated in v1.84 |
| `TPM2_AC_GetCapability` | 32.2 | Hard | Attached component capability query. Hardware-specific, rarely needed for software TPM |
| `TPM2_AC_Send` | 32.3 | Hard | Send data to attached component. Hardware-specific |
| `TPM2_Policy_AC_SendSelect` | 32.4 | Medium | Policy for AC_Send. Like other policy commands |
| `TPM2_ACT_SetTimeout` | 33.2 | Medium | Set authenticated countdown timer. Needs ACT state and timer infrastructure |

#### v1.84 additions (9 commands)

| Command | Spec Section | Difficulty | Notes |
|---------|-------------|------------|-------|
| `TPM2_ECC_Encrypt` | 14.8 | Medium | ECC-based encryption (ECIES or ElGamal). wolfCrypt ECIES support available |
| `TPM2_ECC_Decrypt` | 14.9 | Medium | ECC-based decryption. Paired with ECC_Encrypt |
| `TPM2_PolicyCapability` | 23.x | Easy | Assert TPM capability value in policy session |
| `TPM2_PolicyParameters` | 23.x | Easy | Assert command parameters in policy session |
| `TPM2_SetCapability` | 30.x | Medium | Modify TPM capability settings. Platform auth required |
| `TPM2_NV_DefineSpace2` | 31.x | Medium | Extended NV space definition (larger attribute field). Extends existing NV_DefineSpace |
| `TPM2_NV_ReadPublic2` | 31.x | Easy | Extended NV public read. Extends existing NV_ReadPublic |
| `TPM2_ReadOnlyControl` | 24.x | Easy | Toggle TPM read-only mode. Simple flag |
| `TPM2_PolicyTransportSPDM` | 23.x | Hard | SPDM transport policy. Requires SPDM protocol support |

### Coverage Summary

The eight v1.85 PQC commands (`TPM2_Encapsulate`, `TPM2_Decapsulate`, `TPM2_SignDigest`, `TPM2_VerifyDigestSignature`, `TPM2_SignSequenceStart`, `TPM2_SignSequenceComplete`, `TPM2_VerifySequenceStart`, `TPM2_VerifySequenceComplete`) are implemented under `--enable-pqc` (alias `--enable-v185`). See [Post-Quantum Support](post-quantum.md) for the PQC-only restriction on these commands.

| Spec Version | Total Commands | Implemented | Missing | Coverage |
|-------------|---------------|-------------|---------|----------|
| v1.38 | 113 | 105 | 8 | 93% |
| v1.59 | 120 | 105 | 15 | 88% |
| v1.84 | 129 | 105 | 24 | 81% |
| v1.85 | 137 | 113 | 24 | 82% |

## Startup and Shutdown Lifecycle

1. **First boot:** `FWTPM_NV_Init` finds no NV file, generates random hierarchy seeds, and saves the initial state.
2. **`TPM2_Startup(SU_CLEAR)`:** Flushes transient objects and sessions and resets PCRs. Required before any other TPM command.
3. **Normal operation:** Commands are processed through `FWTPM_ProcessCommand`.
4. **`TPM2_Shutdown`:** Saves NV state but does not clear the "started" flag. The TPM remains logically powered on.
5. **Server restart** (process exit and relaunch) constitutes a power cycle. Only after a power cycle can `TPM2_Startup` be called again.

Calling `TPM2_Startup` on an already-started TPM returns `TPM_RC_INITIALIZE`.

## Primary Key Derivation

Primary keys are deterministically derived from the hierarchy seed per TPM 2.0 Part 1 Section 26. The same seed and the same template always produce the same key:

- **RSA:** Primes p and q are derived by iterative KDFa with the labels `"RSA p"` and `"RSA q"`, then primality testing, then CRT computation.
- **ECC:** The private scalar d is derived with `KDFa(nameAlg, seed, "ECC", hashUnique, counter)`, and the public point is Q = d*G.
- **KEYEDHASH and SYMCIPHER:** Key bytes are derived with `KDFa(nameAlg, seed, label, hashUnique)`.
- **hashUnique:** `H(sensitiveCreate.data || inPublic.unique)` per Section 26.1.

A primary key cache (SHA-256 of the template, `FWTPM_MAX_PRIMARY_CACHE` slots) avoids re-deriving expensive RSA keys on repeated `CreatePrimary` calls.

Hierarchy seeds are managed by `ChangePPS` (platform) and `ChangeEPS` (endorsement). `Clear` regenerates the owner and endorsement seeds. The null seed is re-randomized on every `Startup(CLEAR)`. For post-quantum primary keys, see [Post-Quantum Support](post-quantum.md).

## See Also

- [Building](building.md)
- [Usage](usage.md)
- [HAL and Porting](hal-and-porting.md)
- [Post-Quantum Support](post-quantum.md)
- [SPDM Responder](spdm.md)
- [Post-Quantum (library-wide)](../post-quantum.md)
- [SPDM (library-wide)](../spdm.md)
