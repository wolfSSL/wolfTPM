# Building the fwTPM

This page covers how to build the fwTPM server, the configure options and compile defines that control it, and the compile-time macros that tune size and features. For what the fwTPM is, see the [Overview](overview.md).

## Prerequisites

wolfSSL must be built with TPM support, keygen, and `WC_RSA_NO_PADDING`:

```sh
cd wolfssl
./configure --enable-wolftpm --enable-pkcallbacks --enable-keygen CFLAGS="-DWC_RSA_NO_PADDING"
make
sudo make install
```

## Build the fwTPM Server

**Socket transport (SWTPM protocol, default for development):**

```sh
cd wolftpm
./configure --enable-fwtpm --enable-swtpm
make
```

This produces `src/fwtpm/fwtpm_server` and builds the wolfTPM client library with `WOLFTPM_SWTPM` for socket-based communication.

**TIS and shared-memory transport (for fwTPM HAL integration):**

```sh
./configure --enable-fwtpm
make
```

When `--enable-swtpm` is omitted, the build uses TIS shared-memory transport (`WOLFTPM_FWTPM_HAL`, `WOLFTPM_ADV_IO`) and compiles `fwtpm_tis.c` into the server.

**fwTPM server only (no client library or examples):**

```sh
./configure --enable-fwtpm-only --enable-swtpm
make
```

This builds only the `fwtpm_server` binary and skips `libwolftpm`, examples, and tests. It is useful for embedded targets that only need the TPM server.

**Debug build:**

```sh
./configure --enable-fwtpm --enable-swtpm --enable-debug
make
```

## Build Output

| Artifact | Description |
|----------|-------------|
| `src/fwtpm/fwtpm_server` | Standalone fwTPM server binary |
| `src/.libs/libwolftpm.*` | wolfTPM client library |

## Key Build Flags

| Configure Option | Effect |
|-----------------|--------|
| `--enable-fwtpm` | Build `fwtpm_server` binary (alongside client library) |
| `--enable-fwtpm-only` | Build only `fwtpm_server` (no client library, examples, or tests) |
| `--enable-swtpm` | Use SWTPM TCP socket transport (ports 2321 and 2322) |
| `--enable-fwtpm-nv-appendonly` | Append-only NV journal for write-once flash ports (off by default) |
| `--enable-fwtpm-small-ctx` | Reduced-size fwTPM context for small targets |
| `--enable-pqc` (alias `--enable-v185`) | TPM 2.0 v1.85 post-quantum support (see [Post-Quantum Support](post-quantum.md)) |
| `--enable-spdm` | SPDM responder (with `--enable-tcg` or `--enable-psk`; see [SPDM Responder](spdm.md)) |
| `--enable-fuzz` | Fuzzing build |
| `--enable-debug` | Enable debug logging |

| Compile Define | Set By |
|---------------|--------|
| `WOLFTPM_FWTPM` | Automatically set for the `fwtpm_server` target only |
| `WOLFTPM_SWTPM` | `--enable-swtpm` |
| `WOLFTPM_FWTPM_HAL` | `--enable-fwtpm` without `--enable-swtpm` |
| `WOLFTPM_FWTPM_TIS` | `--enable-fwtpm` without `--enable-swtpm` |
| `WOLFTPM_ADV_IO` | Set with `WOLFTPM_FWTPM_HAL` |
| `WOLFTPM_FWTPM_NV_APPEND_ONLY` | `--enable-fwtpm-nv-appendonly` (CMake `WOLFTPM_FWTPM_NV_APPEND_ONLY=yes`) |
| `WOLFTPM_FWTPM_TCG_TEST` | Manually (`CFLAGS=-DWOLFTPM_FWTPM_TCG_TEST`); off by default |

No vendor commands are registered by default. Define `WOLFTPM_FWTPM_TCG_TEST` to compile in the optional `TPM2_Vendor_TCG_Test` (`0x20000000`) echo command.

## Command-Code Enforcement

A valid command code carries only the 16-bit index plus, for vendor commands, the V bit (`CC_VEND`, bit 29). Codes with any other reserved bit set, or codes not in the dispatch table, are rejected with `TPM_RC_COMMAND_CODE`. `TPM2_GetCapability(TPM_CAP_COMMANDS)` returns proper `TPMA_CC` values (index, handle attributes, and V bit, ordered by command code).

## Configuration Macros

All macros are compile-time overridable (for example `-DFWTPM_MAX_OBJECTS=8`).

| Macro | Default | Description |
|-------|---------|-------------|
| `FWTPM_MAX_COMMAND_SIZE` | 4096 | Maximum command and response buffer size (bytes) |
| `FWTPM_MAX_RANDOM_BYTES` | 48 | Maximum bytes per `GetRandom` call |
| `FWTPM_MAX_OBJECTS` | 16 | Maximum concurrently loaded transient objects |
| `FWTPM_MAX_PERSISTENT` | 8 | Maximum persistent objects (via `EvictControl`) |
| `FWTPM_MAX_PRIVKEY_DER` | 2048 | Maximum DER-encoded private key size (bytes) |
| `FWTPM_MAX_HASH_SEQ` | 4 | Maximum concurrent hash and HMAC sequences |
| `FWTPM_MAX_PRIMARY_CACHE` | 16 | Cached primary keys per hierarchy and template |
| `FWTPM_MAX_SESSIONS` | 8 | Maximum concurrent auth sessions |
| `FWTPM_MAX_NV_INDICES` | 16 | Maximum NV RAM index slots; omitted from `FWTPM_CTX` with `FWTPM_NO_NV` |
| `FWTPM_MAX_NV_DATA` | 2048 | Maximum data per NV index (bytes) |
| `FWTPM_DA_DEFAULT_MAX_TRIES` | 32 | DA failed-auth count before lockout |
| `FWTPM_DA_DEFAULT_RECOVERY` | 600 | DA self-heal interval (seconds per try) |
| `FWTPM_DA_DEFAULT_LOCKOUT_RECOVERY` | 86400 | lockoutAuth recovery time (seconds) |
| `FWTPM_DA_MAX_TRIES_LIMIT` | 0xFFFF | Upper clamp for a replayed `maxTries` or `failedTries` |
| `FWTPM_MAX_DATA_BUF` | 1024 | Internal buffer for HMAC, hash, general data |
| `FWTPM_MAX_PUB_BUF` | 512 | Internal buffer for public area, signatures |
| `FWTPM_MAX_DER_SIG_BUF` | 256 | Internal buffer for DER signatures, ECC points |
| `FWTPM_MAX_ATTEST_BUF` | 1024 | Internal buffer for attestation marshaling |
| `FWTPM_MAX_CMD_AUTHS` | 3 | Maximum authorization sessions per command (TPM spec hard cap) |
| `FWTPM_MAX_SENSITIVE_SIZE` | `FWTPM_MAX_PRIVKEY_DER + 128` | Maximum marshaled sensitive area (private key, auth, and nonce headroom) |
| `FWTPM_MAX_SIGN_SEQ` | 4 | Maximum concurrent v1.85 PQC sign and verify sequences |
| `FWTPM_MAX_SYM_KEY_SIZE` | 32 | Symmetric key buffer (sized for AES-256) |
| `FWTPM_MAX_HMAC_KEY_SIZE` | 64 | HMAC key buffer (sized for SHA-512 block) |
| `FWTPM_MAX_HMAC_DIGEST_SIZE` | 64 | HMAC output buffer (sized for SHA-512) |
| `FWTPM_CMD_PORT` | 2321 | Default TCP command port |
| `FWTPM_PLAT_PORT` | 2322 | Default TCP platform port |
| `FWTPM_NV_FILE` | `"fwtpm_nv.bin"` | Default NV storage file path |
| `FWTPM_NV_MAX_WRITE_ALIGN` | 64 | Max append-only program granule in bytes (upper bound on a HAL's `writeAlign`); sizes the pending-granule buffer when `WOLFTPM_FWTPM_NV_APPEND_ONLY` is set |
| `FWTPM_PCR_BANKS` | 2 | Number of PCR banks (SHA-256 and SHA-384) |
| `FWTPM_TIS_BURST_COUNT` | 64 | TIS FIFO burst count (bytes per transfer) |
| `FWTPM_TIS_FIFO_SIZE` | 4096 | TIS command and response FIFO size |

### Stack and Heap Control

| Macro | Effect |
|-------|--------|
| `WOLFTPM_SMALL_STACK` | Use heap allocation for large stack objects |
| `WOLFTPM2_NO_HEAP` | Forbid heap allocation (all stack) |

!!! note
    `WOLFTPM_SMALL_STACK` and `WOLFTPM2_NO_HEAP` are mutually exclusive. Defining both is a compile error.

### v1.85 Embedded RAM Impact

Enabling `--enable-pqc` (or `--enable-v185`) lifts several internal buffers to accommodate PQC key and signature sizes. The defaults shrink automatically at compile time based on which ML-DSA and ML-KEM parameter sets wolfCrypt was built with (`WOLFSSL_NO_ML_DSA_44/65/87`, `WOLFSSL_NO_KYBER512/768/1024`). Boards that only enable the smaller parameter sets get smaller buffers with no per-board override.

**Buffer sizes by enabled parameter set:**

| Macro | Classical | MLDSA-44 + MLKEM-512 | MLDSA-65 + MLKEM-768 | MLDSA-87 + MLKEM-1024 |
|-------|-----------|----------------------|----------------------|------------------------|
| `FWTPM_TIS_FIFO_SIZE`     | 4096 | 4096 | 8192 | 8192 |
| `FWTPM_MAX_COMMAND_SIZE`  | 4096 | 4096 | 8192 | 8192 |
| `FWTPM_MAX_PUB_BUF`       | 512  | 1440 | 2080 | 2720 |
| `FWTPM_MAX_DER_SIG_BUF`   | 256  | 2548 | 3437 | 4755 |
| `FWTPM_MAX_KEM_CT_BUF`    | n/a  | 832  | 1152 | 1632 |

Sizing logic lives in `wolftpm/fwtpm/fwtpm.h` (constants `FWTPM_MAX_MLDSA_SIG_SIZE`, `FWTPM_MAX_MLDSA_PUB_SIZE`, `FWTPM_MAX_MLKEM_CT_SIZE`, `FWTPM_MAX_MLKEM_PUB_SIZE`) and `wolftpm/fwtpm/fwtpm_tis.h` (FIFO size). The ML-DSA constants come from wolfCrypt's `WC_MLDSA_{44,65,87}_*_SIZE` macros. The ML-KEM constants are FIPS 203 spec values, because wolfCrypt's `WC_ML_KEM_*_SIZE` macros cannot be evaluated by the preprocessor.

The 8192 lifts on the FIFO and command buffers only apply when MLDSA-65 or MLDSA-87 is enabled, because their signatures do not fit a 4096-byte response with TPM headers. MLDSA-44-only and MLKEM-only v1.85 builds stay at 4096.

**Per-deployment override:** every macro above is still `#ifndef`-guarded, so a board can override individually on the compile line if the automatic default is wrong for its workload (for example `-DFWTPM_TIS_FIFO_SIZE=2048`).

**Heap versus stack:** building with `WOLFTPM_SMALL_STACK` moves the large per-call buffers off the stack into `XMALLOC` and `XFREE` regions. The PQC paths already use `FWTPM_DECLARE_BUF` and `FWTPM_ALLOC_BUF`, which respect this flag, so no source changes are required. `WOLFTPM2_NO_HEAP` is supported but pays the full stack cost, so pair it with the smallest PQC parameter set you can.

### Algorithm Feature Macros

These macros use wolfCrypt's existing compile-time options to control which cryptographic algorithms are available in `fwtpm_server`. If an algorithm is disabled, the corresponding TPM commands are excluded from the build.

| Macro | Default | Effect |
|-------|---------|--------|
| `NO_RSA` | not defined | Excludes RSA keygen, sign, verify, `RSA_Encrypt`, `RSA_Decrypt` |
| `HAVE_ECC` | defined | Enables ECC keygen, sign, verify, `ECDH_KeyGen`, `ECDH_ZGen`, `ECC_Parameters` |
| `HAVE_ECC384` | defined | Enables P-384 curve support |
| `HAVE_ECC521` or `HAVE_ALL_CURVES` | build-dependent | Enables P-521 when `MAX_ECC_KEY_BITS >= 521` provides 66-byte TPM ECC fields |
| `ECC_MIN_KEY_SZ` | wolfCrypt-defined | Excludes smaller curves from `ECC_Parameters` and `TPM_CAP_ECC_CURVES` |
| `NO_AES` | not defined | Excludes `EncryptDecrypt`, `EncryptDecrypt2`, AES parameter encryption |
| `WOLFSSL_SHA384` | defined | Enables SHA-384 PCR bank |

When an algorithm is disabled, commands that exclusively use that algorithm are removed from the dispatch table at compile time. Commands that support multiple algorithms (for example `CreatePrimary` and `Sign`) remain available but return `TPM_RC_ASYMMETRIC` for the disabled algorithm type.

### TPM Feature Group Macros

These fwTPM-specific macros disable entire groups of TPM 2.0 functionality to reduce code size on constrained targets.

| Macro | Default | Commands Excluded |
|-------|---------|-------------------|
| `FWTPM_NO_ATTESTATION` | not defined | `Quote`, `Certify`, `CertifyCreation`, `GetTime`, `NV_Certify` |
| `FWTPM_NO_NV` | not defined | `NV_DefineSpace`, `NV_UndefineSpace`, `NV_ReadPublic`, `NV_Write`, `NV_Read`, `NV_Extend`, `NV_Increment`, `NV_WriteLock`, `NV_ReadLock`, `NV_Certify`; also removes the in-memory NV index slots from `FWTPM_CTX` |
| `FWTPM_NO_POLICY` | not defined | `PolicyGetDigest`, `PolicyRestart`, `PolicyPCR`, `PolicyPassword`, `PolicyAuthValue`, `PolicyCommandCode`, `PolicyOR`, `PolicySecret`, `PolicyAuthorize`, `PolicyNV` |
| `FWTPM_NO_CREDENTIAL` | not defined | `MakeCredential`, `ActivateCredential` |
| `FWTPM_NO_DA` | not defined | `DictionaryAttackParameters`, `DictionaryAttackLockReset`, and all lockout accounting |
| `FWTPM_NO_PARAM_ENC` | not defined | Command and response parameter (XOR and AES-CFB) encryption support in sessions |
| `FWTPM_NO_KEY_MIGRATION` | not defined | `Import`, `Duplicate`, `Rewrap` |
| `FWTPM_NO_ECDH` | not defined | `ECDH_KeyGen`, `ECDH_ZGen`, `EC_Ephemeral`, `ZGen_2Phase`, `ECC_Parameters` (ECDSA sign and verify retained), plus the `ecEphemeral*` commit state in `FWTPM_CTX` |
| `FWTPM_NO_HASH_CMDS` | not defined | `Hash`, `HMAC`, `HMAC_Start`, `HashSequenceStart`, `SequenceUpdate`, `SequenceComplete`, `EventSequenceComplete`, and the `FWTPM_CTX` hash-sequence slots |
| `FWTPM_NO_CONTEXT` | not defined | `ContextSave`, `ContextLoad` (`FlushContext` retained), plus the per-boot context protection key and saved-context replay list in `FWTPM_CTX` |
| `FWTPM_NO_SYM_ENCRYPT` | not defined | `EncryptDecrypt`, `EncryptDecrypt2` |
| `FWTPM_NO_CLOCK` | not defined | `ReadClock`, `ClockSet`, `ClockRateAdjust` |

Removing a command group also removes it from the `TPM2_GetCapability(TPM_CAP_COMMANDS)` advertisement and the `TPM_PT_TOTAL_COMMANDS` count, since both are derived from the dispatch table. When `WOLFTPM_MLDSA` is built, `SequenceUpdate` alone is retained under `FWTPM_NO_HASH_CMDS`, because ML-DSA verify sequences stream their message through it. `SequenceComplete` is not shared (ML-DSA sequences finalize through `TPM2_SignSequenceComplete` and `TPM2_VerifySequenceComplete`), so it is gated out with the rest of the hash commands rather than advertised as a command that can never succeed.

The `FWTPM_DA_USED_RETRY` macro (off by default) does not remove commands. It makes the server return `TPM_RC_RETRY` on the first DA-protected auth use after startup, emulating a real TPM persisting `daUsed`. See Dictionary Attack Protection in the [Overview](overview.md).

**Minimal build example.** There is no umbrella macro. Select the command groups to drop explicitly, so each is a deliberate choice. For example, to build a small ECC-only signing and NV fTPM (this set drops attestation and keeps `Sign`, `VerifySignature`, PCR, and NV):

```sh
./configure --enable-fwtpm --enable-swtpm \
    CFLAGS="-DNO_RSA \
        -DFWTPM_NO_POLICY -DFWTPM_NO_ATTESTATION -DFWTPM_NO_CREDENTIAL \
        -DFWTPM_NO_DA -DFWTPM_NO_PARAM_ENC -DFWTPM_NO_KEY_MIGRATION \
        -DFWTPM_NO_ECDH -DFWTPM_NO_HASH_CMDS -DFWTPM_NO_CONTEXT \
        -DFWTPM_NO_SYM_ENCRYPT -DFWTPM_NO_CLOCK"
```

That set retains a core fTPM: `Startup`, `Shutdown`, `SelfTest`, `GetRandom`, `GetCapability`, the `PCR_*` commands, `Create`, `CreatePrimary`, `Load`, `ReadPublic`, `FlushContext`, `Sign`, `VerifySignature`, the `NV_*` commands, and session support (`StartAuthSession` and `Unseal`). Add `-DFWTPM_NO_NV` to also drop NV, or drop any `-DFWTPM_NO_*` above to keep that group. This ECC-only build is small enough to run as a soft-core fTPM on a constrained FPGA (see the MicroBlaze V example in the `wolftpm-examples` repository, which fits an ECC-only fTPM into about 192 KB of on-chip memory).

**Dependencies:**

- `FWTPM_NO_NV` also removes `NV_Certify`, even if `FWTPM_NO_ATTESTATION` is not set.
- `NO_RSA` implies no RSA attestation signatures. ECC-only attestation still works with `HAVE_ECC`.

## See Also

- [Overview](overview.md)
- [Usage](usage.md)
- [HAL and Porting](hal-and-porting.md)
- [Post-Quantum Support](post-quantum.md)
- [SPDM Responder](spdm.md)
