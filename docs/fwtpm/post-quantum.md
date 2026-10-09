# fwTPM Post-Quantum Support (TPM 2.0 v1.85)

The fwTPM implements the post-quantum additions from TCG TPM 2.0 Library Specification v1.85, using wolfCrypt's FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) modules. This brings post-quantum keys, signing, and key encapsulation to platforms that have no TPM silicon. These v1.85 commands raise the implemented count from 103 to 111 commands. For the library-wide post-quantum view, see [Post-Quantum](../post-quantum.md).

Enable it with `--enable-pqc`, which the fwTPM build promotes to the full `--enable-v185`, at configure time. It is also auto-detected when `--enable-fwtpm` is built against a wolfCrypt that has both ML-DSA and ML-KEM available. Both flags set the internal `WOLFTPM_V185` macro that gates the implementation. Pass `--disable-pqc` to opt out when auto-detect would otherwise enable it.

## Algorithms

| Alg | Parameter Sets | Use |
|---|---|---|
| `TPM_ALG_MLKEM` (0x00A0) | ML-KEM-512 / 768 / 1024 | Key encapsulation (decrypt-only keys) |
| `TPM_ALG_MLDSA` (0x00A1) | ML-DSA-44 / 65 / 87 | Pure ML-DSA message signing |
| `TPM_ALG_HASH_MLDSA` (0x00A2) | HashML-DSA-44 / 65 / 87 | Pre-hashed ML-DSA signing |

## Commands

The eight v1.85 PQC commands live in `src/fwtpm/fwtpm_command.c`:

| Command | CC | Purpose |
|---|---|---|
| `TPM2_Encapsulate` | `0x000001A7` | ML-KEM encapsulation, returns sharedSecret and ciphertext |
| `TPM2_Decapsulate` | `0x000001A8` | ML-KEM decapsulation from ciphertext (requires USER auth) |
| `TPM2_SignSequenceStart` | `0x000001AA` | Begin ML-DSA sign sequence |
| `TPM2_SignSequenceComplete` | `0x000001A4` | Finalize sign sequence with message buffer |
| `TPM2_VerifySequenceStart` | `0x000001A9` | Begin ML-DSA verify sequence |
| `TPM2_VerifySequenceComplete` | `0x000001A3` | Finalize verify sequence, returns TPMT_TK_VERIFIED |
| `TPM2_SignDigest` | `0x000001A6` | One-shot digest sign (HashML-DSA or ext-mu ML-DSA) |
| `TPM2_VerifyDigestSignature` | `0x000001A5` | Verify digest signature |

## Primary Key Derivation

PQC primary keys follow the same deterministic derivation model as RSA and ECC: hierarchy seed and template, then a KDFa-derived seed, then FIPS 203 or FIPS 204 key expansion.

- **ML-DSA:** `KDFa(nameAlg, seed, "MLDSA", hashUnique)` gives a 32-byte Xi. `wc_MlDsaKey_MakeKeyFromSeed` turns that into the public key and the expanded private key. The wire format stores only the 32-byte Xi per TCG Part 2 Table 210.
- **HashML-DSA:** the label is `"HASH_MLDSA"`, with the same seed size and expansion.
- **ML-KEM:** `KDFa(nameAlg, seed, "MLKEM", hashUnique)` gives a 64-byte value (d followed by z). `wc_MlKemKey_MakeKeyWithRandom` turns that into the encapsulation and decapsulation keys. The wire format stores only the 64-byte seed per TCG Part 2 Table 206.

!!! note
    These label strings are an interpretation. TCG Part 4 v185, which would specify them normatively, is unpublished. They are subject to change if a later release candidate or Part 4 v185 prescribes different labels.

## Sign and Verify Sequences

Pure ML-DSA sequences are streamable on both sign and verify, so `TPM2_SequenceUpdate` is accepted. `TPM_RC_ONE_SHOT_SIGNATURE` applies to multi-pass schemes such as EdDSA, not to pure ML-DSA. A caller can also pass the whole message through the `buffer` parameter of `TPM2_SignSequenceComplete`. Verify sequences accumulate the message through `TPM2_SequenceUpdate`, because `TPM2_VerifySequenceComplete` has no buffer parameter.

HashML-DSA sequences (both sign and verify) use wolfCrypt's `wc_HashAlg` context to stream the message into the key's hash algorithm. `TPM2_SignSequenceComplete` finalizes the hash and calls `wc_MlDsaKey_SignCtxHash`.

Signature wire formats differ per spec Part 2 Table 217:

- **Pure ML-DSA:** `TPM2B_SIGNATURE_MLDSA`, laid out as `sigAlg + size + bytes`
- **HashML-DSA:** `TPMS_SIGNATURE_HASH_MLDSA`, laid out as `sigAlg + hashAlg + size + bytes`

## Buffer Constants

Under `WOLFTPM_V185`, buffers are lifted to fit ML-DSA-87 signatures (4627 bytes) and public keys (2592 bytes):

| Symbol | v1.38 | v1.85 |
|---|---|---|
| `FWTPM_MAX_COMMAND_SIZE` | 4096 | 8192 |
| `FWTPM_MAX_PUB_BUF` | 512 | 2720 |
| `FWTPM_MAX_DER_SIG_BUF` | 256 | 4736 |
| `FWTPM_MAX_KEM_CT_BUF` | n/a | 1600 |
| `FWTPM_TIS_FIFO_SIZE` | 4096 | 8192 |
| `FWTPM_NV_PUBAREA_EST` | 600 | 2720 |

These are the worst-case values. The defaults shrink at compile time to match the parameter sets wolfCrypt was built with. See "v1.85 Embedded RAM Impact" in [Building](building.md) for the per-parameter-set table.

## Limitations and Scope

The v1.85 commands are implemented for post-quantum keys only. Non-PQC key types are rejected with `TPM_RC_KEY` or `TPM_RC_SCHEME`, even when the v1.85 spec defines the commands generically:

- `TPM2_Encapsulate` and `TPM2_Decapsulate`: ML-KEM only. ECC DHKEM (the Table 100 `ecdh` arm with a non-NULL KDF) is not implemented.
- `TPM2_SignSequenceStart`, `TPM2_VerifySequenceStart`, `TPM2_SignSequenceComplete`, and `TPM2_VerifySequenceComplete`: ML-DSA and HashML-DSA only. Classical schemes (RSASSA, RSAPSS, ECDSA, SM2, ECSCHNORR, HMAC) that the spec also permits through these commands are not supported.
- `TPM2_SignDigest` and `TPM2_VerifyDigestSignature`: ML-DSA and HashML-DSA only. Classical digest signing (RSASSA, RSAPSS, ECDSA) over these new commands is not supported. Use the existing `TPM2_Sign` and `TPM2_VerifySignature` commands for those schemes.

## Deferred and Out of Scope

Three v1.85 features are deferred, each for a documented reason:

1. **ML-KEM-salted sessions.** Part 3 Sec.11.1 (`TPM2_StartAuthSession`) does not describe an ML-KEM bullet alongside the RSA-OAEP and ECDH paths, even though Part 2 Sec.11.4.2 Table 222 defines the `mlkem` arm of `TPMU_ENCRYPTED_SECRET`. Part 4 v185, which would specify this normatively, is not yet published. Current behavior: `TPM2_StartAuthSession` returns `TPM_RC_KEY` for an ML-KEM tpmKey. Revisit when Part 4 v185 is published.
2. **External-mu ML-DSA signing.** wolfCrypt has no mu-direct sign API. Part 2 Sec.12.2.3.7 says "512-byte external Mu", but FIPS 204 Algorithm 7 Line 6 produces 64 bytes (SHAKE256 output). This is pending a wolfCrypt API addition and TCG errata confirmation. Current behavior: `TPM_RC_SCHEME` for ext-mu paths, and `TPM_RC_EXT_MU` for Pure ML-DSA keys without `allowExternalMu`.
3. **ECC KEM arm of Encapsulate and Decapsulate.** Part 2 Sec.10.3.13 Table 100 has both `mlkem` and `ecdh` arms, but the table note allows implementations to modify the union based on the algorithms they support. The fwTPM supports the `mlkem` arm only.

## Test Coverage

`tests/fwtpm_unit_tests.c` includes ten PQC tests that exercise the full path:

- CreatePrimary for ML-KEM-768 and ML-DSA-65
- Full Encapsulate and Decapsulate round-trip (shared secret byte match)
- HashML-DSA SignDigest and VerifyDigestSignature round-trip
- Pure ML-DSA sign sequence and verify sequence round-trip
- Dual-source known-answer tests (NIST ACVP and wolfSSL internal vectors) for ML-DSA-44 verify, ML-DSA-44 keygen determinism, ML-KEM-512 encapsulation with pinned randomness, and ML-KEM-512 keygen determinism
- LoadExternal of a NIST ACVP ML-DSA-44 public key through the fwTPM handler

## See Also

- [Overview](overview.md)
- [Building](building.md)
- [Usage](usage.md)
- [SPDM Responder](spdm.md)
- [Post-Quantum (library-wide)](../post-quantum.md)
