# wolfTPM TPM 2.0 v1.85 Post-Quantum Examples

Examples exercising the ML-DSA / ML-KEM post-quantum additions from TCG
TPM 2.0 Library Specification v1.85, wrapped by `wolfTPM2_*` API calls.

The examples run against the in-tree fwTPM server. No shipping hardware
TPM firmware implements v1.85 PQC yet. See
[docs/FWTPM.md](../../docs/FWTPM.md#tpm-20-v185-post-quantum-support) for
the full fwTPM PQC reference.

## Building

**wolfSSL** (ML-DSA and ML-KEM in wolfCrypt):

```
./configure --enable-wolftpm --enable-dilithium --enable-mlkem \
            --enable-experimental --enable-harden --enable-keygen
make
sudo make install
```

**wolfTPM**:

```
./configure --enable-fwtpm --enable-pqc
make
```

`--enable-pqc` is an alias for `--enable-v185`. If you omit both but
`--enable-fwtpm` is set and wolfCrypt has ML-DSA + ML-KEM,
configure auto-enables PQC.

## Run the test suite

```
make check
```

Runs the full suite, including all PQC coverage:
- `tests/fwtpm_unit.test` — 30+ in-process PQC handler tests
- `tests/unit.test` — PQC wrapper tests over the mssim socket
  (ML-DSA Sign/Verify Sequence, ML-KEM Encap/Decap, EncryptSecret MLKEM, etc.)
- `tests/pqc_mssim_e2e.sh` — dedicated PQC end-to-end round-trip

The individual scripts `make check` invokes are also runnable directly
for faster targeted iteration:

```
./tests/fwtpm_check.sh        # fwtpm_unit.test + unit.test + tpm2_tools suite
./tests/pqc_mssim_e2e.sh      # PQC E2E only (fastest PQC-focused check)
```

## Individual examples

All examples expect a running `fwtpm_server` on `127.0.0.1:2321`:

```
./src/fwtpm/fwtpm_server --clear &
```

### `pqc_mssim_e2e`

End-to-end client test over the mssim socket. Two round-trips:

1. MLKEM-768 `CreatePrimary` + `Encapsulate` + `Decapsulate`. Asserts
   ciphertext is 1088 bytes and the two shared secrets are byte-identical.
2. HashMLDSA-65 (SHA-256) `CreatePrimary` + `SignDigest` +
   `VerifyDigestSignature`. Asserts the signature is 3309 bytes and the
   validation ticket tag is `TPM_ST_DIGEST_VERIFIED`.

```
./examples/pqc/pqc_mssim_e2e
```

### `mlkem_encap`

ML-KEM encapsulation round-trip. Creates a primary ML-KEM key, runs
`Encapsulate`, then `Decapsulate`s the produced ciphertext and confirms
the shared secrets match.

```
./examples/pqc/mlkem_encap                # default: MLKEM-768
./examples/pqc/mlkem_encap -mlkem=512
./examples/pqc/mlkem_encap -mlkem=1024
```

### `mldsa_sign`

Pure ML-DSA sign+verify round-trip. Creates a primary ML-DSA key, signs
a fixed message via `SignSequenceStart` + `SignSequenceComplete` (Pure
ML-DSA is one-shot per Part 3 Sec.17.5, so the message rides on the
Complete buffer), then verifies via `VerifySequenceStart` +
`VerifySequenceUpdate` + `VerifySequenceComplete` (Sec.20.3 allows Update
on verify sequences). Asserts the returned validation ticket tag is
`TPM_ST_MESSAGE_VERIFIED`.

```
./examples/pqc/mldsa_sign                 # default: MLDSA-65
./examples/pqc/mldsa_sign -mldsa=44
./examples/pqc/mldsa_sign -mldsa=87
```

### PQC keys via `keygen` / `keyload`

`examples/keygen/keygen` accepts v1.85 PQC options alongside `-rsa`,
`-ecc`, `-sym`, and `-keyedhash`:

```
./examples/keygen/keygen keyblob.bin -mldsa=65           # Pure ML-DSA
./examples/keygen/keygen keyblob.bin -hash_mldsa=65      # SHA-256 pre-hash
./examples/keygen/keygen keyblob.bin -mlkem=768          # ML-KEM
```

Parameter sets:
- `-mldsa=44|65|87` (default 65)
- `-hash_mldsa=44|65|87` (default 65, SHA-256 pre-hash)
- `-mlkem=512|768|1024` (default 768)

Verify the produced blob round-trips through `TPM2_Create` + `TPM2_Load`
by loading it back:

```
./examples/keygen/keyload keyblob.bin
```

A successful load prints `Loaded key to 0x80000000`. The full 18-way
matrix (three variants x three parameter sets) is exercised by
`examples/run_examples.sh` when v1.85 is detected in `config.h`.
