# Post-Quantum Cryptography

wolfTPM implements the post-quantum algorithms added in TCG TPM 2.0 Library Specification v1.85, built on wolfCrypt's FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) modules. This page covers the supported algorithms, how to build with them, and the PQC examples shipped in `examples/pqc`.

## Overview

Supported algorithms:

| Algorithm | Standard | Parameter sets |
|---|---|---|
| ML-DSA (signing) | FIPS 204 | ML-DSA-44 / 65 / 87 |
| HashML-DSA (pre-hash signing) | FIPS 204 | ML-DSA-44 / 65 / 87 with caller hash |
| ML-KEM (key encapsulation) | FIPS 203 | ML-KEM-512 / 768 / 1024 |

wolfTPM supports the SEALSQ QVault TPM, which SEALSQ positions as the first TPM 2.0 device with these v1.85 PQC algorithms in silicon. SEALSQ describes QVault TPM-185 engineering samples as available, so check with SEALSQ for current production and certification status. The same PQC API also runs against the in-tree fwTPM server, which is useful for CI or when no hardware is present. For measured ML-DSA and ML-KEM performance on QVault TPM silicon, see the Benchmarks section at the end of this page.

## Building

### wolfSSL

wolfSSL provides ML-DSA and ML-KEM in wolfCrypt:

```sh
./configure --enable-wolftpm --enable-pkcallbacks --enable-keygen \
            --enable-mldsa --enable-mlkem \
            --enable-harden CFLAGS="-DWC_RSA_NO_PADDING"
make
sudo make install
```

For the PQC TLS 1.3 demo described below, also add `--enable-tls-mlkem-standalone`. The standalone option is required for the standalone `ML_KEM_*` TLS groups; without it wolfSSL only offers the hybrid groups and `wolfSSL_UseKeyShare` rejects the client default. The `gen_pqc_certs` tool needs certificate generation, which `--enable-wolftpm` already enables, and `--enable-wolftpm` also provides the crypto callback and private-key-id support the TLS server uses. Keep `--enable-pkcallbacks`, which is a separate wolfSSL option. The demo needs wolfSSL 5.9.4-stable or later.

### fwTPM (software TPM)

```sh
./configure --enable-fwtpm --enable-pqc
make
```

The fwTPM server uses the full v1.85 command set, so configure promotes `--enable-pqc` to `--enable-v185`. If you omit both flags and wolfCrypt has ML-DSA and ML-KEM, configure auto-enables v1.85. Pass `--disable-pqc` to opt out explicitly.

### Hardware TPM: SEALSQ QVault

SEALSQ QVault is the hardware TPM currently supported for v1.85 PQC:

```sh
./configure --enable-sealsq --enable-pqc
make
```

On Linux, add `--enable-devtpm` to use the kernel TPM driver. For examples that pass transient handles between processes, also add `CFLAGS='-DTPM2_LINUX_DEV="/dev/tpm0"'`. The default `/dev/tpmrm0` virtualizes and discards those handles when a process closes the device. Keep the inner double quotes literal inside the single-quoted `CFLAGS` value.

`--enable-pqc` builds the lean ML-DSA and ML-KEM subset (`WOLFTPM_PQC`) for hardware. Use `--enable-v185` (`WOLFTPM_V185`) for the full v1.85 command set.

Non-SHA-1 TPM examples include:

```sh
./examples/pqc/pqc_ctrl --caps --algs
./examples/pqc/pqc_ctrl --mldsa=65 --mlkem=768
./examples/wrap/hash "wolfTPM" -sha256
```

### Trimming the PQC footprint

To compile only the operations you call (smaller binary and smaller buffer maximums), mirror the wolfSSL flags:

```sh
# ML-DSA verify-only + ML-KEM encapsulate-only (no sign, no decapsulate)
./configure --enable-pqc --enable-mldsa=verify-only --enable-mlkem=enc
```

| Flag | Values | Drops |
|------|--------|-------|
| `--enable-mldsa` | `all` (default) / `sign-only` / `verify-only` / `no` | the unselected ML-DSA operation |
| `--enable-mlkem` | `all` (default) / `enc` / `dec` / `no` | the unselected ML-KEM operation |
| `--disable-hash-mldsa` | none | pre-hash ML-DSA key support |

These map to `WOLFTPM_NO_MLDSA_SIGN`, `WOLFTPM_NO_MLKEM_DECAP`, and similar defines, which embedded integrators can also pass directly via `CFLAGS` without autotools. Existing `--enable-v185` builds are unaffected (every operation defaults on). Disabling both algorithms (`--enable-mldsa=no --enable-mlkem=no`) is a configure error. Use `--disable-pqc` to build without any post-quantum support.

The same flags also trim the fwTPM server: `--enable-fwtpm --enable-mldsa=verify-only` compiles out the ML-DSA sign command handlers, dispatch entries, and crypto. ML-KEM is controlled separately and stays at its default of `all`, so to build a server whose PQC surface is only ML-DSA verify, also pass `--enable-mlkem=no`. fwTPM always builds the full v1.85 spec surface, so the trims apply on top of `WOLFTPM_V185`.

!!! note
    Trimming does not make the examples allocation-free; they still allocate signature and ciphertext buffers with `XMALLOC`. fwTPM has a separate `WOLFTPM2_NO_HEAP` option that moves all buffers to the stack, at the cost of much larger stack use. See [fwTPM Building](fwtpm/building.md) for details.

## Running the examples

```sh
make check
```

With the fwTPM build above, `make check` runs the software-TPM suite, including PQC coverage:

- `tests/fwtpm_unit.test`: 30+ in-process PQC handler tests
- `tests/fwtpm_check.sh`: starts the server, then runs `tests/unit.test` (PQC wrapper tests over the mssim socket such as ML-DSA Sign/Verify Sequence, ML-KEM Encap/Decap, and EncryptSecret ML-KEM), `examples/run_examples.sh`, and the tpm2-tools suite
- `tests/fwtpm_da_retry.sh`: dictionary attack retry check (needs a build with `-DFWTPM_DA_USED_RETRY`)

`make check` does not run `tests/pqc_mssim_e2e.sh`. Run that script directly for a fast, PQC-focused end-to-end check:

```sh
./tests/pqc_mssim_e2e.sh
```

With an fwTPM build, start `fwtpm_server` on `127.0.0.1:2321` before running the individual examples below. A SEALSQ build uses its configured hardware transport.

```sh
./src/fwtpm/fwtpm_server --clear &
```

For the fwTPM server's PQC internals (the eight v1.85 commands, primary-key derivation, buffer constants, and spec-interpretation decisions), see [docs/FWTPM.md](fwtpm/overview.md).

## Examples

### pqc_ctrl

`pqc_ctrl` is a single CLI to drive and validate a PQC TPM (SEALSQ QVault TPM, or the fwTPM). Each command runs an operation against the TPM. Every key operation flushes the transient object table first, so a TPM with a small object memory (such as the SEALSQ QVault TPM) does not hit `TPM_RC_OBJECT_MEMORY` when commands are chained.

```sh
./examples/pqc/pqc_ctrl                 # --all (default)
./examples/pqc/pqc_ctrl --caps --algs   # identify + list supported algorithms
./examples/pqc/pqc_ctrl --mldsa=87      # ML-DSA-87 sign/verify
./examples/pqc/pqc_ctrl --mlkem=1024    # ML-KEM-1024 encap/decap
./examples/pqc/pqc_ctrl --selftest --getrandom=32 --pcrread=0
```

| Command | Description |
|---|---|
| `--caps` | Manufacturer, vendor string, firmware, FIPS mode |
| `--algs` | List the algorithms the TPM reports as supported |
| `--selftest` | `TPM2_SelfTest` |
| `--getrandom[=N]` | N random bytes (default 16) |
| `--pcrread[=idx]` | Read a PCR (SHA-256 bank, falling back to SHA-384) |
| `--pcrextend=idx` | Extend a PCR with a test digest (explicit index required) |
| `--flush` | Flush all loaded transient objects between operations |
| `--clear` | `TPM2_Clear`, wipes the owner hierarchy |
| `--mldsa[=44/65/87]` | Pure ML-DSA sign/verify (default 65) |
| `--hash-mldsa[=44/65/87]` | HashML-DSA (SHA-256 pre-hash) sign/verify |
| `--mlkem[=512/768/1024]` | ML-KEM encapsulate/decapsulate |
| `--all` | caps + algs + selftest + getrandom + pcrread + every PQC set |

Commands run left to right, so they can be chained. `pqc_ctrl` requires `--enable-v185` (or `--enable-pqc`). Point it at the SEALSQ part with `--enable-sealsq`, or at the fwTPM with `--enable-fwtpm --enable-swtpm`.

`pqc_ctrl.sh` runs the whole command set as a pass/fail suite (it mirrors `examples/spdm/spdm_test.sh`) when the device supports all parameter sets. The state-changing steps are opt-in via `PQC_CTRL_CLEAR=1` so the suite never changes a TPM unexpectedly:

```sh
./examples/pqc/pqc_ctrl.sh
PQC_CTRL_CLEAR=1 ./examples/pqc/pqc_ctrl.sh   # also extend PCR 16 and run TPM2_Clear
```

!!! warning
    `PQC_CTRL_CLEAR=1` does two things, not one. It first extends PCR 16, which cannot be undone without resetting the PCR, and then runs `TPM2_Clear`, which wipes the owner hierarchy. Use it only on a disposable test TPM, or on a device whose state you have backed up.

### pqc_mssim_e2e

End-to-end client test over the mssim socket. It runs four checks in sequence:

1. ML-KEM-768 `CreatePrimary`, `Encapsulate`, and `Decapsulate`. It asserts the ciphertext is 1088 bytes and the two shared secrets are byte-identical.
2. HashML-DSA-65 (SHA-256) `CreatePrimary`, `SignDigest`, and `VerifyDigestSignature`. It asserts the signature is 3309 bytes and the validation ticket tag is `TPM_ST_DIGEST_VERIFIED`.
3. An ML-KEM `MakeCredential` and `ActivateCredential` round-trip.
4. An ML-DSA `Quote`.

```sh
./examples/pqc/pqc_mssim_e2e
```

### mlkem_encap

ML-KEM encapsulation round-trip. It creates a primary ML-KEM key, runs `Encapsulate`, then runs `Decapsulate` on the produced ciphertext and confirms the shared secrets match.

```sh
./examples/pqc/mlkem_encap                # default: ML-KEM-768
./examples/pqc/mlkem_encap -mlkem=512
./examples/pqc/mlkem_encap -mlkem=1024
```

### mldsa_sign

Pure ML-DSA sign and verify round-trip. It creates a primary ML-DSA key and signs a fixed message via `SignSequenceStart` and `SignSequenceComplete`. Pure ML-DSA sequences are streamable, so the message could also be fed through `SequenceUpdate`; this example passes it whole on the Complete buffer for signing. It then verifies via `VerifySequenceStart`, `VerifySequenceUpdate`, and `VerifySequenceComplete`. It asserts the returned validation ticket tag is `TPM_ST_MESSAGE_VERIFIED`.

```sh
./examples/pqc/mldsa_sign                 # default: ML-DSA-65
./examples/pqc/mldsa_sign -mldsa=44
./examples/pqc/mldsa_sign -mldsa=87
```

### PQC keys via keygen and keyload

`examples/keygen/keygen` accepts v1.85 PQC options alongside `-rsa`, `-ecc`, `-sym`, and `-keyedhash`:

```sh
./examples/keygen/keygen keyblob.bin -mldsa=65           # Pure ML-DSA
./examples/keygen/keygen keyblob.bin -hash_mldsa=65      # SHA-256 pre-hash
./examples/keygen/keygen keyblob.bin -mlkem=768          # ML-KEM
```

Parameter sets:

- `-mldsa=44|65|87` (default 65)
- `-hash_mldsa=44|65|87` (default 65, SHA-256 pre-hash)
- `-mlkem=512|768|1024` (default 768)

Verify that the produced blob round-trips through `TPM2_Create` and `TPM2_Load` by loading it back:

```sh
./examples/keygen/keyload keyblob.bin
```

A successful load prints a transient key handle. The full matrix (three variants times three parameter sets, nine key configurations, each run through keygen and keyload) is exercised by `examples/run_examples.sh` when v1.85 is detected in `config.h`. That generic suite also covers non-PQC operations with their own TPM requirements.

### PQC keys for parameter encryption

A post-quantum primary can key a TPM 2.0 parameter-encryption session. ML-KEM (decrypt capable) is used as the session salt key and ML-DSA (sign only) as the session bind key. The session protects the command's first sized parameter the same way an RSA or ECC salted session does. Any RSA or ECC storage key the example needs (for example the parent of a created child) is unchanged.

!!! note
    Parameter-encryption confidentiality comes from the session key, which a bound session derives from the bind entity's authValue (TPM 2.0 Library Part 1, Salted Session). A sign-only ML-DSA key cannot exchange a salt, and the example's bind authValue is a public constant, so an ML-DSA bind alone provides session binding but no confidentiality against a bus observer. To keep the advertised encryption real, the helper also creates a transient SRK and uses it as the asymmetric salt for the ML-DSA session: confidentiality comes from the encrypted salt while the ML-DSA key supplies the binding. A real deployment that relies on a bare bound session for confidentiality must use a bind entity whose authValue is secret and was not sent in cleartext.

`wrap_test`, `pcr/quote`, `nvram/store`, and `nvram/counter` take `-mlkem[=512|768|1024]` and `-mldsa[=44|65|87]`. `keygen` uses `-paramkey=mlkem[=...]` and `-paramkey=mldsa[=...]` because its `-mlkem` and `-mldsa` options already select the child key algorithm.

```sh
./examples/wrap/wrap_test -aes -mlkem=768
./examples/pcr/quote 16 quote.blob -ecc -xor -mldsa=65
./examples/nvram/counter -aes -mldsa=65
./examples/keygen/keygen keyblob.bin -ecc -aes -paramkey=mlkem=768
```

ML-KEM is a restricted decryption (salt) key, which requires a symmetric definition. The example helper sets AES-128-CFB on it, because a TPM rejects a restricted key with no symmetric algorithm via `TPM_RC_SYMMETRIC`.

### create_primary with an ML-DSA primary

`examples/keygen/create_primary` can create an ML-DSA primary key:

```sh
./examples/keygen/create_primary -mldsa            # default ML-DSA-65
./examples/keygen/create_primary -mldsa=87 -oh
```

### Post-Quantum TLS 1.3 (ML-KEM and TPM ML-DSA)

This is a full TLS 1.3 handshake where the server's ML-DSA identity key lives in the TPM. The server signs the CertificateVerify on-chip via the wolfTPM crypto callback. The client performs an ML-KEM key exchange and validates the server against a software CA.

It requires a wolfSSL that routes `wc_MlDsaKey_SignCtx` to the crypto callback for device keys (private key in the TPM). That change is in wolfSSL 5.9.4-stable and later. A development snapshot must contain wolfSSL commit `6b0c832284286dbaec8e5ab35581ff470e90826b`. The commands below start the in-tree fwTPM for this demo.

!!! warning
    This is a demo. The identity key is an unauthenticated deterministic TPM primary (empty auth), reproducible by both `gen_pqc_certs` and the server from the owner hierarchy. A primary's key material is derived from the hierarchy seed and the creation inputs, and an object auth value does not change that derivation. Adding a non-empty auth value or policy alone therefore does not stop another caller who can authorize `CreatePrimary` under the owner hierarchy from recreating the same key. For production, prefer a provisioned child or persistent identity object together with controlled hierarchy authorization. The client validates the server chain against the demo CA but does not bind the certificate to the host name, so the demo connects to the default localhost and does not pass `-h=`. Supplying `-h=` turns on strict verification including `wolfSSL_check_domain_name`, which this leaf cannot satisfy. A production deployment should issue the leaf with a matching subjectAltName.

Three programs are involved:

- `examples/pqc/gen_pqc_certs` makes a software ML-DSA CA and a device leaf cert whose subject key is the TPM ML-DSA key.
- `examples/tls/tls_server -mldsa` recreates that TPM key and serves TLS 1.3.
- `examples/tls/tls_client -mldsa` connects, does the ML-KEM key exchange, and verifies the CA.

```sh
./src/fwtpm/fwtpm_server --clear &

# 1. certificate chain bound to the TPM key (-mldsa must match the server)
./examples/pqc/gen_pqc_certs -mldsa=65

# 2. server (same -mldsa as gen_pqc_certs)
./examples/tls/tls_server -p=11111 -mldsa=65 &

# 3. client (choose the ML-KEM group)
./examples/tls/tls_client -p=11111 -mldsa -group=ML_KEM_768
```

Options:

- `gen_pqc_certs -mldsa=44/65/87`: ML-DSA parameter set.
- `tls_server -p=<port> -mldsa=44/65/87`.
- `tls_client -h=<host> -p=<port> -group=<name>`, where `<name>` is `ML_KEM_512/768/1024` or a hybrid `SECP256R1MLKEM768` / `X25519MLKEM768` (hybrids need the matching classical curve enabled in wolfSSL).

The one-shot end-to-end test drives all three and asserts the ML-KEM group, TPM-signed ML-DSA authentication, CA verification, and app data:

```sh
ENABLE_PQC_TLS=1 ./examples/run_examples.sh   # includes the PQC TLS matrix
```

## Benchmarks

Measured ML-DSA and ML-KEM latencies on SEALSQ QVault TPM silicon (key generation, sign, verify, encapsulate, decapsulate), taken with `examples/bench/bench`, is in [benchmarks.md](benchmarks.md). Key generation is a one-off provisioning cost. See that page for how the ML-DSA and ECDSA figures were captured before comparing them.

## See Also

- [benchmarks.md](benchmarks.md)
- [FWTPM.md](fwtpm/overview.md)
- [DEVTPM.md](system-interfaces.md)
- [spdm.md](spdm.md)
