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
./configure --enable-wolftpm --enable-mldsa --enable-mlkem \
            --enable-harden --enable-keygen --enable-certgen
make
sudo make install
```

`--enable-certgen` is needed by the TLS `gen_pqc_certs` tool below;
`--enable-wolftpm` provides the crypto callback and private-key-id support the
TLS server uses.

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

### PQC keys for parameter encryption

A post-quantum primary can key a TPM 2.0 parameter-encryption session:
ML-KEM (decrypt capable) is used as the session salt key and ML-DSA
(sign only) as the session bind key. The session protects the command's
first sized parameter the same way an RSA/ECC salted session does. Any
RSA/ECC storage key the example needs (for example the parent of a
created child) is unchanged.

Note on ML-DSA confidentiality: parameter-encryption confidentiality comes
from the session key, which a bound session derives from the bind entity's
authValue (TPM 2.0 Library Part 1, Salted Session). A sign-only ML-DSA key
cannot exchange a salt, and the example's bind authValue is a public
constant, so an ML-DSA bind alone provides session binding but no
confidentiality against a bus observer. To keep the advertised encryption
real, the helper additionally creates a transient SRK and uses it as the
asymmetric salt for the ML-DSA session: confidentiality comes from the
encrypted salt while the ML-DSA key supplies the binding. A real deployment
that relies on a bare bound session for confidentiality must use a bind
entity whose authValue is secret and was not sent in cleartext.

`wrap_test`, `pcr/quote`, and `nvram/store` and `nvram/counter` take
`-mlkem[=512|768|1024]` and `-mldsa[=44|65|87]`. `keygen` uses
`-paramkey=mlkem[=...]` / `-paramkey=mldsa[=...]` because its `-mlkem` /
`-mldsa` already select the child key algorithm.

```
./examples/wrap/wrap_test -aes -mlkem=768
./examples/pcr/quote 16 quote.blob -ecc -xor -mldsa=65
./examples/nvram/counter -aes -mldsa=65
./examples/keygen/keygen keyblob.bin -ecc -aes -paramkey=mlkem=768
```

ML-KEM is a restricted decryption (salt) key, which requires a symmetric
definition; the example helper sets AES-128-CFB on it (a TPM rejects a
restricted key with no symmetric algorithm via `TPM_RC_SYMMETRIC`).

### `create_primary` ML-DSA primary

`examples/keygen/create_primary` can create an ML-DSA primary key:

```
./examples/keygen/create_primary -mldsa            # default MLDSA-65
./examples/keygen/create_primary -mldsa=87 -oh
```

## Post-Quantum TLS 1.3 (ML-KEM + TPM ML-DSA)

A full TLS 1.3 handshake where the server's ML-DSA identity key lives in the
TPM. The server signs the CertificateVerify on-chip via the wolfTPM crypto
callback; the client performs an ML-KEM key exchange and validates the server
against a software CA.

Requires wolfSSL with a fix that routes `wc_MlDsaKey_SignCtx` to the crypto
callback for device keys (private key in the TPM). No shipping TPM implements
TCG v1.85 PQC yet, so this runs against the in-tree fwTPM.

Demo scope: the identity key is an unauthenticated deterministic TPM primary
(empty auth), reproducible by both `gen_pqc_certs` and the server from the owner
hierarchy. A production deployment should protect the identity key with a
non-empty auth value or policy so it cannot be recreated from the public cert.
The client validates the server chain against the demo CA but does not bind the
certificate to the host name; a production client should also issue the leaf with
a matching subjectAltName and call `wolfSSL_check_domain_name` before connecting.

Three programs:
- `examples/pqc/gen_pqc_certs` — makes a software ML-DSA CA and a device leaf
  cert whose subject key is the TPM ML-DSA key.
- `examples/tls/tls_server_pq` — recreates that TPM key and serves TLS 1.3.
- `examples/tls/tls_client_pq` — connects, ML-KEM key exchange, verifies the CA.

```
./src/fwtpm/fwtpm_server --clear &

# 1. certificate chain bound to the TPM key (-mldsa must match the server)
./examples/pqc/gen_pqc_certs -mldsa=65

# 2. server (same -mldsa as gen_pqc_certs)
./examples/tls/tls_server_pq -p=11111 -mldsa=65 &

# 3. client (choose the ML-KEM group)
./examples/tls/tls_client_pq -h=localhost -p=11111 -group=ML_KEM_768
```

Options:
- `gen_pqc_certs -mldsa=44/65/87` — ML-DSA parameter set.
- `tls_server_pq -p=<port> -mldsa=44/65/87`.
- `tls_client_pq -h=<host> -p=<port> -group=<name>` where `<name>` is
  `ML_KEM_512/768/1024` or a hybrid `SECP256R1MLKEM768` / `X25519MLKEM768`
  (hybrids need the matching classical curve enabled in wolfSSL).

The one-shot end-to-end test drives all three and asserts the ML-KEM group,
TPM-signed ML-DSA authentication, CA verification, and app data:

```
./tests/tls_pq_e2e.sh                    # ML_KEM_768 + ML-DSA-65
./tests/tls_pq_e2e.sh SECP256R1MLKEM768 87
```
