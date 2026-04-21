# wolfTPM TPM 2.0 v1.85 Post-Quantum Examples

Examples exercising the ML-DSA / ML-KEM post-quantum additions from the
TCG TPM 2.0 Library Specification v1.85, wrapped by `wolfTPM2_*` high-
level API calls.

## Building

```
./configure --enable-swtpm --enable-v185
make
```

The `--enable-swtpm` flag points the client library at an mssim socket
transport (default `127.0.0.1:2321`). The `--enable-v185` flag compiles
in the PQC wrappers and handlers.

## `pqc_mssim_e2e`

End-to-end client test that talks to a running `fwtpm_server` over the
mssim socket. Two round-trips in one binary:

1. **MLKEM-768 Encap/Decap** — `CreatePrimary` → `Encapsulate` →
   `Decapsulate`; asserts ciphertext is 1088 bytes and the two derived
   shared secrets are byte-identical.
2. **HashMLDSA-65 SignDigest/Verify** — `CreatePrimary` (SHA-256 pre-hash)
   → `SignDigest` over a 32-byte digest → `VerifyDigestSignature`;
   asserts the signature is 3309 bytes and the validation ticket tag is
   `TPM_ST_DIGEST_VERIFIED`.

Run manually:

```
./src/fwtpm/fwtpm_server --clear &
./examples/pqc/pqc_mssim_e2e
kill %1
```

Or use the automated harness which also starts and stops the server:

```
./tests/pqc_mssim_e2e.sh
```

## Purpose

The in-process `fwtpm_unit.test` suite exercises every PQC handler via
`FWTPM_ProcessCommand` inside a single binary. This example is the
orthogonal test: it proves that client marshaling + mssim framing +
`fwtpm_server` unmarshaling + PQC handler dispatch all agree **over a
real TCP socket** between two separately-compiled processes.

Any wire-format bug that happens to cancel itself between same-process
marshal/unmarshal would fail here.
