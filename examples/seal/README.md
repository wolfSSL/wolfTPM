# wolfTPM Seal/Unseal Examples

This directory contains examples demonstrating TPM 2.0 seal/unseal operations
with different authorization policies, listed from simplest to most flexible.

## Examples

### seal / unseal (Password Policy)

The simplest seal/unseal using a password-based authorization policy.

```sh
./examples/seal/seal keyblob.bin mySecretData
./examples/seal/unseal output.bin keyblob.bin
```

### seal_pcr (PCR-Only Policy)

Seals a secret bound to specific PCR values. The secret can only be unsealed
when the PCR values match what was measured at seal time. No password or
signing key required.

**Use case:** Static Root of Trust — bind secrets to a specific boot state.

```sh
# Seal and unseal in one step
./examples/seal/seal_pcr -both -pcr=16 -secretstr="MySecret"

# Separate seal/unseal (e.g., seal on first boot, unseal on subsequent boots)
./examples/seal/seal_pcr -seal -pcr=16 -secretstr="MySecret"
./examples/seal/seal_pcr -unseal -pcr=16

# With parameter encryption
./examples/seal/seal_pcr -both -pcr=16 -xor -secretstr="MySecret"
./examples/seal/seal_pcr -both -pcr=16 -aes -secretstr="MySecret"

# Custom sealed blob filename
./examples/seal/seal_pcr -seal -sealblob=myblob.bin -secretstr="MySecret"
./examples/seal/seal_pcr -unseal -sealblob=myblob.bin
```

### seal_policy_auth (PolicyAuthorize + PCR)

Seals a secret using PolicyAuthorize with a TPM-resident signing key and PCR
policy. The signing key can re-authorize the policy for new PCR values,
allowing secrets to survive authorized changes (e.g., OS updates).

**Use case:** Flexible measured boot with authorized policy updates.

**Note:** `authkey.bin` and `sealblob.bin` must be kept together. If the
signing key is regenerated, the sealed blob becomes un-unsealable.

```sh
# ECC signing key (default)
./examples/seal/seal_policy_auth -both -ecc -pcr=16 -secretstr="MySecret"

# RSA signing key
./examples/seal/seal_policy_auth -both -rsa -pcr=16 -secretstr="MySecret"

# Separate seal/unseal
./examples/seal/seal_policy_auth -seal -ecc -pcr=16 -secretstr="MySecret"
./examples/seal/seal_policy_auth -unseal -ecc -pcr=16

# With parameter encryption
./examples/seal/seal_policy_auth -both -ecc -pcr=16 -xor -secretstr="MySecret"
./examples/seal/seal_policy_auth -both -rsa -pcr=16 -aes -secretstr="MySecret"
```

### seal_nv (NV Storage + PCR Policy)

Stores a secret in TPM NV (non-volatile) memory protected by a PCR policy.
Unlike file-based sealed blobs, the secret lives entirely inside the TPM.
Located at `examples/nvram/seal_nv`.

**Use case:** Secrets that must persist in TPM hardware without external files.

```sh
# Store, read, delete lifecycle
./examples/nvram/seal_nv -store -pcr=16 -secretstr="MySecret"
./examples/nvram/seal_nv -read -pcr=16
./examples/nvram/seal_nv -delete

# Custom NV index
./examples/nvram/seal_nv -store -pcr=16 -nvindex=0x01800204 -secretstr="MySecret"
./examples/nvram/seal_nv -read -pcr=16 -nvindex=0x01800204
./examples/nvram/seal_nv -delete -nvindex=0x01800204
```

## Testing

### Standalone Test Script

`seal_test.sh` runs 28 tests across all three seal example groups:

```sh
bash examples/seal/seal_test.sh
```

Tests include positive cases (seal/unseal lifecycle, secret verification),
negative cases (PCR mismatch, missing auth key), parameter encryption variants
(XOR, AES), and custom filenames/NV indices.

Output uses colored PASS/FAIL/SKIP with a summary. Verbose output is saved
to `seal_test.log`.

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WOLFCRYPT_ENABLE` | 1 | wolfCrypt support compiled in |
| `WOLFCRYPT_DEFAULT` | 0 | Using default (reduced) wolfCrypt config |
| `WOLFCRYPT_ECC` | 1 | ECC support available |
| `WOLFCRYPT_RSA` | 1 | RSA support available |

### Integration Tests

The seal examples are also tested as part of `examples/run_examples.sh`
which runs during `make check`.

## Policy Comparison

| Feature | seal (password) | seal_pcr | seal_policy_auth | seal_nv |
|---------|----------------|----------|-----------------|---------|
| Authorization | Password | PCR values | Signing key + PCR | PCR values |
| Complexity | Low | Low | High | Medium |
| Survives PCR change | N/A | No | Yes (with auth key) | No |
| Storage | File | File | File (blob + key) | TPM NV |
| Parameter Encryption | Yes | Yes | Yes | Yes |
