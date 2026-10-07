# Sealing and NVRAM

A TPM 2.0 can act as a secure vault. This page covers sealing secrets to a key or to PCR values, storing keys and data in TPM non-volatile memory (NVRAM), and the secure boot root of trust example built on both. All examples are built with the rest of the wolfTPM examples and run from the root of the wolfTPM source tree.

## Seal and unseal overview

TPM 2.0 can protect secrets using a standard Seal/Unseal procedure. A seal can be created using a TPM 2.0 key or against a set of PCR values.

!!! note
    Secret data sealed in a key is limited to a maximum size of 128 bytes.

The simplest pair of examples is `seal/seal` and `seal/unseal`. Demo usage is shown when they are run without parameters.

### Sealing data into a TPM 2.0 key

The `seal` example stores data securely in a newly generated TPM 2.0 key. Only when this key is loaded into the TPM can the secret data be read back.

Example output from sealing and unsealing a secret message:

```sh
$ ./examples/seal/seal keyblob.bin mySecretMessage
TPM2.0 Simple Seal example
	Key Blob: keyblob.bin
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
Sealing the user secret into a new TPM key
Created new TPM seal key (pub 46, priv 141 bytes)
Wrote 193 bytes to keyblob.bin
Key Public Blob 46
Key Private Blob 141

$ ./examples/keygen/keyload -persistent
TPM2.0 Key load example
	Key Blob: keyblob.bin
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 193 bytes from keyblob.bin
Reading the private part of the key
Loaded key to 0x80000001
Key was made persistent at 0x81000202

$ ./examples/seal/unseal message.raw
Example how to unseal data using TPM2.0
wolfTPM2_Init: success
Unsealing succeeded
Stored unsealed data to file = message.raw

$ cat message.raw
mySecretMessage
```

After a successful unsealing, the data is stored into a new file. If no filename is provided, the `unseal` tool stores the data in `unseal.bin`.

### Sealing to PCRs with a signed policy

To seal a secret to PCRs without the brittleness of a fixed PCR value, an external key signs the expected PCR state. See [Secure boot root of trust](#secure-boot-root-of-trust) below, and the `seal_policy_auth` example in the next section.

## Seal examples

The `examples/seal/` directory contains examples of TPM 2.0 seal and unseal operations with different authorization policies, listed from simplest to most flexible.

### seal and unseal (password policy)

The simplest seal and unseal, using a password-based authorization policy.

```sh
./examples/seal/seal keyblob.bin mySecretData
./examples/seal/unseal output.bin keyblob.bin
```

### seal_pcr (PCR-only policy)

Seals a secret bound to specific PCR values. The secret can only be unsealed when the PCR values match what was measured at seal time. No password or signing key is required.

Use case: Static Root of Trust, binding secrets to a specific boot state.

```sh
# Seal and unseal in one step
./examples/seal/seal_pcr -both -pcr=16 -secretstr="MySecret"

# Separate seal/unseal (for example, seal on first boot, unseal on later boots)
./examples/seal/seal_pcr -seal -pcr=16 -secretstr="MySecret"
./examples/seal/seal_pcr -unseal -pcr=16

# With parameter encryption
./examples/seal/seal_pcr -both -pcr=16 -xor -secretstr="MySecret"
./examples/seal/seal_pcr -both -pcr=16 -aes -secretstr="MySecret"

# Custom sealed blob filename
./examples/seal/seal_pcr -seal -sealblob=myblob.bin -secretstr="MySecret"
./examples/seal/seal_pcr -unseal -sealblob=myblob.bin
```

### seal_policy_auth (PolicyAuthorize and PCR)

Seals a secret using PolicyAuthorize with a TPM-resident signing key and a PCR policy. The signing key can re-authorize the policy for new PCR values, so secrets can survive authorized changes such as OS updates.

Use case: flexible measured boot with authorized policy updates.

!!! note
    `authkey.bin` and `sealblob.bin` must be kept together. If the signing key is regenerated, the sealed blob can no longer be unsealed.

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

### seal_nv (NV storage and PCR policy)

Stores a secret in TPM NV (non-volatile) memory protected by a PCR policy. Unlike file-based sealed blobs, the secret lives entirely inside the TPM. The program is located at `examples/nvram/seal_nv`.

Use case: secrets that must persist in TPM hardware without external files.

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

### Testing

`seal_test.sh` runs 28 tests across all three seal example groups:

```sh
bash examples/seal/seal_test.sh
```

The tests include positive cases (seal and unseal lifecycle, secret verification), negative cases (PCR mismatch, missing auth key), parameter encryption variants (XOR, AES), and custom filenames and NV indices. Output uses colored PASS, FAIL and SKIP markers with a summary. Verbose output is saved to `seal_test.log`.

| Variable | Default | Description |
|----------|---------|-------------|
| `WOLFCRYPT_ENABLE` | 1 | wolfCrypt support compiled in |
| `WOLFCRYPT_DEFAULT` | 0 | Using the default (reduced) wolfCrypt config |
| `WOLFCRYPT_ECC` | 1 | ECC support available |
| `WOLFCRYPT_RSA` | 1 | RSA support available |

The seal examples are also tested as part of `examples/run_examples.sh`, which runs during `make check`.

### Policy comparison

| Feature | seal (password) | seal_pcr | seal_policy_auth | seal_nv |
|---------|----------------|----------|-----------------|---------|
| Authorization | Password | PCR values | Signing key + PCR | PCR values |
| Complexity | Low | Low | High | Medium |
| Survives PCR change | N/A | No | Yes (with auth key) | No |
| Storage | File | File | File (blob + key) | TPM NV |
| Parameter Encryption | Yes | Yes | Yes | Yes |

## Storing keys in NVRAM

These examples show how to use the TPM as a secure vault for keys. There are two programs: one stores a TPM key into the TPM's NVRAM, and the other extracts the key from NVRAM. Both can use parameter encryption to protect against MITM attacks. The NV location is protected with a password authorization that is passed in encrypted form when `-aes` is given on the command line.

Before running the examples, make sure a `keyblob.bin` was generated using the keygen tool. The key can be of any type: RSA, ECC or symmetric. The example stores the private and public part. For a symmetric key the public part is metadata from the TPM.

Typical output for storing and then reading an RSA key with parameter encryption enabled:

```sh
$ ./examples/nvram/store -aes
Parameter Encryption: Enabled (AES CFB).

TPM2_StartAuthSession: sessionHandle 0x2000000
Reading 840 bytes from keyblob.bin
Storing key at TPM NV index 0x1800202 with password protection

Public part = 616 bytes
NV write of public part succeeded

Private part = 222 bytes
Stored 2-byte size marker before the private part
NV write of private part succeeded


$ ./examples/nvram/read -aes
Parameter Encryption: Enabled (AES CFB).

TPM2_StartAuthSession: sessionHandle 0x2000000
Trying to read 616 bytes of public key part from NV
Successfully read public key part from NV

Trying to read size marker of the private key part from NV
Successfully read size marker from NV

Trying to read 222 bytes of private key part from NV
Successfully read private key part from NV

Extraction of key from NVRAM at index 0x1800202 succeeded
Loading SRK: Storage 0x81000200 (282 bytes)
Trying to load the key extracted from NVRAM
Loaded key to 0x80000001
```

The `read` example tries to load the extracted key if both the public and private part were stored in NVRAM. The `-aes` switch turns on parameter encryption.

The examples can work with partial key material, private or public only, using the `-priv` and `-pub` options. Typical output of storing only the private part of an RSA key pair without parameter encryption:

```sh
$ ./examples/nvram/store -priv
Parameter Encryption: Not enabled (try -aes or -xor).

Reading 506 bytes from keyblob.bin
Reading the private part of the key
Storing key at TPM NV index 0x1800202 with password protection

Private part = 222 bytes
Stored 2-byte size marker before the private part
NV write of private part succeeded

$ ./examples/nvram/read -priv
Parameter Encryption: Not enabled (try -aes or -xor).

Trying to read size marker of the private key part from NV
Successfully read size marker from NV

Trying to read 222 bytes of private key part from NV
Successfully read private key part from NV

Extraction of key from NVRAM at index 0x1800202 succeeded
```

After a successful key extraction with `read`, the NV index is destroyed. To use `read` again, run `store` again first.

### NVRAM programs

All programs are in `examples/nvram/`.

| Program | Purpose |
|---------|---------|
| `store.c` | Stores a TPM key (private part, public part, or both) into an NV index. |
| `read.c` | Reads a key back from NV, loads it, and can delete the NV index. |
| `counter.c` | Creates and increments an NV counter. |
| `extend.c` | NV extend example showing bus protection with a PolicyOR. |
| `policy_nv.c` | Stores data in NV and tests a TPM2_PolicyNV based authorization. |
| `seal_nv.c` | Stores a secret in NV protected by a PCR policy (see [Seal examples](#seal-examples)). |

## Secure boot root of trust

The `examples/boot/` directory holds a TPM based root of trust design for secure boot, such as wolfBoot.

### Secure boot ROT

The design for storing a public key based root of trust in the TPM:

1. Use AES-CFB parameter encryption for all communication (salted and bound).
2. Derive a password from unique device parameters and use it as the "auth" to load the NV (authenticate).
3. The NV contains a hash of the public key (the hash matches the `.config` setting).
4. wolfBoot still has the public key internally and programs the TPM NV if it is not populated.
5. The NV is locked and created under the platform hierarchy.

Example:

```sh
$ ./examples/boot/secure_rot -write=../wolfBoot/wolfboot_signing_public_key.der -lock
TPM2: Caps 0x00000000, Did 0x0000, Vid 0x0000, Rid 0x 0
TPM2_Startup pass
TPM2_SelfTest pass
NV Auth (32)
	19 3f bf 0c bb 90 ca a1 40 96 a6 ee 8e fc 7c 3f | .?......@.....|?
	c1 c2 7f 1d c3 e0 a2 5e c7 72 5a a1 94 76 63 53 | .......^.rZ..vcS
Parameter Encryption: Enabled. (AES CFB)

TPM2_StartAuthSession: handle 0x2000000, algorithm AES
TPM2_StartAuthSession: sessionHandle 0x2000000
Storing hash of public key file ../wolfBoot/wolfboot_signing_public_key.der to NV index 0x1400200 with password protection

Public Key Hash (32)
	e3 29 f9 9e 56 93 6e 24 02 34 13 81 0f 7c 73 4d | .)..V.n$.4...|sM
	8f 9d 63 b8 8f 43 39 7b e5 46 93 dd 77 58 77 29 | ..c..C9{.F..wXw)
TPM2_NV_ReadPublic: Sz 14, Idx 0x1400200, nameAlg 11, Attr 0x42072005, authPol 0, dataSz 32, name 34
TPM2_NV_DefineSpace: Auth 0x4000000c, Idx 0x1400200, Attribs 0x1107763205, Size 32
TPM2_NV_Write: Auth 0x1400200, Idx 0x1400200, Offset 0, Size 32
Wrote 32 bytes to NV 0x1400200
Reading NV 0x1400200 public key hash
TPM2_NV_ReadPublic: Sz 14, Idx 0x1400200, nameAlg 11, Attr 0x62072005, authPol 0, dataSz 32, name 34
TPM2_NV_Read: Auth 0x1400200, Idx 0x1400200, Offset 0, Size 32
Read Public Key Hash (32)
	e3 29 f9 9e 56 93 6e 24 02 34 13 81 0f 7c 73 4d | .)..V.n$.4...|sM
	8f 9d 63 b8 8f 43 39 7b e5 46 93 dd 77 58 77 29 | ..c..C9{.F..wXw)
Locking NV index 0x1400200
NV 0x1400200 locked
TPM2_FlushContext: Closed handle 0x2000000
```

### Secure boot encryption key storage

To seal a secret to PCRs without the brittleness issue, an external key signs the state of the PCRs.

| Tool | Purpose |
|------|---------|
| `./examples/pcr/policy_sign` | Signs a digest for a PCR policy. Outputs the signature and, with `-outpolicy`, the policy authorization digest for the public key. |
| `./examples/boot/secret_seal` | Seals a secret using the authorization policy digest for the public key. If no secret is provided, a random value is generated and sealed. |
| `./examples/boot/secret_unseal` | Unseals a secret using the signed authorization policy and the public key. |

Create a signed PCR policy:

```sh
# Extend "aaa" to test PCR 16
echo aaa > aaa.bin
./examples/pcr/reset 16
./examples/pcr/extend 16 aaa.bin

# RSA sign this PCR (result to pcrsig.bin), also creates policyauth.bin from the public key
./examples/pcr/policy_sign -pcr=16 -rsa -key=./certs/example-rsa2048-key.der -out=pcrsig.bin -outpolicy=policyauth.bin
# OR
# ECC sign
./examples/pcr/policy_sign -pcr=16 -ecc -key=./certs/example-ecc256-key.der -out=pcrsig.bin -outpolicy=policyauth.bin
```

Create a sealed secret using that signed policy, based on the public key:

```sh
# Create a keyed hash sealed object using the policy authorization for the public key
./examples/boot/secret_seal -rsa -policy=policyauth.bin -out=sealblob.bin
./examples/boot/secret_seal -ecc -policy=policyauth.bin -out=sealblob.bin
# OR
# Provide the public key for policy authorization (instead of -policy=)
./examples/boot/secret_seal -rsa -publickey=./certs/example-rsa2048-key-pub.der -out=sealblob.bin
./examples/boot/secret_seal -ecc -publickey=./certs/example-ecc256-key-pub.der -out=sealblob.bin
```

Unseal:

```sh
# Unseal using the public key
./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -rsa -publickey=./certs/example-rsa2048-key-pub.der -seal=sealblob.bin
./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -ecc -publickey=./certs/example-ecc256-key-pub.der -seal=sealblob.bin
```

## See Also

- [TLS and certificates](tls-and-certificates.md)
- [Management and GPIO](management-and-gpio.md)
- [Firmware update](firmware-update.md)
- [Supported hardware](supported-hardware.md)
