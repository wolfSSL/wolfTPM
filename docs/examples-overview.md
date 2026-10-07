# Examples Overview

The wolfTPM examples show how to use a TPM 2.0 module through both the native `TPM2_*` API and the `wolfTPM2_*` wrapper API. They build with the library and are ready to run after a successful install. To connect them to your hardware platform, see the `TPM2_IoCb` function in `tpm_io.c` and the [HAL I/O callback guide](hal-io-callback.md).

The examples create RSA and ECC keys in NV for testing, using the handles defined in `./examples/tpm_test.h` (see [Run flags and test handles](#run-flags-and-test-handles)). The PKCS #7 and TLS examples need CSRs generated and signed with a test script. See the CSR and certificate signing section of `examples/README.md` for the steps.

Some examples are vendor specific, such as the extra GPIO examples for the ST33 and NPCT75x TPMs. These only work on that hardware.

## Native API test

Demonstrates calling the native `TPM2_*` APIs.

```sh
./examples/native/native_test
```

## Wrapper API test

Demonstrates calling the `wolfTPM2_*` wrapper APIs.

```sh
./examples/wrap/wrap_test
```

## Crypto primitive examples

Small, focused examples for common TPM crypto operations:

```sh
./examples/wrap/getrandom [bytes]
./examples/wrap/hash [-sha384|-sha512]
./examples/wrap/encrypt_decrypt [-aescfb|-aesctr|-aescbc]
./examples/keygen/ecdh
```

| Command | What it does |
| --- | --- |
| `getrandom [bytes]` | Gets random bytes from the TPM RNG (default 32). |
| `hash` | Hashes a message with a TPM hash sequence. SHA-256 is the default; use `-sha384` or `-sha512` to change it. |
| `encrypt_decrypt` | Symmetric encrypt/decrypt round trip. AES-CFB is the default. |
| `ecdh` | ECDH (P-256) key agreement that produces a shared secret. |

!!! note
    Many TPMs disable `TPM2_EncryptDecrypt` entirely because of export controls. The `encrypt_decrypt` example skips gracefully when the command is unavailable.

## Parameter encryption

To enable parameter encryption in the examples, use `-aes` for AES-CFB mode or `-xor` for XOR mode. Only some TPM commands and responses support it. If the `TPM2_` API entry has `CMD_FLAG_ENC2` or `CMD_FLAG_DEC2` set in its flags, the command uses parameter encryption or decryption.

Only the first parameter of a TPM command can be encrypted, and it must be of type `TPM2B_DATA`. Examples are the password auth of a TPM key or the qualifying data of a TPM2.0 Quote. The request and the response can be encrypted together or separately. The `sessionAttributes` control this:

* `TPMA_SESSION_encrypt` for the command request
* `TPMA_SESSION_decrypt` for the command response

Either one can be set alone, or both can be set in the same authorization session. This is up to the developer.

Examples that use parameter encryption:

* Key generation with an encrypted authorization value. See [Key Management](key-management.md).
* A secure vault for keys with encrypted NV authorization. See [Sealing and NVRAM](sealing-and-nvram.md).
* A TPM2.0 Quote with encrypted user data. The qualifying data supplied for a Quote is arbitrary data that goes into the signed Quote structure. With parameter encryption the host sends it to the TPM in encrypted form, which protects it from man-in-the-middle attacks. See [Attestation](attestation.md).

### Post-quantum session keys (v1.85)

On a v1.85 PQC capable TPM, the parameter encryption session can be keyed with a post-quantum primary instead of an RSA or ECC storage key. ML-KEM is decrypt capable and is used as the session salt key. ML-DSA is sign only and is used as the session bind key. The RSA or ECC storage key, where one is needed (for example as the parent of a created child), is unchanged.

Pass `-mlkem[=512|768|1024]` to salt the session with an ML-KEM key, or `-mldsa[=44|65|87]` to bind it to an ML-DSA key. These flags are accepted by `wrap_test`, `pcr/quote`, `nvram/store` and `nvram/counter`. The `keygen` example uses `-paramkey=mlkem[=...]` and `-paramkey=mldsa[=...]` instead, because `-mlkem` and `-mldsa` there select the child key type.

```sh
./examples/wrap/wrap_test -aes -mlkem=768
./examples/pcr/quote 16 quote.blob -ecc -xor -mldsa=65
./examples/nvram/counter -aes -mldsa=65
./examples/keygen/keygen keyblob.bin -ecc -aes -paramkey=mlkem=768
```

## Run flags and test handles

The handles used by the examples are defined in `./examples/tpm_test.h`.

| Define | Value | Purpose |
| --- | --- | --- |
| `TPM2_DEMO_STORAGE_KEY_HANDLE` | `0x81000200` | Persistent storage key (RSA) |
| `TPM2_DEMO_STORAGE_EC_KEY_HANDLE` | `0x81000201` | Persistent storage key (ECC) |
| `TPM2_DEMO_PERSISTENT_KEY_HANDLE` | `0x81000202` | Persistent key for common use |
| `TPM2_DEMO_HMAC_KEY_HANDLE` | `0x81000210` | Persistent HMAC key |

The RSA and ECC test keys and certificates use an index offset added to a base address:

| Define | Index | Handle | Type |
| --- | --- | --- | --- |
| `TPM2_DEMO_RSA_KEY_HANDLE` | `0x20` | `0x81000000 + 0x20` | Persistent key |
| `TPM2_DEMO_RSA_CERT_HANDLE` | `0x20` | `0x01800000 + 0x20` | NV index |
| `TPM2_DEMO_ECC_KEY_HANDLE` | `0x21` | `0x81000000 + 0x21` | Persistent key |
| `TPM2_DEMO_ECC_CERT_HANDLE` | `0x21` | `0x01800000 + 0x21` | NV index |

!!! warning
    To run the TLS server and client examples on the same machine, build wolfTPM with `WOLFTPM_TIS_LOCK` (`./configure --enable-tislock`). It adds a named semaphore that protects concurrent access to the SPI device between processes.

## See Also

* [Key Management](key-management.md)
* [Attestation](attestation.md)
* [Sealing and NVRAM](sealing-and-nvram.md)
* [HAL I/O callback guide](hal-io-callback.md)
