# Key Management

wolfTPM includes example programs for creating TPM keys, storing them to disk as key blobs, importing external keys, and loading them back into a temporary TPM handle. This page walks through the key generation examples and lists the programs in `examples/keygen/` and the wrapper utilities in `examples/wrap/`.

## Key generation overview

The `keygen` example creates a TPM key under the storage key (SRK) and writes the key blob to disk. The `keyload` example reads that blob and loads it into a temporary TPM handle.

```sh
$ ./examples/keygen/keygen keyblob.bin -rsa
TPM2.0 Key generation example
Loading SRK: Storage 0x81000200 (282 bytes)
Creating new RSA key...
Created new key (pub 280, priv 222 bytes)
Wrote 840 bytes to keyblob.bin

$ ./examples/keygen/keyload keyblob.bin
TPM2.0 Key load example
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 840 bytes from keyblob.bin
Loaded key to 0x80000001


$ ./examples/keygen/keygen keyblob.bin -ecc
TPM2.0 Key generation example
Loading SRK: Storage 0x81000200 (282 bytes)
Creating new ECC key...
Created new key (pub 88, priv 126 bytes)
Wrote 744 bytes to keyblob.bin

$ ./examples/keygen/keyload keyblob.bin
TPM2.0 Key load example
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 744 bytes from keyblob.bin
Loaded key to 0x80000001
```

Symmetric and keyed hash keys use the same flow:

```sh
$ ./examples/keygen/keygen -sym=aescfb128
TPM2.0 Key generation example
	Key Blob: keyblob.bin
	Algorithm: SYMCIPHER
		 aescfb mode, 128 keybits
	Template: Default
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
Symmetric template
Creating new SYMCIPHER key...
Created new key (pub 50, priv 142 bytes)
Wrote 198 bytes to keyblob.bin

$ ./examples/keygen/keyload
TPM2.0 Key load example
	Key Blob: keyblob.bin
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 198 bytes from keyblob.bin
Reading the private part of the key
Loaded key to 0x80000001

$ ./examples/keygen/keygen -keyedhash
TPM2.0 Key generation example
	Key Blob: keyblob.bin
	Algorithm: KEYEDHASH
	Template: Default
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
Keyed Hash template
Creating new KEYEDHASH key...
TPM2_Create key: pub 48, priv 158
Public Area (size 48):
  Type: KEYEDHASH (0x8), name: SHA256 (0xB), objAttr: 0x40460, authPolicy sz: 0
  Keyed Hash: scheme: HMAC (0x5), scheme hash: SHA256 (0xB), unique size 32
TPM2_Load Key Handle 0x80000001
New key created and loaded (pub 48, priv 158 bytes)
Wrote 212 bytes to keyblob.bin
```

When no filename is given, the default `keyblob.bin` is used. That means `keygen` and `keyload` can run without extra parameters for a quick demonstration. Use one of the `--help` switches to see the full list of algorithms and options `keygen` supports.

The `keyimport` example takes a private key, wraps it as a TPM key blob and stores it to disk. It can then be loaded with `keyload`:

```sh
$ ./examples/keygen/keyimport keyblob.bin -rsa
TPM2.0 Key import example
Loading SRK: Storage 0x81000200 (282 bytes)
Imported key (pub 278, priv 222 bytes)
Wrote 840 bytes to keyblob.bin

$ ./examples/keygen/keyload keyblob.bin
TPM2.0 Key load example
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 840 bytes from keyblob.bin
Loaded key to 0x80000001


$ ./examples/keygen/keyimport keyblob.bin -ecc
TPM2.0 Key Import example
Loading SRK: Storage 0x81000200 (282 bytes)
Imported key (pub 86, priv 126 bytes)
Wrote 744 bytes to keyblob.bin

$ ./examples/keygen/keyload keyblob.bin
TPM2.0 Key load example
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 744 bytes from keyblob.bin
Loaded key to 0x80000001
```

`keyload` takes only one argument, the filename of the stored key. It does not need to be told the key type because the RSA or ECC scheme is stored inside the key blob.

To protect the authorization value while creating a key, add `-aes` or `-xor` to `keygen`. See [Examples Overview](examples-overview.md#parameter-encryption).

## Programs (examples/keygen/)

| Program | Description |
| --- | --- |
| `create_primary.c` | Creates and stores primary keys, including endorsement hierarchy keys such as the IAK and IDevID. |
| `keygen.c` | Creates a new RSA, ECC, symmetric or keyed hash key under the SRK and writes the key blob to disk. |
| `keyload.c` | Reads a key blob from disk and loads it into a temporary TPM handle. |
| `keyimport.c` | Imports an existing private key as a TPM key blob and writes it to disk. |
| `external_import.c` | Imports an external private key (built into the example) under the SRK. Use `-rsa` or `-ecc` for the SRK type, and `-load` to load the saved `keyblob.bin` to a third level key. |
| `ecdh.c` | ECDH key agreement using a TPM key, producing a shared secret. |

## Wrapper utilities (examples/wrap/)

| Program | Description |
| --- | --- |
| `wrap_test.c` | Exercises the `wolfTPM2_*` wrapper APIs. |
| `caps.c` | Reads and prints TPM capabilities. |
| `getrandom.c` | Gets random bytes from the TPM RNG. |
| `hash.c` | Hashes a message with a TPM hash sequence. |
| `hmac.c` | Computes an HMAC with a persistent TPM HMAC key, creating the key if it is not found. |
| `encrypt_decrypt.c` | Symmetric encrypt/decrypt round trip with a TPM key. |

## Storing keys in NV

Keys and secrets can also be stored in the TPM's NV memory, optionally with an encrypted authorization value. See [Sealing and NVRAM](sealing-and-nvram.md).

## See Also

* [Examples Overview](examples-overview.md)
* [Sealing and NVRAM](sealing-and-nvram.md)
* [Attestation](attestation.md)
