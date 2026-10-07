# Attestation

wolfTPM includes examples for local and remote attestation, TPM signed timestamps, endorsement key certificates and device identity keys. This page covers the remote attestation challenge flow, PCR quotes, signed timestamps, EK certificate validation and the manufacturer identity keys.

## Remote attestation overview

Remote attestation is the process of a client giving evidence to an attestation server, which checks that the client is in a known state. For this to work, the client and server must first establish trust. This is done with the standard TPM 2.0 commands `TPM2_MakeCredential` and `TPM2_ActivateCredential`.

1. The client sends the server the public parts of a TPM 2.0 Primary Attestation Key (PAK) and a quote signing Attestation Key (AK).
2. `MakeCredential` uses the public part of the PAK to encrypt a challenge (a secret). Typically the challenge is a digest of the public part of the AK. Only the TPM that can load the private part of the PAK and AK can decrypt it. Both keys carry the `fixedTPM` attribute, so the only TPM that can load them is the one where they were created.
3. The server sends the challenge to the client.
4. `ActivateCredential` uses the loaded PAK and AK to decrypt the challenge and recover the secret. The client can then respond to the server.

This proves to the server that the client holds the expected TPM identity and attestation key.

!!! note
    The transport used to exchange the challenge and response is up to the developer, because it is implementation specific. One option is a TLS 1.3 client-server connection using wolfSSL.

The examples used in this flow:

| Program | Role |
| --- | --- |
| `./examples/attestation/make_credential` | Used by a server to create a remote attestation challenge. |
| `./examples/attestation/activate_credential` | Used by a client to decrypt the challenge and respond. |
| `./examples/attestation/certify` | Certifies (attests) that an object with a given name is loaded in the TPM. |
| `./examples/keygen/create_primary` | Creates a primary key (PK) and attestation key (AK). |

All of these examples accept `-eh` to use the Endorsement Key and an Attestation Key under the Endorsement Hierarchy. The private part of the EK never leaves the TPM, and the EK is unique to each TPM chip, so a challenge encrypted to the EK can only be opened by that TPM. The drawback is privacy: the EK identifies the TPM, so the identity of the host under attestation is always known. The examples support both an AK under the SRK and an AK under the EK. The developer chooses which to use.

## Creating keys for attestation

Use the `keygen` example to create the TPM 2.0 Attestation Key and the Primary Storage Key that serves as the Primary Attestation Key (PAK).

```sh
$ ./examples/keygen/keygen -rsa
TPM2.0 Key generation example
	Key Blob: keyblob.bin
	Algorithm: RSA
	Template: AIK
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
RSA AIK template
Creating new RSA key...
New key created and loaded (pub 280, priv 222 bytes)
Wrote 508 bytes to keyblob.bin
Wrote 288 bytes to srk.pub
Wrote AK Name digest
```

The files written here (`keyblob.bin`, `srk.pub` and the AK name digest) are the inputs for the next two steps. See [Key Management](key-management.md) for more on `keygen`.

## MakeCredential and ActivateCredential

### Make credential

An attestation server uses `make_credential` to generate the challenge. The secret is 32 bytes of random data that can serve as a symmetric key seed in some attestation schemes.

```sh
$ ./examples/attestation/make_credential
Using public key from SRK to create the challenge
Demo how to create a credential challenge for remote attestation
Credential will be stored in cred.blob
wolfTPM2_Init: success
Reading 288 bytes from srk.pub
Reading the private part of the key
Public key for encryption loaded
Read AK Name digest success
TPM2_MakeCredential success
Wrote credential blob and secret to cred.blob, 648 bytes
```

The transfer of the PAK and AK public parts between the client and server is not part of this example.

### Activate credential

A client uses `activate_credential` to decrypt the challenge. The secret is exposed in plain text and can be sent to the attestation server.

```sh
$ ./examples/attestation/activate_credential
Using default values
Demo how to create a credential blob for remote attestation
wolfTPM2_Init: success
Credential will be read from cred.blob
Loading SRK: Storage 0x81000200 (282 bytes)
SRK loaded
Reading 508 bytes from keyblob.bin
Reading the private part of the key
AK loaded at 0x80000001
Read credential blob and secret from cred.blob, 648 bytes
TPM2_ActivateCredential success
```

Sending the response containing the secret (in plain text or as a symmetric key seed) back to the server is also outside this example.

### Certify

The `certify` example uses `TPM2_Certify` to sign attestation information for another key. This proves that an object with a specific name is loaded in the TPM. A common use is having the restricted IAK sign the attestation information for the IDevID.

`create_primary` can create RSA or ECC IDevID and IAK keys. They are created under the endorsement hierarchy and follow the TCG "TPM 2.0 Keys for Device Identity and Attestation" specification for primary key policies. The IDevID key is used for external, non-restricted signing. The IAK is used for internal attestation. Here the IAK certifies the IDevID.

```sh
% ./examples/keygen/create_primary -rsa -eh -iak -keep
TPM2.0 Primary Key generation example
        Algorithm: RSA
        Unique: IAK
        Store Handle: 0x00000000
        Use Parameter Encryption: NULL
Creating new RSA primary key...
Create Primary Handle: 0x80000000

% ./examples/keygen/create_primary -rsa -eh -idevid -keep
TPM2.0 Primary Key generation example
        Algorithm: RSA
        Unique: IDEVID
        Store Handle: 0x00000000
        Use Parameter Encryption: NULL
Creating new RSA primary key...
Create Primary Handle: 0x80000001

% ./examples/attestation/certify -rsa -certify=0x80000001 -signer=0x80000000
Certify 0x80000001 with 0x80000000 to generate TPM-signed attestation info
EK Policy Session: Handle 0x3000000
TPM2_Certify complete
Certify Info 172
RSA Signature: 256

% ./examples/management/flush 0x80000001
Preparing to free TPM2.0 Resources
Freeing 80000001 object

% ./examples/management/flush 0x80000000
Preparing to free TPM2.0 Resources
Freeing 80000000 object
```

For ECC, use the same steps and replace `-rsa` with `-ecc`.

## Quote and PCR attestation

The `examples/pcr/` folder has tools for working with Platform Configuration Registers (PCRs) and for generating a TPM 2.0 Quote. Build with `./configure --enable-debug` to see more log output.

| Program | Purpose |
| --- | --- |
| `./examples/pcr/reset` | Clears the content of a PCR (restrictions apply, see below). |
| `./examples/pcr/extend` | Modifies the content of a PCR with an extend operation. |
| `./examples/pcr/quote` | Generates a TPM 2.0 Quote with the PCR digest and a TPM signature. |
| `./examples/pcr/allocate` | Reports which PCR banks the TPM implements and has allocated, and changes the allocation. |
| `./examples/pcr/demo.sh` | Script that demonstrates the tools above. |
| `./examples/pcr/demo-quote-zip.sh` | Script that measures a system file and generates a TPM signed proof of that measurement. |

### PCR basics

A PCR can only be changed by an extend operation. At power-up the TPM resets all PCRs to their default value (all zeros or all ones, depending on the PCR). The same PCR value can only be reached by extending with the same digests in the same order. Extending with A, B, C gives a different result than C, B, A, but each order is reproducible.

`TPM2_Extend` uses a SHA-1 or SHA-256 hash operation to combine the current PCR value with the new digest.

Every PCR can be extended, but only some can be reset at runtime:

* PCR0 to 15 are reset at boot and can be cleared again only by a reboot.
* PCR16 is for debugging. All the tools above use it by default, and it is safe to test with.
* PCR17 to 22 are reserved for Dynamic Root of Trust Measurement (DRTM).

Reset locality follows TCG PC Client: PCR16 and 23 reset at localities 0 to 3, PCR20 to 22 at localities 2 to 4, and PCR17 to 19 at locality 4. Use `-loc=n` to select the locality (see `wolfTPM2_SetLocality`). It applies to the built-in TIS/SPI driver and the fwTPM.

### Bank allocation

A TPM keeps a separate set of PCRs per hash algorithm, called a bank. Which banks exist is fixed in silicon, but which are allocated is provisioned with `TPM2_PCR_Allocate` and can be changed. Many parts, including the Infineon SLB9672 and later, allocate only one bank at a time, so moving from SHA-256 to SHA-384 means deallocating SHA-256. SHA-1 is deprecated and is not allocated on current parts.

!!! warning
    The selection replaces the allocation. Any bank not named in the request is deallocated. The command needs the platform hierarchy, which platform firmware has usually disabled under an OS (the TPM answers `TPM_RC_HIERARCHY` regardless of the authorization supplied). Use `wolfTPM2_AllocatePCRBanks_ex` with a session where platform auth is not the empty password. The change takes effect at the next TPM reset, so power cycle the TPM or restart the simulator, then re-read the banks. Changing banks invalidates every `PolicyPCR` digest, and anything sealed to PCR values can no longer be unsealed.

### Quote

`TPM2_Quote` puts the PCR digest in a TCG defined `TPMS_ATTEST` structure together with a TPM signature. The signature comes from an Attestation Identity Key (AIK) that only the TPM can use, which gives assurance about the source of the Quote and the PCR digest.

### Tool usage

```sh
$ ./examples/pcr/reset -?
Incorrect arguments
Expected usage:
./examples/pcr/reset [pcr] [-loc=n]
* pcr is a PCR index between 0-23 (default 16)
* -loc=n switch to TPM locality n (0-4) before reset
    (PCR 17-19 need locality 4; 20-22 need locality 2-4;
     enforced by the fwTPM and by discrete TPMs like the ST33)
Demo usage without parameters, resets PCR16.
```

```sh
$ ./examples/pcr/extend -?
Incorrect arguments
Expected usage:
./examples/pcr/extend [pcr] [filename]
* pcr is a PCR index between 0-23 (default 16)
* filename points to file(data) to measure
	If wolfTPM is built with --disable-wolfcrypt the file
	must contain SHA256 digest ready for extend operation.
	Otherwise, the extend tool computes the hash using wolfcrypt.
Demo usage without parameters, extends PCR16 with known hash.
```

```sh
$ ./examples/pcr/quote -?
Incorrect arguments
Expected usage:
./examples/pcr/quote [pcr] [filename]
* pcr is a PCR index between 0-23 (default 16)
* filename for saving the TPMS_ATTEST structure to a file
Demo usage without parameters, generates quote over PCR16 and
saves the output TPMS_ATTEST structure to "quote.blob" file.
```

```sh
$ ./examples/pcr/allocate -?
Expected usage:
./examples/pcr/allocate [-sha1] [-sha256] [-sha384] [-sha512]
                        [-restore]
* no algorithm flags: report the current allocation and exit
* -shaN: include that bank in the new allocation (repeatable)
* -restore: put the original allocation back before exiting
Demo usage without parameters, reports the PCR banks.

WARNING: the algorithm flags REPLACE the allocation. Banks not
named are deallocated, every PolicyPCR digest changes, and blobs
sealed to PCR values become unsealable. Many TPMs support only
one active bank at a time.

The new allocation takes effect at the next TPM reset, so power
cycle the TPM (or restart the simulator) and re-run to confirm.
```

With no flags, `allocate` reports the banks the TPM has. The list comes from the TPM's own `TPM_CAP_PCRS` response, so a bank this build has no name for prints as its hash algorithm id, and `pcrSelect` is the raw bitmap:

```sh
$ ./examples/pcr/allocate
PCR banks:
  Bank       Allocated  pcrSelect
  SHA-256    yes        FFFFFF
  SHA-384    yes        FFFFFF
  SHA-1      no         000000
```

To move to a SHA-384 only allocation and confirm it after a reset:

```sh
$ ./examples/pcr/allocate -sha384
TPM reported: allocationSuccess YES, maxPCR 24, sizeNeeded 1152, sizeAvailable 4608
PCR allocation staged. It takes effect at the next TPM reset
(Startup(CLEAR) after a _TPM_Init) - power cycle the TPM, or
restart the simulator process, then re-run to confirm.

$ ./examples/pcr/allocate
PCR banks:
  Bank       Allocated  pcrSelect
  SHA-256    no         000000
  SHA-384    yes        FFFFFF
  SHA-1      no         000000
```

On a TPM that keeps one bank active, asking for two is rejected with `TPM_RC_PCR`. A TPM that accepts the command but lacks space reports `allocationSuccess = NO`, which the wrapper returns as `BUFFER_E` with `sizeNeeded` greater than `sizeAvailable`. Neither case is a wolfTPM error.

Use `-restore` in scripts so a run leaves the banks as it found them. It replays the exact selection read at startup, bitmaps included, so a partially selected bank comes back partial.

### Typical demo output

All PCR examples run without arguments. This is the output of `./examples/pcr/demo.sh`:

```sh
$ ./examples/pcr/reset
Demo how to reset a PCR (clear the PCR value)
wolfTPM2_Init: success
Trying to reset PCR16...
TPM2_PCR_Reset success
PCR16 digest:
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
```

PCR16 is back to all zeros, so later PCR digests are predictable. This is similar to PCR7 right after boot, but PCR16 lets you test without rebooting.

```sh
$ ./examples/pcr/extend
Demo how to extend data into a PCR (TPM2.0 measurement)
wolfTPM2_Init: success
Hash to be used for measurement:
000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
TPM2_PCR_Extend success
PCR16 digest:
    bb 22 75 c4 9f 28 ad 52 ca e6 d5 5e 34 a9 74 a5 | ."u..(.R...^4.t.
    8c 7a 3b a2 6f 97 6e 8e cb be 7a 53 69 18 dc 73 | .z;.o.n...zSi..s
```

The new value comes from the old PCR content (all zeros) and the supplied SHA-256 digest. It is always the same if `reset` runs before `extend`. To use your own data, pass the PCR index first (16 is recommended) and a file second.

```sh
$ ./examples/pcr/quote
Demo of generating signed PCR measurement (TPM2.0 Quote)
wolfTPM2_Init: success
TPM2_CreatePrimary: 0x80000000 (314 bytes)
wolfTPM2_CreateEK: Endorsement 0x80000000 (314 bytes)
TPM2_CreatePrimary: 0x80000001 (282 bytes)
wolfTPM2_CreateSRK: Storage 0x80000001 (282 bytes)
TPM2_StartAuthSession: sessionHandle 0x3000000
TPM2_Create key: pub 280, priv 212
TPM2_Load Key Handle 0x80000002
wolfTPM2_CreateAndLoadAIK: AIK 0x80000002 (280 bytes)
TPM2_Quote: success
TPM with signature attests (type 0x8018):
    TPM signed 1 count of PCRs
    PCR digest:
    c7 d4 27 2a 57 97 7f 66 1f bd 79 30 0a 1b bf ff | ..'*W..f..y0....
    2e 43 57 cc 44 14 7a 82 11 aa 76 3f 9f 1b 3a 6c | .CW.D.z...v?..:l
    TPM generated signature:
    28 dc da 76 33 35 a5 85 2a 0c 0b e8 25 d0 f8 8d | (..v35..*...%...
    1f ce c3 3b 71 64 ed 54 e6 4d 82 af f3 83 18 8e | ...;qd.T.M......
    (remaining signature bytes omitted)
```

Before the TPM signs the quote, the example creates an Endorsement Key (EK), which acts as the primary key for the others. It then creates a Storage Key (SRK) and, under it, an Attestation Identity Key (AIK) that signs the quote structure.

### Measuring a system file (local attestation)

A system administrator wants to confirm that the `zip` tool on a user's system is genuine and unmodified. The administrator resets PCR16, extends it with a hash of the binary, and generates a quote that serves as a reference for later comparison. This is what `./examples/pcr/demo-quote-zip.sh` does.

```sh
$ ./examples/pcr/reset 16
...
Trying to reset PCR16...
TPM2_PCR_Reset success
...
```

The `extend` tool hashes `/usr/bin/zip` with wolfCrypt (SHA-256) and wolfTPM issues a `TPM2_PCR_Extend` on PCR16:

```sh
$ ./examples/pcr/extend 16 /usr/bin/zip
...
TPM2_PCR_Extend success
PCR16 digest:
    2b bd 54 ae 08 5b 59 ef 90 42 d5 ca 5d df b5 b5 | +.T..[Y..B..]...
    74 3a 26 76 d4 39 37 eb b0 53 f5 82 67 6f b4 aa | t:&v.97..S..go..
```

Then the administrator creates a quote as proof of the measurement in PCR16:

```sh
$ ./examples/pcr/quote 16 zip.quote
...
TPM2_Quote: success
TPM with signature attests (type 0x8018):
    TPM signed 1 count of PCRs
...
```

The quote is saved to the binary file `zip.quote`. The `TPMS_ATTEST` structure also holds clock and time information. See the next section for time attestation.

### Quote with encrypted qualifying data

The qualifying data supplied for a quote can be protected with parameter encryption. See [Examples Overview](examples-overview.md#parameter-encryption).

## Signed timestamp (GetTime)

The `signed_timestamp` example creates an Attestation Identity Key (AIK) and uses it to generate a TPM signed timestamp. The timestamp can serve as a protected report of the current system uptime.

```sh
./examples/timestamp/signed_timestamp
```

The example uses an `authSession` (authorization session) and a `policySession` (policy authorization) to enable the Endorsement Hierarchy, which is needed to create the AIK. The AIK then issues a `TPM2_GetTime` command through the native API, which returns a TPM generated and signed timestamp.

The `clock_set` example increments the TPM2 clock:

```sh
./examples/timestamp/clock_set [time]
```

## Endorsement key certificates

TPM manufacturers provision endorsement certificates based on a TPM key. The TCG EK Credential Profile defines how they are stored in the TCG NV index range (`TPM_20_TCG_NV_SPACE`). The `get_ek_certs` example enumerates and validates the EK certificates stored there, and creates a primary EK handle that can be used for signing. The `verify_ek_cert` example validates a single EK certificate against the trusted CA list. Some root and intermediate CAs are loaded in `trusted_certs.h`.

```sh
./examples/endorsement/get_ek_certs
./examples/endorsement/verify_ek_cert
```

### Example detail

1. Get the handles in the TCG NV range with `wolfTPM2_GetHandles` and `TPM_20_TCG_NV_SPACE`.
2. Get the certificate size by reading the public NV information with `wolfTPM2_NVReadPublic`.
3. Read the NV data (certificate DER/ASN.1) from the NV index with `wolfTPM2_NVReadAuth`.
4. Get the EK public template for the NV index with `wolfTPM2_GetKeyTemplate_EKIndex` or `wolfTPM2_GetKeyTemplate_EK`.
5. Create the primary endorsement key with the public template and the `TPM_RH_ENDORSEMENT` hierarchy using `wolfTPM2_CreatePrimaryKey`.
6. Parse the ASN.1/DER certificate with `wc_ParseCert` to get the issuer, serial number and other fields.
7. The URI for the CA issuer certificate is in `extAuthInfoCaIssuer`.
8. Import the certificate public key and compare it with the primary EK public unique area.
9. Validate the EK certificate with the wolfSSL Certificate Manager. Load trusted certificates with `wolfSSL_CertManagerLoadCABuffer` and verify with `wolfSSL_CertManagerVerifyBuffer`.
10. Optionally convert to PEM and export with `wc_DerToPem`.

### Example certificate chains

Infineon SLB9672. Certificates can be downloaded from these URLs (replace xxx with the 3 digit CA number):

* `https://pki.infineon.com/OptigaRsaMfrCAxxx/OptigaRsaMfrCAxxx.crt`
* `https://pki.infineon.com/OptigaEccMfrCAxxx/OptigaEccMfrCAxxx.crt`

Examples:

* Infineon OPTIGA(TM) RSA Root CA 2, then Infineon OPTIGA(TM) TPM 2.0 RSA CA 059
* Infineon OPTIGA(TM) ECC Root CA 2, then Infineon OPTIGA(TM) TPM 2.0 ECC CA 059

STMicro ST33KTPM:

* STSAFE RSA root CA 02 (`http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt`), then STSAFE-TPM RSA intermediate CA 10 (`http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt`)
* STSAFE ECC root CA 02 (`http://sw-center.st.com/STSAFE/STSAFEEccRootCA02.crt`), then STSAFE-TPM ECC intermediate CA 10 (`http://sw-center.st.com/STSAFE/stsafetpmeccint10.crt`)

Sample output on an ST33KTPM (certificate hex dumps shortened):

```
$ ./examples/endorsement/verify_ek_cert
Endorsement Certificate Verify
TPM2: Caps 0x30000415, Did 0x0004, Vid 0x104a, Rid 0x 1
TPM2_Startup pass
TPM2_NV_ReadPublic: Sz 14, Idx 0x1c00002, nameAlg 11, Attr 0x62076801, authPol 0, dataSz 1300, name 34
TPM2_NV_Read: Auth 0x1c00002, Idx 0x1c00002, Offset 0, Size 768
TPM2_NV_Read: Auth 0x1c00002, Idx 0x1c00002, Offset 768, Size 532
EK Data: 1300
        30 82 05 10 30 82 02 f8 a0 03 02 01 02 02 14 58 | 0...0..........X
        ...
wolfTPM2_HashStart: Handle 0x80000002
wolfTPM2_HashUpdate: Handle 0x80000002, DataSz 764
wolfTPM2_HashFinish: Handle 0x80000002, DigestSz 48
Cert Hash: 48
        ...
Issuer Public Exponent 0x10001, Modulus 512
        ...
TPM2_LoadExternal: 0x80000002
EK Certificate Signature: 512
        ...
TPM2_RSA_Encrypt: 512
Decrypted Sig: 512
        ...
Expected Hash: 48
        ...
Sig Hash: 48
        ...
Certificate signature is valid
TPM2_FlushContext: Closed handle 0x80000002
TPM2_FlushContext: Closed handle 0x80000000
```

## Device identity

The TCG publishes a specification for TPM manufacturer guidance on setting up keys for device identity and attestation. wolfTPM supports it with `WOLFTPM_MFG_IDENTITY`, and it has been tested with the ST33KTPM.

ST33KTPM samples are provisioned with a default master password, enabled with `TEST_SAMPLE`. To use your own master password, define `TPM2_IAK_SAMPLE_MASTER_PASSWORD`. The master password is hashed together with the device serial number to produce the authentication for accessing these keys.

The default keys are ECDSA SECP384R1 with SHA2-384. They are stored at the NV indexes defined by `TPM2_IAK_KEY_HANDLE`, `TPM2_IAK_CERT_HANDLE`, `TPM2_IDEVID_KEY_HANDLE` and `TPM2_IDEVID_CERT_HANDLE`.

## See Also

* [Examples Overview](examples-overview.md)
* [Key Management](key-management.md)
* [Sealing and NVRAM](sealing-and-nvram.md)
* [Supported Hardware](supported-hardware.md)
