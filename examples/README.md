# wolfTPM Examples

These examples demonstrate features of a TPM 2.0 module.

The examples create RSA and ECC keys in NV for testing using handles defined in `./examples/tpm_test.h`.

The PKCS #7 and TLS examples require generating CSR's and signing them using a test script. See CSR and Certificate Signing below.

To enable parameter encryption use `-aes` for AES-CFB mode or `-xor` for XOR mode. Only some TPM commands / responses support parameter encryption. If the TPM2_ API has .flags `CMD_FLAG_ENC2` or `CMD_FLAG_DEC2` set then the command will use parameter encryption / decryption.

There are some vendor specific examples, like the TPM 2.0 extra GPIO examples for ST33 and NPCT75x.

## Native API Test

Demonstrates calling native TPM2_* API's.

`./examples/native/native_test`


## Wrapper API Test

Demonstrates calling the wolfTPM2_* wrapper API's.

`./examples/wrap/wrap_test`


## Attestation Use Cases

### TPM signed timestamp, TPM2.0 GetTime

Demonstrates creation of Attestation Identity Keys (AIK) and the generation of TPM signed timestamp that can be later used as protected report of the current system uptime.

This example demonstrates the use of `authSession` (authorization Session) and `policySession` (Policy authorization) to enable the Endorsement Hierarchy necessary for creating AIK. The AIK is used to issue a `TPM2_GetTime` command using the TPM 2.0 native API. This provides a TPM generated and signed timestamp that can be used as a system report of its uptime.

`./examples/timestamp/signed_timestamp`

### TPM signed PCR(system) measurement, TPM2.0 Quote

Demonstrates the generation of TPM2.0 Quote used for attestation of the system state by putting PCR value(s) in a TPM signed structure.

More information about how to test and use PCR attestation can be found in the in [examples/pcr/README.md](./examples/pcr/README.md).

`./examples/pcr/quote`
`./examples/pcr/extend`
`./examples/pcr/reset`

### Remote Attestation challenge

Demonstrates how to create Remote Attestation challenge using the TPM 2.0 and afterwards prepare a response.

Detailed information about using these examples can be found in  [examples/attestation/README.md](./examples/attestation/README.md)

`./examples/attestation/make_credential`
`./examples/attestation/activate_credential`

## Parameter Encryption

### Key generation with encrypted authorization

Detailed information can be found in this file under section "Key generation"

### Secure vault for keys with encrypted NVRAM authorization

Detailed information can be found in this file under section "Storing keys into the TPM's NVRAM"

### TPM2.0 Quote with encrypted user data

Example for demonstrating how to use parameter encryption to protect the user data between the Host and the TPM.

In this example the qualifying data that can be supplied by the user for a Quote operation is protected. Qualifying data is arbitrary data incorporated into the signed Quote structure. Using parameter encryption, wolfTPM enables the Host to transfer that user data in encrypted form to the TPM and vice versa. Thus, protecting the data from man-in-the-middle attacks.

Only the first parameter of a TPM command can be encrypted and the parameter must be of type `TPM2B_DATA`. For example, the password auth of a TPM key or the qualifying data of a TPM2.0 Quote.

The encryption of command request and response can be performed together or separate. There can be a communication exchange between the TPM and a client program where only the parameter in the request command is encrypted.

This behavior depends on the `sessionAttributes`:

- `TPMA_SESSION_encrypt` for command request
- `TPMA_SESSION_decrypt` for command response

Either one can be set separately or both can be set in one authorization session. This is up to the user (developer).

`./examples/pcr/quote_paramenc`

## CSR

Generates a Certificate Signing Request for building a certificate based on a TPM key pair.

`./examples/csr/csr`

It creates two files:
`./certs/tpm-rsa-cert.csr`
`./certs/tpm-ecc-cert.csr`


## Certificate Signing

External script for generating test certificates based on TPM generated CSR's. Typically the CSR would be provided to a trusted CA for signing.

`./certs/certreq.sh`

The script creates the following X.509 files (also in .pem format):
`./certs/ca-ecc-cert.der`
`./certs/ca-rsa-cert.der`
`./certs/client-rsa-cert.der`
`./certs/client-ecc-cert.der`
`./certs/server-rsa-cert.der`
`./certs/server-ecc-cert.der`


## PKCS #7

Example signs and verifies data with PKCS #7 using a TPM based key.

* Must first run:
1. `./examples/csr/csr`
2. `./certs/certreq.sh`
3. `./examples/pkcs7/pkcs7`

The result is displayed to stdout on the console.


## TLS Examples

The TLS example uses TPM based ECDHE (ECC Ephemeral key) support. It can be disabled using `CFLAGS="-DWOLFTPM2_USE_SW_ECDHE"` or `#define WOLFTPM2_USE_SW_ECDHE`. We are also looking into using the 2-phase `TPM2_EC_Ephemeral` and `TPM2_ZGen_2Phase` methods for improved performance and scalability.

To force ECC use with wolfSSL when RSA is enabled define `TLS_USE_ECC`.

To use symmetric AES/Hashing/HMAC with the TPM define `WOLFTPM_USE_SYMMETRIC`.

Generation of the Client and Server Certificates requires running:


1. `./examples/keygen/keygen rsa_test_blob.raw -rsa -t`
2. `./examples/keygen/keygen ecc_test_blob.raw -ecc -t`
3. `./examples/csr/csr`
4. `./certs/certreq.sh`
5. Copy the CA files from wolfTPM to wolfSSL certs directory.
    a. `cp ./certs/ca-ecc-cert.pem ../wolfssl/certs/tpm-ca-ecc-cert.pem`
    b. `cp ./certs/ca-rsa-cert.pem ../wolfssl/certs/tpm-ca-rsa-cert.pem`

Note: The `wolf-ca-rsa-cert.pem` and `wolf-ca-ecc-cert.pem` files come from the wolfSSL example certificates here:

```
cp ../wolfssl/certs/ca-cert.pem ./certs/wolf-ca-rsa-cert.pem
cp ../wolfssl/certs/ca-ecc-cert.pem ./certs/wolf-ca-ecc-cert.pem
```

### TLS Client

Examples show using a TPM key and certificate for TLS mutual authentication (client authentication).

This example client connects to localhost on on port 11111 by default. These can be overridden using `TLS_HOST` and `TLS_PORT`.

You can validate using the wolfSSL example server this like:
`./examples/server/server -b -p 11111 -g -d -i -V`

To validate client certificate use the following wolfSSL example server command:
`./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-rsa-cert.pem -i -V`
or
`./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-ecc-cert.pem -i -V`

Then run the wolfTPM TLS client example:
`./examples/tls/tls_client -rsa`
or
`./examples/tls/tls_client -ecc`


### TLS Server

This example shows using a TPM key and certificate for a TLS server.

By default it listens on port 11111 and can be overridden at build-time using the `TLS_PORT` macro.

Run the wolfTPM TLS server example:
`./examples/tls/tls_server -rsa`
or
`./examples/tls/tls_server -ecc`

Then run the wolfSSL example client this like:
`./examples/client/client -h localhost -p 11111 -g -d`

To validate server certificate use the following wolfSSL example client comment:
`./examples/client/client -h localhost -p 11111 -g -A ./certs/tpm-ca-rsa-cert.pem`
or
`./examples/client/client -h localhost -p 11111 -g -A ./certs/tpm-ca-ecc-cert.pem`


Or using your browser: `https://localhost:11111`

With browsers you will get certificate warnings until you load the test CA's `./certs/ca-rsa-cert.pem` and `./certs/ca-ecc-cert.pem` into your OS key store.
For testing most browsers have a way to continue to the site anyways to bypass the warning.


## Clock

Updating the TPM clock

The TPM has internal hardware clock that can be useful to the user. There are two values that the TPM can provide in respect to time.

TPM time is the current uptime, since the last power on sequence. This value can not be changed or modified. There is no mechanism for that. The value is reset at every power sequence.

TPM clock is the total time the TPM has ever been powered. This value can be modified using the TPM2_ClockSet command. The TPM clock can be set only forward.

This way the user can keep track of relative and current time using the TPM clock.

Note: If the new time value makes a change bigger than the TPM clock update interval, then the TPM will first update its volatile register for time and then the non-volatile register for time. This may cause a narrow delay before the commands returns execution to the user. Depending on the TPM manufacturer, the delay can vary from us to few ms.

Note: This example can take an optional argument, the time value in milliseconds used for incrementing the TPM clock. Default value is 50000ms (50 seconds).

`./examples/timestamp/clock_set`

## Benchmark

Performance benchmarks.

`./examples/bench/bench`

## Key Generation

Examples for generating a TPM key blob and storing to disk, then loading from disk and loading into temporary TPM handle.

```
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

./examples/keygen/keygen -sym=aescfb128
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

When filename is not supplied, a default filename "keyblob.bin" is used, therefore `keyload` and `keygen` can be used without additional parameters for quick TPM 2.0 key generation demonstration.

To see the complete list of supported cryptographic algorithms and options by the `keygen` example, use one of the `--help` switches.

Example for importing a private key as TPM key blob and storing to disk, then loading from disk and loading into temporary TPM handle.

```
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

The `keyload` tool takes only one argument, the filename of the stored key. Because the information what is key scheme (RSA or ECC) is contained within the key blob.

## Storing keys into the TPM's NVRAM

These examples demonstrates how to use the TPM as a secure vault for keys. There are two programs, one to store a TPM key into the TPM's NVRAM and another to extract the key from the TPM's NVRAM. Both examples can use parameter encryption to protect from MITM attacks. The Non-volatile memory location is protected with a password authorization that is passed in encrypted form, when "-aes" is given on the command line.

Before running the examples, make sure there is a keyblob.bin generated using the keygen tool. The key can be of any type, RSA, ECC or symmetric. The example will store the private and public part. In case of a symmetric key the public part is meta data from the TPM. How to generate a key you can see above, in the description of the keygen example.

Typical output for storing and then reading an RSA key with parameter encryption enabled:

```

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

The "read" example will try to load the extracted key, if both the public and private part of the key were stored in NVRAM. The "-aes" switches triggers the use of parameter encryption.

The examples can work with partial key material - private or public. This is achieved by using the "-priv" and "-pub" options.

Typical output of storing only the private key of RSA asymmetric key pair in NVRAM and without parameter encryption enabled.

```

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

After successful key extraction using "read", the NV Index is destroyed. Therefore, to use "read" again, the "store" example must be run again as well.

## Seal / Unseal

TPM 2.0 can protect secrets using a standard Seal/Unseal procedure. Seal can be created using a TPM 2.0 key or against a set of PCR values. Note: Secret data sealed in a key is limited to a maximum size of 128 bytes.

There are two examples available: `seal/seal` and `seal/unseal`.

Demo usage is available, without parameters.

### Sealing data into a TPM 2.0 Key

Using the `seal` example we store securely our data in a newly generated TPM 2.0 key. Only when this key is loaded into the TPM, we could read back our secret data.

Please find example output from sealing and unsealing a secret message:

```
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

### Sealing data to the TPM with policy authorization

Data can also be sealed to the TPM, either to NVM or regular, with policy authorization. ./examples/seal/seal\_policy\_auth.c shows an example of how to seal data to the TPM using the wolfTPM2\_SealWithAuthKey function and unseal with wolfTPM2\_UnsealWithAuthSig. These functions call wolfTPM2\_PolicyPCR to add the PCR values to the policyDigest and TPM2\_PolicyAuthorize to sign the digest with either an ecc or rsa key. ./examples/nvram/seal\_policy\_auth\_nv.c is similar but seals to the data to NVM and uses TPM2\_PolicyAuthorizeNV to keep the policyDigest in NVM so it persists in between boots. ./examples/nvram/seal\_policy\_auth\_nv\_external.c works the same way but it shows how to use a key generated from outside wolfTPM, currently only supports ecc256 keys

```
$ ./examples/seal/seal_policy_auth -ecc -aes 16
Example for sealing data to the TPM with policy authorization
	PCR Indicies:16 
	Use Parameter Encryption: CFB
wolfTPM2_Init: success
TPM2_StartAuthSession: sessionHandle 0x3000000
Loading SRK: Storage 0x81000200 (282 bytes)
ECC template
Loaded sealBlob to 0x80000002
TPM2_StartAuthSession: sessionHandle 0x3000000
Usealed secret matches!

$ ./examples/nvram/seal_policy_auth_nv -ecc -aes 16
Example for sealing data to NV memory with policy authorization
	PCR Indicies:16 
	Use Parameter Encryption: CFB
wolfTPM2_Init: success
TPM2_StartAuthSession: sessionHandle 0x3000000
Loading SRK: Storage 0x81000200 (282 bytes)
ECC template
TPM2_StartAuthSession: sessionHandle 0x3000000
Usealed secret matches!

$ ./examples/nvram/seal_policy_auth_nv_external -ecc -aes 16
Warning: Unrecognized option: -ecc
Example for sealing data to NV memory with policy authorization
	PCR Indicies:16 
	Use Parameter Encryption: CFB
wolfTPM2_Init: success
Loading SRK: Storage 0x81000200 (282 bytes)
TPM2_StartAuthSession: sessionHandle 0x3000000
TPM2_StartAuthSession: sessionHandle 0x3000000
Usealed secret matches!
```

## GPIO Control

Some TPM 2.0 modules have extra I/O functionalities and additional GPIO that the developer could use. This extra GPIO could be used to signal other subsystems about security events or system states.

Currently, the GPIO control examples support ST33 and NPCT75x TPM 2.0 modules.

There are four examples available. Configuration using `gpio/gpio_config`.

Every example has a help option `-h`. Please consult with `gpio_config -h` about the various GPIO modes.

Once configured, a GPIO can be controlled using `gpio/gpio_set` and `gpio/gpio_read`.

Demo usage is available, when no parameters are supplied. Recommended is to use carefully selected options, because GPIO interact with the physical world.

### GPIO Config

ST33 supports 6 modes, information from `gpio/gpio_config` below:

```
$ ./examples/gpio/gpio_config -h
Expected usage:
./examples/gpio/gpio_config [num] [mode]
* num is a GPIO number between 0-3 (default 0)
* mode is a number selecting the GPIO mode between 0-6 (default 3):
	0. standard - reset to the GPIO's default mode
	1. floating - input in floating configuration.
	2. pullup   - input with pull up enabled
	3. pulldown - input with pull down enabled
	4. opendrain - output in open drain configuration
	5. pushpull  - output in push pull configuration
	6. unconfigure - delete the NV index for the selected GPIO
Example usage, without parameters, configures GPIO0 as input with a pull down.
```

Example usage for configuring a GPIO to output can be found below:

```
$ ./examples/gpio/gpio_config 0 5
GPIO num is: 0
GPIO mode is: 5
Example how to use extra GPIO on a TPM 2.0 modules
Trying to configure GPIO0...
TPM2_GPIO_Config success
NV Index for GPIO access created
```

Example usage for configuring a GPIO as input with a pull-up on ST33 can be found below:

```
$ ./examples/gpio/gpio_config 0 3
GPIO num is: 0
GPIO mode is: 3
Demo how to use extra GPIO on a TPM 2.0 modules
Trying to configure GPIO0...
TPM2_GPIO_Config success
NV Index for GPIO access created
```

### GPIO Config (NPCT75xx)

NPCT75x supports 3 output modes (no input modes), information from `gpio/gpio_config` below:

```
$ ./examples/gpio/gpio_config -h
Expected usage:
./examples/gpio/gpio_config [num] [mode]
* num is a GPIO number between 3 and 4 (default 3)
* mode is either push-pull, open-drain or open-drain with pull-up
	1. pushpull  - output in push pull configuration
	2. opendrain - output in open drain configuration
	3. pullup - output in open drain with pull-up enabled
	4. unconfig - delete NV index for GPIO access
Example usage, without parameters, configures GPIO3 as push-pull output.
```

Please note that NPCT75x GPIO numbering starts from GPIO3, while ST33 starts from GPIO0.

```
$ ./examples/gpio/gpio_nuvoton 4 1
Example for GPIO configuration of a NPTC7xx TPM 2.0 module
GPIO number: 4
GPIO mode: 1
Successfully read the current configuration
Successfully wrote new configuration
NV Index for GPIO access created
```

### GPIO Usage

Switching a GPIO configuration is seamless.
* For ST33 `gpio/gpio_config` takes care of deleting existing NV Index, so a new GPIO configuration can be chosen.
* For NPCT75xx `gpio/gpio_config` can reconfigure any GPIO without deleting the created NV index.

```
$ ./examples/gpio/gpio_set 0 -high
GPIO0 set to high level

$ ./examples/gpio/gpio_set 0 -low
GPIO0 set to low level
```

```
$ ./examples/gpio/gpio_read 0
GPIO0 is Low
```


## Support

If you need more information about using these examples please contact us at support@wolfssl.com
