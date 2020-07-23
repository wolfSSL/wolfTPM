# Quote & Attestation Demo

This folder contains examples for performing local attestation. You will learn how to measure a system file using wolfTPM and then generate a TPM 2.0 Quote as proof for that measurement. See [Technology Introduction](## Technology introduction) below.

## List of examples

The `./examples/pcr/` folder contains tools for working with Platform Configuration Registers (PCR). It is recommended to build wolfTPM with debug output enabled using `./configure --enable-debug` before `make` to see more logging output. There are example scripts to show using these PCR examples.

Examples:

* `./examples/pcr/reset`: Used to clear the content of a PCR (restrictions apply, see below)
* `./examples/pcr/extend`: Used to modify the content of a PCR (extend is a cryptographic operation, see below)
* `./examples/pcr/quote`: Used to generate a TPM2.0 Quote structure containing the PCR digest and TPM-generated signature

Scripts:

* `./examples/pcr/demo.sh` - script demonstrating the tools above
* `./examples/pcr/demo-quote-zip.sh` - script demonstrating how using the tools above a system file can be measured and a TPM-signed proof with that measurement generated


## Technology introduction

### Platform Configuration Registers (PCR)

PCRs in TPM2.0 are special registers that allow only one type of write operations to be performed on them. A TPM 2.0 extend operation is the only way to update a PCR.

At power-up, the TPM resets all PCRs to their default state (all zeros or all ones, depending on the PCR). From this state, the TPM can generate the same PCR value only if the PCR is extended with the same hash digest. In case of multiple values(multiple extend operations), the values must be supplied in the correct order, otherwise the final PCR value would differ.

For example, doing a measured boot under Linux would generate the same PCR digest, if the kernel is the same at every boot. However, loading the same (A) Linux kernel, (B) initrd image and (C) configuration file would generate the same PCR digest only when the order of extend operations is consistent (for example, A-B-C). It does not matter which extend operation is first or last as long as the order is kept the same. For example, C-B-A would result in a reproducible digest, but it would differ from the A-B-C digest.

### Reset

Not all PCRs are equal. The user can perform `extend` operation on all PCRs, but the user can `reset` only on one of them during normal runtime. This is what makes PCRs so useful.

* PCR0-15 are reset at boot and can be cleared again(reset) only from reboot cycle.
* PCR16 is a PCR for debug purposes. This is the PCR used by all tools above by default. It is safe to test and work with PCR16.
* PCR17-22 are reserved for Dynamic Root of Trust Measurement (DRTM), an advanced topic that is to be covered separately.

### Extend

The TPM 2.0 `TPM2_Extend` API uses a SHA1 or SHA256 cryptographic operation to combine the current value of the PCR and with newly provided hash digest.

### Quote

The TPM 2.0 `TPM2_Quote` API is a standard operation that encapsulates the PCR digest in a TCG defined structure called `TPMS_ATTEST` together with TPM signature. The signature is produced from a TPM generated key called Attestation Identity Key (AIK) that only the TPM can use. This provides guarantee for the source of the Quote and PCR digest. Together, the Quote and PCR provide the means for system measurement and integrity.

## Example Usage

### Reset Example Usage

```sh
$ ./examples/pcr/reset -?
PCR index is out of range (0-23)
Expected usage:
./examples/pcr/reset [pcr]
* pcr is a PCR index between 0-23 (default 16)
Demo usage without parameters, resets PCR16.
```

### Extend Example Usage

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

### Quote Example Usage

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

## Typical demo output

All PCR examples can be used without arguments. This is the output of the `./examples/pcr/demo.sh` script:

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

As expected, the PCR16 content is now set back to all zeroes. From this moment on we can generate predictable PCR digests(values) for system measurement. Similar to using PCR7 after boot, because PCR7 is reset at system boot. Using PCR16 allows us to skip system reboots and test safely.

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

Based on the old content of the PCR (all zeros) and the provided hash (SHA256 32-byte digest), the PCR gets its new value printed at the end of the `extend` example. This value will always be the same, if `reset` is launched before `extend`. To pass custom hash digest, the `extend` tool accepts PCR index as first argument(recommended to use 16 for PCR16) and user file as second argument.

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
    6e 2d 9f 9e 5a 86 4f 11 fe 13 84 94 cf 05 b9 d5 | n-..Z.O.........
    eb 5a 34 39 b2 a5 7a 5f 52 c0 f4 e7 2b 70 b7 62 | .Z49..z_R...+p.b
    6a fe 79 4e 2e 46 2e 43 d7 1c ef 2c 14 21 11 14 | j.yN.F.C...,.!..
    95 01 93 a9 85 0d 02 c7 b2 f8 75 1a bd 59 da 56 | ..........u..Y.V
    cc 43 e3 d2 aa 14 49 2a 59 26 09 9e c9 4b 1a 66 | .C....I*Y&...K.f
    cb 77 65 95 79 69 89 bd 46 46 13 3d 2c a9 78 f8 | .we.yi..FF.=,.x.
    2c ab 8a 4a 6b f2 97 67 86 37 f8 f6 9d 85 cd cf | ,..Jk..g.7......
    a4 ae c6 d3 cf c1 63 92 8c 7b 88 79 90 54 0a ba | ......c..{.y.T..
    8d c6 1c 8f 6e 6d 61 bc a9 2f 35 b0 1a 46 74 9a | ....nma../5..Ft.
    e3 7d 39 33 52 1a f5 4b 07 8d 30 53 75 b5 68 40 | .}93R..K..0Su.h@
    04 e7 a1 fc b1 93 5d 1e bc ca f4 a9 fa 75 d3 f6 | ......]......u..
    3d 4a 5b 07 23 0e f0 f4 1f 97 23 76 1a ee 66 93 | =J[.#.....#v..f.
    cd fd 9e 6f 2b d3 95 c5 51 cf f6 81 5b 97 a1 d2 | ...o+...Q...[...
    06 45 c0 30 70 ad bd 36 66 9f 95 af 60 7c d5 a2 | .E.0p..6f...`|..
```

Before producing a TPM-signed structure containing the PCR measurement, the quote example starts by creating an Endorsement Key(EK) that is required for the TPM to operate. It serves essentially as the primary key for all other keys. Next, a Storage Key(SRK) is generated and under that SRK a special Attestation Identity Key(AIK) is added. Using the AIK the TPM can sign the quote structure.

## Steps for measuring a system file (performing local attestation)

A system administrator wants to make sure the zip tool of an user is genuine (legitimate software, correct version and has not been tampered with). To do this, the SysAdmin resets PCR16 and can afterwards generate a PCR digest based on the zip binary that can be used for future references if the file has been modified.

This is the output from `./examples/pcr/demo-quote-zip.sh` script.

```sh
$ ./examples/pcr/reset 16
...
Trying to reset PCR16...
TPM2_PCR_Reset success
...
```

This is a good known initial state of the PCR. By using the `extend` tool the SysAdmin feeds the `/usr/bin/zip` binary to wolfCrypt for SHA256 hash computation, which then is used by wolfTPM to issue a `TPM2_Extend` operation in PCR16.

```sh
$ ./examples/pcr/extend 16 /usr/bin/zip
...
TPM2_PCR_Extend success
PCR16 digest:
    2b bd 54 ae 08 5b 59 ef 90 42 d5 ca 5d df b5 b5 | +.T..[Y..B..]...
    74 3a 26 76 d4 39 37 eb b0 53 f5 82 67 6f b4 aa | t:&v.97..S..go..
```

Once the extend operation is finished, the SysAdmin wants to create a TPM2.0 Quote as proof of the measurement in PCR16.

```sh
$ ./examples/pcr/quote 16 zip.quote
...
TPM2_Quote: success
TPM with signature attests (type 0x8018):
    TPM signed 1 count of PCRs
...
```

The result of the TPM2.0 Quote operation is saved in the `zip.quote` binary file. The `TPMS_ATTEST` structure of TPM 2.0 Quote contains also useful clock and time information. For more about the TPM time attestation please check the `./examples/timestamp/signed_timestamp` example.
