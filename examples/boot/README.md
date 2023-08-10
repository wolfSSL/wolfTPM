# Secure Boot Root-of-Trust (ROT)

Design for storage of public key based root of trust into TPM:

1) Use AES-CFB parameter encryption for all communication (salted and bound)
2) Derive a password based on unique device parameters used as "auth" to load NV (authenticate)
3) The NV contains a hash of the public key (hash matches .config setting)
4) WolfBoot still has the public key internally and programs the TPM with the NV if not populated.
5) The NV is locked and created under the platform hierarchy

Exammple:

```
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

# Secure Boot Encryption Key Storage

TODO:
* Sealing based on PCR's and key?
* RSA encrypt/decrypt?
