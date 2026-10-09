# TPM 2.0 Overview

This page describes what a TPM is, the hierarchies and PCRs that wolfTPM exposes, the terminology used in the code, and how to identify the TPM module you are talking to.

wolfTPM is a portable, open-source TPM 2.0 stack with backward API compatibility designed for embedded use. It is highly portable, due to having been written in native C, having a single IO callback for SPI hardware interface, no external dependencies, and its compacted code with low resource usage. wolfTPM offers API wrappers to help with complex TPM operations like attestation and examples to help with complex cryptographic processes like the generation of Certificate Signing Request (CSR) using a TPM.

## Protocol overview

Trusted Platform Module (TPM, also known as ISO/IEC 11889) is an international standard for a secure crypto processor, a dedicated micro controller designed to secure hardware through integrated cryptographic keys. Computer programs can use a TPM to authenticate hardware devices, since each TPM chip has a unique and secret RSA key burned in as it is produced.

A TPM provides the following:

- A random number generator.
- Facilities for the secure generation of cryptographic keys for limited uses.
- Remote attestation: Creates a nearly unforgeable hash key summary of the hardware and software configuration. The software in charge of hashing the configuration data determines the extent of the summary. This allows a third party to verify that the software has not been changed.
- Binding: Encrypts data using the TPM bind key, a unique RSA key descended from a storage key.
- Sealing: Similar to binding, but in addition, specifies the TPM state for the data to be decrypted (unsealed).

A TPM can also be used for platform integrity, disk encryption, password protection, and software license protection.

## Hierarchies

```
Platform    TPM_RH_PLATFORM
Owner       TPM_RH_OWNER
Endorsement TPM_RH_ENDORSEMENT
```

Each hierarchy has their own manufacture generated seed.

The arguments used on `TPM2_Create` or `TPM2_CreatePrimary` create a template, which is fed into a KDF to produce the same key based hierarchy used. The key generated is the same each time, even after reboot. The generation of a new RSA 2048 bit key takes about 15 seconds. Typically these are created and then stored in NV using `TPM2_EvictControl`. Each TPM generates their own keys uniquely based on the seed.

There is also an Ephemeral hierarchy (`TPM_RH_NULL`), which can be used to create ephemeral keys.

## Platform Configuration Registers (PCRs)

PCRs hold hash digests at indices 0 to 23 in banks supported and allocated by the TPM. They can be extended to prove the integrity of a boot sequence (secure boot).

## Terminology

This project uses the terms append vs. marshall and parse vs. unmarshall.

Acronyms:

* HAL: Hardware Abstraction Layer.
* NV: Non-Volatile memory.
* TPM: Trusted Platform Module.

## Device Identification

The following lines are the identification output captured from each tested module. The `Caps/Did/Vid/Rid` line comes from the TIS bus registers.

```
Infineon SLB9670:
TPM2: Caps 0x30000697, Did 0x001b, Vid 0x15d1, Rid 0x10
Mfg IFX (1), Vendor SLB9670, Fw 7.85 (4555), FIPS 140-2 1, CC-EAL4 1

Infineon SLB9672:
TPM2: Caps 0x30000697, Did 0x001d, Vid 0x15d1, Rid 0x36
Mfg IFX (1), Vendor SLB9672, Fw 16.10 (0x4068), FIPS 140-2 1, CC-EAL4 1

Infineon SLB9673:
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a), FIPS 140-2 1, CC-EAL4 1

STMicro ST33KTPM2XSPI
TPM2: Caps 0x30000415, Did 0x0003, Vid 0x104a, Rid 0x 0
Mfg STM  (2), Vendor ST33KTPM2XSPI, Fw 9.256 (0x0), FIPS 140-2 1, CC-EAL4 0

STMicro ST33TPHF2XSPI
TPM2: Caps 0x1a7e2882, Did 0x0000, Vid 0x104a, Rid 0x4e
Mfg STM  (2), Vendor , Fw 74.8 (1151341959), FIPS 140-2 1, CC-EAL4 0

STMicro ST33TPHF2XSPI (newer firmware line)
TPM2: Caps 0x30000415, Did 0x0000, Vid 0x104a, Rid 0x4e
Mfg STM  (2), Vendor , Fw 1.258 (0x0), FIPS 140-2 1, CC-EAL4 0

STMicro ST33TPHF2XI2C
TPM2: Caps 0x1a7e2882, Did 0x0000, Vid 0x104a, Rid 0x4e
Mfg STM  (2), Vendor , Fw 74.9 (1151341959), FIPS 140-2 1, CC-EAL4 0

Microchip ATTPM20
TPM2: Caps 0x30000695, Did 0x3205, Vid 0x1114, Rid 0x 1
Mfg MCHP (3), Vendor , Fw 512.20481 (0), FIPS 140-2 0, CC-EAL4 0

Nations Technologies Inc. Z32H330 TPM 2.0 module
Mfg NTZ (0), Vendor Z32H330, Fw 7.51 (419631892), FIPS 140-2 0, CC-EAL4 0

Nations Technologies Inc. NS350 TPM 2.0 module
TPM2: Caps 0x30000615, Did 0x0701, Vid 0x9999, Rid 0x 1
Mfg NSG (0), Vendor NS350, Fw 30.30 (0x24042510), FIPS 140-2 1, CC-EAL4 0

Nuvoton NPCT650 TPM2.0
Mfg NTC (0), Vendor rlsNPCT , Fw 1.3 (65536), FIPS 140-2 0, CC-EAL4 0

Nuvoton NPCT750 TPM2.0
TPM2: Caps 0x30000697, Did 0x00fc, Vid 0x1050, Rid 0x 1
Mfg NTC (0), Vendor NPCT75x"!!4rls, Fw 7.2 (131072), FIPS 140-2 1, CC-EAL4 0

SealSQ QVault TPM 2.0
TPM2: Caps 0x30000797, Did 0x0083, Vid 0x2406, Rid 0x 3
Mfg SEAL (6), Vendor QVault TPM, Fw 2.1 (0x3010303), FIPS 140-3, CC-EAL4 0

NVIDIA Jetson Orin (Tegra234) OP-TEE firmware TPM, via /dev/tpmrm0
Mfg MSFT (7), Vendor SSE fTPM, Fw 8216.1808 (0x105300), FIPS 140-2, CC-EAL4 0
```

Early ST33TPHF2X 1.x firmware reports `TPM_PT_VENDOR_STRING_1..4` as binary rather than text, so the `Vendor` field prints empty. Later 1.x firmware reports ASCII such as `ST33TPHF2XSPI`. The firmware major version identifies the line instead: 1.x and 2.x are ST33TPHF2X (SPI and I2C firmware respectively), 9.x is ST33KTPM2X and 10.x is ST33KTPM2A. See `examples/firmware/README.md` in the wolfTPM source tree for how this selects the firmware update format and command codes.

!!! note
    The NVIDIA Jetson Orin entry has no `Caps/Did/Vid/Rid` line because those values come from TIS bus registers, which a firmware TPM does not have. The entry was captured with `--enable-autodetect`, where `wolfTPM2_Init_ex` returns as soon as the kernel device opens, so the debug line is never reached. An `--enable-devtpm` build still prints it, reading all zeros. `Fw 8216.1808` is `TPM_PT_FIRMWARE_VERSION_1` = `0x20180710`, which this implementation uses to carry a build date (2018-07-10) rather than a version number. Spec revision is 1.62, and all four PCR banks (SHA-1, SHA-256, SHA-384, SHA-512) are allocated with PCRs 0 to 23.

## See Also

* [Supported Hardware](supported-hardware.md)
* [API Reference](api-reference.md)
* [Getting Started](getting-started.md)
* [Project Structure](project-structure.md)
