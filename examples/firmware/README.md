# TPM Firmware Update Support

Currently wolfTPM supports firmware update capability for the Infineon SLB9672 (SPI) and SLB9673 (I2C) TPM 2.0 modules. Infineon has open sourced their firmware update.

## Infineon Firmware

### Extracting the firmware

Infineon releases firmware as a .bin file (example: TPM20_15.23.17664.0_R1.BIN).

The .bin contains a 16-byte GUID header, at least one manifest based on key group and the firmware. A typical manifest is 3KB and firmware is 920KB.

We have included a host side tool `ifx_fw_extract` for extracting the manifest and firmware data file required for a TPM upgrade.

Example usage:

```sh
# Build host tool
make

# Help
./ifx_fw_extract --help
Usage:
  ifx_fw_extract <fw-file>
  ifx_fw_extract <fw-file> <keygroup_id> <manifest-file> <data-file>

# Find key groups in .bin
./ifx_fw_extract TPM20_26.13.17770.0_R1.BIN
Reading TPM20_26.13.17770.0_R1.BIN
Found group 00000007

# Extract manifest and firmware data files for key group
./ifx_fw_extract TPM20_26.13.17770.0_R1.BIN 7 TPM20_26.13.17770.0_R1.MANIFEST TPM20_26.13.17770.0_R1.DATA
Reading TPM20_26.13.17770.0_R1.BIN
Found group 00000007
Chosen group found: 00000007
Manifest size is 3224
Data size is 934693
Writing TPM20_26.13.17770.0_R1.MANIFEST
Writing TPM20_26.13.17770.0_R1.DATA
```

### Updating the firmware

The `ifx_fw_update` tool uses the manifest (header) and firmware data file.

The TPM has a vendor capability for getting the key group id. This is populated in the `WOLFTPM2_CAPS.keyGroupId` when `wolfTPM2_GetCapabilities` is called. This value should match the firmware extract tool `keygroup_id`.

```sh
# Help
./ifx_fw_update --help
Infineon Firmware Update Usage:
        ./ifx_fw_update (get info)
        ./ifx_fw_update --abandon (cancel)
        ./ifx_fw_update <manifest_file> <firmware_file>

# Run without arguments to display the current firmware information including key group id and operational mode
./ifx_fw_update
Infineon Firmware Update Tool
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
TPM2_Startup pass
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a)
Operational mode: Normal TPM operational mode (0x0)
KeyGroupId 0x7, FwCounter 1254 (255 same)

# Run with manifest and firmware files
./ifx_fw_update TPM20_26.13.17770.0_R1.MANIFEST TPM20_26.13.17770.0_R1.DATA
Infineon Firmware Update Tool
	Manifest File: TPM20_26.13.17770.0_R1.MANIFEST
	Firmware File: TPM20_26.13.17770.0_R1.DATA
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
TPM2_Startup pass
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a)
Operational mode: Normal TPM operational mode (0x0)
KeyGroupId 0x7, FwCounter 1254 (255 same)
TPM2_StartAuthSession: handle 0x3000000, algorithm NULL
TPM2_FlushContext: Closed handle 0x3000000
TPM2_StartAuthSession: handle 0x3000000, algorithm NULL
Firmware manifest chunk 1024 offset (0 / 3224), state 1
Firmware manifest chunk 1024 offset (1024 / 3224), state 2
Firmware manifest chunk 1024 offset (2048 / 3224), state 2
Firmware manifest chunk 152 offset (3072 / 3224), state 0
Firmware data chunk offset 0
Firmware data chunk offset 1024
Firmware data chunk offset 2048
Firmware data chunk offset 3072
...
Firmware data chunk offset 932864
Firmware data chunk offset 933888
Firmware data done
Mfg IFX (1), Vendor , Fw 0.0 (0x0)
Operational mode: After finalize or abandon, reboot required (0x4)
KeyGroupId 0x7, FwCounter 1253 (254 same)
TPM2_Shutdown failed 304: Unknown

# Reset or power cycle TPM
./ifx_fw_update
Infineon Firmware Update Tool
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
TPM2_Startup pass
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a)
Operational mode: Normal TPM operational mode (0x0)
KeyGroupId 0x7, FwCounter 1253 (254 same)
```
