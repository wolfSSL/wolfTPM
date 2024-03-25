# TPM Firmware Update Support

Currently wolfTPM supports firmare update capability for the Infineon SLB9672 (SPI) and SLB9673 (I2C) TPM 2.0 modules. Infienon has open sourced their firmware update.

## Infineon Firmware

### Extracting the firmware

Infienon releates firmware as a .bin file (example: TPM20_15.23.17664.0_R1.BIN).

The .bin contains a 16-byte GUID header, at least one manifest based on key group and the firmware. A typical manifest is 3KB and firmware is 920KB.

We have included a host side tool `ifx_fw_extract` for extracting the manifest and firmware data file required for a TPM upgrade.

Example usage:

```sh
make
./ifx_fw_extract --help
Usage:
  ifx_fw_extract <fw-file>
  ifx_fw_extract <fw-file> <keygroup_id> <manifest-file> <data-file>

# Find key groups in .bin
./ifx_fw_extract TPM20_15.23.17664.0_R1.BIN
Reading TPM20_15.23.17664.0_R1.BIN
Found group 00000004

# Extract manifest and firmware data files for key group
./ifx_fw_extract TPM20_15.23.17664.0_R1.BIN 00000004 TPM20_15.23.17664.0_R1.MANIFEST TPM20_15.23.17664.0_R1.DATA
Reading TPM20_15.23.17664.0_R1.BIN
Found group 00000004
Chosen group found: 00000004
Manifest size is 3236
Data size is 919879
Writing TPM20_15.23.17664.0_R1.MANIFEST
Writing TPM20_15.23.17664.0_R1.DATA
```

### Updating the firmware

The `ifx_fw_update` tool uses the manifest (header) and firmware data file.

The TPM has a vendor capability for getting the key group id. This is populated in the `WOLFTPM2_CAPS.keyGroupId` when `wolfTPM2_GetCapabilities` is called. This value should match the firmware extract tool `keygroup_id`.

```sh
./ifx_fw_update --help
Infineon Firmware Update Usage:
        ./ifx_fw_update (get info)
        ./ifx_fw_update --abandon (cancel)
        ./ifx_fw_update <manifest_file> <firmware_file>

# Run without arguments to display the current firmware information including key group id and operational mode
./ifx_fw_update
Infineon Firmware Update Tool
Mfg IFX (1), Vendor SLB9672, Fw 16.10 (0x4068), KeyGroupId 0x5, OpMode 0x4
Manifest file or firmware file arguments missing!

# Run with manifest and firmware files
./ifx_fw_update TPM20_15.23.17664.0_R1.MANIFEST TPM20_15.23.17664.0_R1.DATA

```
