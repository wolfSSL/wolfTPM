# TPM Firmware Update Support

Current support is for Infineon SLB9672 (SPI) and SLB9673 (I2C) TPM 2.0 modules only. Infienon has open sourced their firmware update.

## Infineon Firmware

The firmware files released from Infienon come in a single .bin (example: TPM20_15.23.17664.0_R1.BIN).

This .bin contains a 16-byte GUID header, at least one manifest based on key group and the firmware. A typical manifest is 3KB and firmware is 920KB.

We have included a host side tool `ifx_fw_extract` for extracting the manifest and firmware data file required for a TPM upgrade.

Example usage:

```sh
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

./ifx_fw_update --help

./ifx_fw_update TPM20_15.23.17664.0_R1.MANIFEST TPM20_15.23.17664.0_R1.DATA
```


There is a TPM vendor command for getting the key group id(s). See `tpm2_ifx_firmware_dumpinfo`.

