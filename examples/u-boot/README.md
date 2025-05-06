# wolfTPM Support For Das U-boot

wolfTPM provides experimental support for U-Boot with the following key features:

- Utilizes SOFT SPI driver in U-Boot for TPM communication
- Implements TPM 2.0 driver functionality through its internal TIS layer
- Provides native API access to all TPM 2.0 commands
- Includes wrapper API for common TPM 2.0 operations
- Supports two integration paths:
  - `__linux__`: Uses existing tpm interface via tpm2_linux.c
  - `__UBOOT__`: Direct SPI communication through tpm_io_uboot.c

## wolfTPM U-Boot Commands

The following commands are available through the `wolftpm` interface:

### Basic Commands

- `help` - Show help text
- `device [num device]` - Show all devices or set the specified device
- `info` - Show information about the TPM
- `state` - Show internal state from the TPM (if available)
- `autostart` - Initialize the TPM, perform a Startup(clear) and run a full selftest sequence
- `init` - Initialize the software stack (must be first command)
- `startup <mode> [<op>]` - Issue a TPM2_Startup command
  - `<mode>`: TPM2_SU_CLEAR (reset state) or TPM2_SU_STATE (preserved state)
  - `[<op>]`: optional shutdown with "off"
- `self_test <type>` - Test TPM capabilities
  - `<type>`: "full" (all tests) or "continue" (untested tests only)

### PCR Operations

- `pcr_extend <pcr> <digest_addr> [<digest_algo>]` - Extend PCR with digest
- `pcr_read <pcr> <digest_addr> [<digest_algo>]` - Read PCR to memory
- `pcr_allocate <algorithm> <on/off> [<password>]` - Reconfig PCR bank algorithm
- `pcr_setauthpolicy | pcr_setauthvalue <pcr> <key> [<password>]` - Change PCR access key
- `pcr_print` - Print current PCR state

### Security Management

- `clear <hierarchy>` - Issue TPM2_Clear command
  - `<hierarchy>`: TPM2_RH_LOCKOUT or TPM2_RH_PLATFORM
- `change_auth <hierarchy> <new_pw> [<old_pw>]` - Change hierarchy password
  - `<hierarchy>`: TPM2_RH_LOCKOUT, TPM2_RH_ENDORSEMENT, TPM2_RH_OWNER, or TPM2_RH_PLATFORM
- `dam_reset [<password>]` - Reset internal error counter
- `dam_parameters <max_tries> <recovery_time> <lockout_recovery> [<password>]` - Set DAM parameters
- `caps` - Show TPM capabilities and info

### Firmware Management

- `firmware_update <manifest_addr> <manifest_sz> <firmware_addr> <firmware_sz>` - Update TPM firmware
- `firmware_cancel` - Cancel TPM firmware update

## Enabling wolfTPM in U-Boot

Enable wolfTPM support in U-Boot by adding these options to your board's defconfig:

```
CONFIG_TPM=y
CONFIG_TPM_V2=y
CONFIG_TPM_WOLF=y
CONFIG_CMD_WOLFTPM=y
```

Or use `make menuconfig` and enable:
- Device Drivers → TPM → TPM 2.0 Support
- Device Drivers → TPM → wolfTPM Support
- Command line interface → Security commands → Enable wolfTPM commands

## Building and Running wolfTPM with U-Boot using QEMU

To build and run wolfTPM with U-Boot using QEMU and a tpm simulator, follow these steps:

1. Install swtpm:
```
git clone git@github.com:stefanberger/swtpm.git
cd swtpm
./autogen.sh
make
```

2. Build U-Boot:
```
make distclean
export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=aarch64
make qemu_arm64_defconfig
make -j4
```

3. Create TPM directory:
```
mkdir -p /tmp/mytpm1
```

4. Start swtpm (in first terminal):
```
swtpm socket --tpm2 --tpmstate dir=/tmp/mytpm1 --ctrl type=unixio,path=/tmp/mytpm1/swtpm-sock --log level=20
```

5. Start QEMU (in second terminal):
```
qemu-system-aarch64 -machine virt -nographic -cpu cortex-a57 -bios u-boot.bin -chardev socket,id=chrtpm,path=/tmp/mytpm1/swtpm-sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis-device,tpmdev=tpm0
```

6. Example output:

```
U-Boot 2025.07-rc1-ge15cbf232ddf-dirty (May 06 2025 - 16:25:56 -0700)

DRAM:  128 MiB
using memory 0x46658000-0x47698000 for malloc()
Core:  52 devices, 15 uclasses, devicetree: board
Flash: 64 MiB
Loading Environment from Flash... *** Warning - bad CRC, using default environment

In:    serial,usbkbd
Out:   serial,vidconsole
Err:   serial,vidconsole
No USB controllers found
Net:   eth0: virtio-net#32

Hit any key to stop autoboot:  0
=> tpm2 help
tpm2 - Issue a TPMv2.x command

Usage:
tpm2 <command> [<arguments>]

device [num device]
    Show all devices or set the specified device
info
    Show information about the TPM.
```

7. Example commands:

```
=> tpm2 info
tpm_tis@0 v2.0: VendorID 0x1014, DeviceID 0x0001, RevisionID 0x01 [open]
=> tpm2 startup TPM2_SU_CLEAR
=> tpm2 get_capability 0x6 0x20e 0x200 1
Capabilities read from TPM:
Property 0x6a2e45a9: 0x6c3646a9
=> tpm2 pcr_read 10 0x100000
PCR #10 sha256 32 byte content (20 known updates):
 20 25 73 0a 00 56 61 6c 75 65 3a 0a 00 23 23 20
 4f 75 74 20 6f 66 20 6d 65 6d 6f 72 79 0a 00 23
```

8. Exiting the QEMU:
Press Ctrl-A followed by X
