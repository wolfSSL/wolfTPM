# Management and GPIO

This page covers the small TPM management utilities in `examples/management/` and the GPIO control examples in `examples/gpio/`.

## Management utilities

| Program | Purpose |
|---------|---------|
| `da_check.c` | Dictionary attack (DA) lockout check. Exercises a DA-protected key and a noDA key, enters lockout with repeated bad authorization, and recovers with a lockout reset. |
| `flush.c` | Flushes transient and persistent handles. Run with a handle (for example `0x80000000`) to free that object; with no parameters it flushes common transient objects (transient keys, policy sessions and HMAC sessions). |
| `tpmclear.c` | Runs `TPM2_Clear` to clear a hierarchy. |

```sh
./examples/management/da_check
./examples/management/flush [handle]
./examples/management/tpmclear
```

!!! warning
    `tpmclear` clears the TPM. Keys and data held under the cleared hierarchy are lost.

## GPIO control

Some TPM 2.0 modules have extra I/O functions and additional GPIO that a developer can use. The extra GPIO can signal other subsystems about security events or system states.

!!! note
    The GPIO control examples support only ST33 and NPCT75x TPM 2.0 modules.

There are three programs in `examples/gpio/`:

| Program | Purpose |
|---------|---------|
| `gpio_config.c` | Configures a GPIO. |
| `gpio_set.c` | Sets a configured GPIO high or low. |
| `gpio_read.c` | Reads the level of a configured GPIO. |

Every example has a help option `-h`. Run `gpio_config -h` to see the GPIO modes. Demo usage runs when no parameters are supplied. Choose options carefully, because GPIO interact with the physical world.

### GPIO config (ST33)

ST33 supports 6 modes. Help output from `gpio_config`:

```sh
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

Configure a GPIO as an output:

```sh
$ ./examples/gpio/gpio_config 0 5
GPIO num is: 0
GPIO mode is: 5
Example how to use extra GPIO on a TPM 2.0 modules
Trying to configure GPIO0...
TPM2_GPIO_Config success
NV Index for GPIO access created
```

Configure a GPIO as an input with a pull down (mode 3):

```sh
$ ./examples/gpio/gpio_config 0 3
GPIO num is: 0
GPIO mode is: 3
Demo how to use extra GPIO on a TPM 2.0 modules
Trying to configure GPIO0...
TPM2_GPIO_Config success
NV Index for GPIO access created
```

### GPIO config (NPCT75xx)

NPCT75x supports 3 output modes and no input modes. Help output from `gpio_config`:

```sh
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

NPCT75x GPIO numbering starts from GPIO3, while ST33 starts from GPIO0.

```sh
$ ./examples/gpio/gpio_config 4 1
Example for GPIO configuration of a NPTC7xx TPM 2.0 module
GPIO number: 4
GPIO mode: 1
Successfully read the current configuration
Successfully wrote new configuration
NV Index for GPIO access created
```

### GPIO usage

Switching a GPIO configuration works as follows:

- For ST33, `gpio_config` deletes the existing NV index, so a new GPIO configuration can be chosen.
- For NPCT75xx, `gpio_config` can reconfigure any GPIO without deleting the created NV index.

Once configured, set and read the GPIO:

```sh
$ ./examples/gpio/gpio_set 0 -high
GPIO0 set to high level

$ ./examples/gpio/gpio_set 0 -low
GPIO0 set to low level

$ ./examples/gpio/gpio_read 0
GPIO0 is Low
```

## See Also

- [Sealing and NVRAM](sealing-and-nvram.md)
- [TLS and certificates](tls-and-certificates.md)
- [Firmware update](firmware-update.md)
- [Supported hardware](supported-hardware.md)
