# HAL IO Callback

A single hardware abstraction layer (HAL) callback must be registered to handle communication to the TPM hardware. This page describes the callback, the example implementations distributed with wolfTPM, and the build options that control them.

Examples for several platforms are provided to help with initial setup. If you use one of the built-in, system-provided hardware interfaces, `NULL` can be supplied for the HAL IO callback.

The available system TPM interfaces are:

* Linux `/dev/tpm0`: enabled with `WOLFTPM_LINUX_DEV` or `--enable-devtpm`.
* Windows TBS: enabled with `WOLFTPM_WINAPI` or `--enable-winapi`.
* Software TPM simulator: enabled with `WOLFTPM_SWTPM` or `--enable-swtpm`.

If you use a HAL IO callback, it is registered on library initialization with:

* TPM2 native API: `TPM2_Init`
* wolfTPM wrappers: `wolfTPM2_Init`

## Example HAL Implementations

| Platform | Example File | Build Option |
| -------- | ------------ | ------------ |
| Atmel ASF | `tpm_io_atmel.c` | `WOLFSSL_ATMEL` |
| Barebox | `tpm_io_barebox.c` | `__BAREBOX__` |
| Infineon | `tpm_io_infineon.c` | `WOLFTPM_INFINEON_TRICORE` |
| Linux | `tpm_io_linux.c` | `__linux__` |
| Microchip | `tpm_io_microchip.c` | `WOLFTPM_MICROCHIP_HARMONY` |
| QNX | `tpm_io_qnx.c` | `__QNX__` |
| ST Cube HAL | `tpm_io_st.c` | `WOLFSSL_STM32_CUBEMX` |
| wolfHAL | `tpm_io_wolfhal.c` | `WOLFTPM_WOLFHAL` |
| Xilinx | `tpm_io_xilinx.c` | `__XILINX__` |

## wolfHAL

Enabled with `WOLFTPM_WOLFHAL` or `--enable-wolfhal`. The wolfHAL headers must be on the include path.

This HAL is placed last in the platform selection chain, so it is used only when no other platform macro is defined. For example, building for an STM32 target with the CubeMX headers present selects `tpm_io_st.c` instead.

### Board definitions

wolfTPM does not ship board definitions. `tpm_io_wolfhal.c` includes `"board.h"`, which the application provides on its include path. A wolfHAL project already has one, so in most cases only the TPM-specific entries below need to be added to it.

For SPI:

| Macro | Type | Description |
| ----- | ---- | ----------- |
| `BOARD_SPI_DEV` | `whal_Spi*` | SPI instance the TPM is connected to |
| `BOARD_SPI_COM_CFG` | `whal_Spi_ComCfg*` | SPI session parameters |
| `BOARD_GPIO_DEV` | `whal_Gpio*` | GPIO instance driving chip select |
| `BOARD_CS_PIN` | pin number | Chip select pin, driven active low |

For I2C (also requires `WOLFTPM_ADV_IO`, which `--enable-i2c` sets):

| Macro | Type | Description |
| ----- | ---- | ----------- |
| `BOARD_I2C_DEV` | `whal_I2c*` | I2C instance the TPM is connected to |
| `BOARD_I2C_COM_CFG` | `whal_I2c_ComCfg*` | I2C session parameters, including the TPM target address |

The TPM target address goes in the `addr` field of `BOARD_I2C_COM_CFG`. Most TPM 2.0 I2C parts use `0x2e`. The `TPM2_I2C_ADDR` macro that the other I2C HALs use has no effect here, so defining it is a compile-time error.

A TPM 2.0 I2C part takes roughly 80 us to wake and NAKs until it is ready, so each transfer is retried up to `TPM_I2C_TRIES` times (default 10). Define `TPM_I2C_TRIES` to override this.

A missing entry is reported at compile time, naming the macro that is required. Only the macros needed by the selected bus are checked.

Example additions to an existing wolfHAL `board.h`:

```c
/* TPM on SPI1, chip select on PA15 */
extern whal_Spi_ComCfg g_tpmSpiComCfg;
#define BOARD_SPI_COM_CFG  (&g_tpmSpiComCfg)
#define BOARD_CS_PIN       15
```

For I2C, where the session config carries the TPM address:

```c
/* board.c */
whal_I2c_ComCfg g_tpmI2cComCfg = {
    .freq   = 400000, /* Hz */
    .addr   = 0x2e,   /* TPM target address */
    .addrSz = 7,      /* bits */
};

/* board.h */
extern whal_I2c_ComCfg g_tpmI2cComCfg;
#define BOARD_I2C_COM_CFG  (&g_tpmI2cComCfg)
```

## HAL IO Callback Function

The prototypes for the HAL callback function:

```c
#ifdef WOLFTPM_ADV_IO
typedef int (*TPM2HalIoCb)(struct TPM2_CTX*, INT32 isRead, UINT32 addr,
    BYTE* xferBuf, UINT16 xferSz, void* userCtx);
#else
typedef int (*TPM2HalIoCb)(struct TPM2_CTX*, const BYTE* txBuf, BYTE* rxBuf,
    UINT16 xferSz, void* userCtx);
#endif
```

Example function definitions:

```c
#ifdef WOLFTPM_ADV_IO
int TPM2_IoCb(TPM2_CTX*, int isRead, word32 addr, byte* buf, word16 size,
    void* userCtx);
#else
int TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx);
#endif
```

## Additional Build Options

* `WOLFTPM_CHECK_WAIT_STATE`: Enables checking of the wait state during a SPI transaction. Most TPM 2.0 chips require this and typically need only 0 to 2 wait cycles depending on the command. Only the Infineon TPMs guarantee no wait states.
* `WOLFTPM_ADV_IO`: Enables advanced IO callback mode, which includes the TIS register and a read/write flag. This is required for I2C, but can be used with SPI also.
* `WOLFTPM_DEBUG_IO`: Enables logging of the IO (if using the example HAL).
* `WOLFTPM_HAL_RESET`: Optional TPM hardware reset (nRST) control in the example HAL (`--enable-hal-reset`). On Linux, `TPM2_IoCb_Reset(&dev->ctx, userCtx)` pulses nRST (active low) through the GPIO char device (raw GPIO v2 uAPI, no libgpiod).

## TPM Reset (nRST) HAL Macros

These apply when `WOLFTPM_HAL_RESET` is set.

* `WOLFTPM_RESET_GPIOCHIP`: GPIO char device. Default: `/dev/gpiochip0`.
* `WOLFTPM_RESET_LINE`: GPIO line wired to nRST. Default: ST33 uses `24` (GPIO24, Pi pin 18), Nuvoton uses `4` (GPIO4). Also settable with `--enable-hal-reset=<line>`.
* `WOLFTPM_RESET_HOLD_US` and `WOLFTPM_RESET_SETTLE_US`: reset hold time and post-reset settle time in microseconds. Defaults: `300000` and `1000000`.

## Additional Compiler Macros

* `TPM2_SPI_DEV_PATH`: The device string to be opened by the Linux IO callback. Default: `"/dev/spidev0."`.
* `TPM2_SPI_DEV_CS`: The chip select number string to use. Default: `"0"`.

These can be set during configure:

```sh
./configure CPPFLAGS="-DTPM2_SPI_DEV_PATH=\"/dev/spidev0.\" -DTPM2_SPI_DEV_CS=\"0\""
```

Autodetect uses `TPM2_SPI_DEV_PATH[0..4]` for the searched device paths.

## See Also

* [Supported Hardware](supported-hardware.md)
* [TPM 2.0 Overview](tpm2-overview.md)
