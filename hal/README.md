# wolfTPM Hardware Interface Abstraction Layer (HAL) IO

A single HAL callback must be registered to handle communication to the hardware.

We distribute examples for several platforms to help with initial setup.

If using one of the builtin system provided hardware interfaces then `NULL` can be supplied for the HAL IO callback.

The available system TPM interfaces are:
* Linux `/dev/tpm0`: Enabled with `WOLFTPM_LINUX_DEV` or `--enable-devtpm`.
* Windows TBS: Enabled with `WOLFTPM_WINAPI` or `--enable-winapi`.
* Software TPM Simulator: Enabled with `WOLFTPM_SWTPM` or `--enable-swtpm`.

If using a HAL IO callback it is registered on library initialization using:
* TPM2 Native API's: `TPM2_Init`
* wolfTPM Wrappers: `wolfTPM2_Init`

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
| Xilinx | `tpm_io_xilinx.c` | `__XILINX__` |

## HAL IO Callback Function

Here are the prototypes for the HAL callback function:

```c
#ifdef WOLFTPM_ADV_IO
typedef int (*TPM2HalIoCb)(struct TPM2_CTX*, INT32 isRead, UINT32 addr,
    BYTE* xferBuf, UINT16 xferSz, void* userCtx);
#else
typedef int (*TPM2HalIoCb)(struct TPM2_CTX*, const BYTE* txBuf, BYTE* rxBuf,
    UINT16 xferSz, void* userCtx);
#endif
```

Here are example function definitions:

```c
#ifdef WOLFTPM_ADV_IO
int TPM2_IoCb(TPM2_CTX*, int isRead, word32 addr, byte* buf, word16 size,
    void* userCtx);
#else
int TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx);
#endif
```

## Additional Build options

* `WOLFTPM_CHECK_WAIT_STATE`: Enables check of the wait state during a SPI transaction. Most TPM 2.0 chips require this and typically only require 0-2 wait cycles depending on the command. Only the Infineon TPM's guarantee no wait states.
* `WOLFTPM_ADV_IO`: Enables advanced IO callback mode that includes TIS register and read/write flag. This is requires for I2C, but can be used with SPI also.
* `WOLFTPM_DEBUG_IO`: Enable logging of the IO (if using the example HAL).

## Additional Compiler macros

* `TPM2_SPI_DEV_PATH`: Set to the device string to be opened by the Linux IOCb.  Default: "/dev/spidev0."
* `TPM2_SPI_DEV_CS`: Set to the number string of the CS to use. Default: "0"

These can be set during configure as:
./configure CPPFLAGS="-DTPM2_SPI_DEV_PATH=\"/dev/spidev0.\" -DTPM2_SPI_DEV_CS=\"0\" " 

Note that autodetect will use TPM2_SPI_DEV_PATH[0..4] for the searched device paths.
