/** @defgroup wolfTPM2_Wrappers wolfTPM2 Wrappers
 *
 * This module describes the rich API of wolfTPM called wrappers.
 *
 * wolfTPM wrappers are used in two main cases:
 * * Perform common TPM 2.0 tasks, like key generation and storage
 * * Perform complex TPM 2.0 tasks, like attestation and parameter encryption
 *
 * wolfTPM enables quick and rapid use of TPM 2.0 thanks to its many wrapper functions.
 *
 */

/** @defgroup TPM2_Proprietary TPM2 Proprietary
 *
 * This module describes TPM2 commands specific only to wolfTPM.
 *
 * Typically, these commands include helpers for handling TPM 2.0 data structures.
 *
 * There are also functions to help debugging and testing during development.
 *
 */

/** @defgroup TPM2_Standard TPM2 Standard Commands
 *
 * wolfTPM has support for all TPM 2.0 Commands as defined in the TCG specification.
 *
 * wolfTPM has internal TIS layer to enable communication with a TPM 2.0 on every system:
 * * Baremetal
 * * RTOS
 * * Windows systems
 * * Hybrid SoC
 * * Linux using /dev/tpm0
 * * Linux using devspi
 * * Linux using i2c driver
 *
 * Typically, a wolfTPM developer would use the wolfTPM2 wrappers for quicker development.
 *
 * If you want to use TPM 2.0 Commands directly See tpm2.h under Files -> File List above.
 *
 */

/** @defgroup TPM2_IO wolfTPM2 IO HAL Callbacks
 *
 * This module describes the available example TPM 2.0 IO HAL Callbacks in wolfTPM
 *
 * wolfTPM uses a single IO callback function.
 * This allows the TPM 2.0 stack to be highly portable.
 * These IO Callbacks are working examples for various embedded platforms and operating systems.
 *
 * Here is a non exhaustive list of the existing TPM 2.0 IO Callbacks
 * * ST Micro STM32, through STM32 CubeMX HAL
 * * Native Linux (/dev/tpm0)
 * * Linux through spidev without kernel driver thanks to wolfTPM own TIS layer
 * * Linux through i2c without kernel driver thanks to wolfTPM own TIS layer
 * * Native Windows
 * * Atmel MCUs
 * * Xilinx Zynq
 * * Barebox
 * * QNX
 *
 * Using custom IO Callback is always possible.
 *
 */
