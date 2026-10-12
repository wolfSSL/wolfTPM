# STM32CubeIDE

wolfTPM is available as an STM32 Cube Pack, `I-CUBE-wolfTPM.pack`, downloadable from https://www.wolfssl.com/files/ide/I-CUBE-wolfTPM.pack. The pack has an optional but recommended dependency on the wolfCrypt library. The files live in `IDE/STM32CUBE` in the wolfTPM source tree.

!!! note
    This page is short and will be expanded later.

## Setup

1. Set up the wolfCrypt library in your ST project by following the wolfSSL STM32Cube guide: https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md. To run the wolfTPM unit tests, name the entry function `wolfTPMTest` instead of `wolfCryptDemo`.
2. Install the wolfTPM Cube Pack in the same way as the wolfSSL pack, using CubeMX.
3. Open the project `.ioc` file, click the `Software Packs` drop-down menu, then `Select Components`. Expand the `wolfTPM` pack and check all the components.
4. In the `Software Packs` configuration category of the `.ioc` file, click the wolfTPM pack and enable the library by checking the box.
5. In the `Connectivity` category, find and enable SPI for your project.
6. In the `Software Packs` configuration category, open the wolfTPM pack and set the `Enable wolfCrypt` parameter to True.
7. Save your changes and answer yes to the prompt asking about generating code.
8. Build the project and run the unit tests on the target.

## Notes

Redirect `printf` to the UART so the test output is visible. See the [STM32 printf changes](https://github.com/wolfSSL/wolfssl/tree/master/IDE/STM32Cube#stm32-printf) in the wolfSSL guide.

## See Also

- [Building](building.md), for the bare-metal build options
- [System Interfaces](system-interfaces.md), for the SWTPM over UART example on STM32H5
- [Embedded Integrations](embedded-integrations.md)
