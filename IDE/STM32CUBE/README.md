# wolfTPM for STM32 Cube IDE

The wolfTPM Cube Pack can be found [here](https://www.wolfssl.com/files/ide/I-CUBE-wolfTPM.pack) and has an optional (and recommended) dependency on the `wolfCrypt` library.

1. The first step is to set up the wolfCrypt library in your ST project following the guide here [https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md](https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md). To run the wolfTPM unit tests, name the entry function `wolfTPMTest` instead of `wolfCryptDemo`.

2. Then install the wolfTPM Cube Pack in the same manner as the wolfSSL pack with CUBEMX.

3. Open the project `.ioc` file and click the `Software Packs` drop down menu and then `Select Components`. Expand the `wolfTPM` pack and check all the components.

4. In the `Software Packs` configuration category of the `.ioc` file, click on the wolfTPM pack and enable the library by checking the box.

5. In the `Connectivity` category, find and enable SPI for you project.

6. In the `Software Packs` configuration category, open the wolfTPM pack and set `Enable wolfCrypt` parameter to True.

7. Save your changes and select yes to the prompt asking about generating code.

8. Build the project and run the unit tests.

## Notes
- Make sure to make [these changes](https://github.com/wolfSSL/wolfssl/tree/master/IDE/STM32Cube#stm32-printf) to redirect the printf's to the UART.

