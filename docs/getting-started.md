# Getting Started

wolfTPM is a portable TPM 2.0 library with a native API, a wrapper API, and a set of example applications that come ready to use after a successful build. The examples demonstrate features of a TPM 2.0 module and create RSA and ECC keys in NV storage for testing, using the handles defined in `examples/tpm_test.h`. This page covers the shortest path from a fresh checkout to a first working example.

## Prerequisites and building wolfSSL

wolfTPM needs wolfSSL (wolfCrypt) built with the wolfTPM options. Build and install wolfSSL first:

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm
make
sudo make install
sudo ldconfig
```

`autogen.sh` requires automake and libtool: `sudo apt-get install automake libtool`.

See [Building wolfTPM](building.md) for using a wolfSSL installed in a different directory.

## Build wolfTPM

```bash
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM
./autogen.sh
./configure
make
```

!!! note
    On Linux x86_64 and aarch64, a bare `./configure` automatically enables the software TPM backends (swTPM and fwTPM). This lets `make check` run without any TPM hardware attached. Selecting a hardware path, such as `--enable-devtpm` or `--enable-autodetect`, turns this default off. See [System Interfaces](system-interfaces.md).

For hardware specific build steps, see [Supported Hardware](supported-hardware.md).

## Run your first example

The simplest example reads the TPM capabilities and searches for persistent handles:

```
./examples/wrap/caps
TPM2 Get Capabilities
wolfSSL Entering wolfCrypt_Init
Mfg NSG (0), Vendor NS350, Fw 30.30 (0x24042510), FIPS 140-2 1, CC-EAL4 0
Found 2 persistent handles
```

The output shows the manufacturer and firmware details of your TPM, so it will differ on other modules.

Other examples go further. `./examples/native/native_test` calls the native `TPM2_*` APIs directly (startup, self test, random numbers, hashing, PCR operations, and more). The PKCS #7 and TLS examples require generating CSRs and signing them with a test script. See `examples/README.md` in the source tree for details.

To use parameter encryption in the examples, pass `-aes` for AES-CFB mode or `-xor` for XOR mode. Only some TPM commands and responses support parameter encryption.

!!! note
    To run the TLS server and client on the same machine, build with `WOLFTPM_TIS_LOCK` (`--enable-tislock`) to enable concurrent access protection.

## See Also

- [Building wolfTPM](building.md)
- [Build Options](build-options.md)
- [Supported Hardware](supported-hardware.md)
- [System Interfaces](system-interfaces.md)
