# wolfTPM with Software Simulator (SWTPM) support

wolfTPM is to be able to use Software TPM (SW TPM) defined by section D.3 of [TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code.pdf)

Software TPM implementations tested:
* [Official TCG Reference](https://github.com/TrustedComputingGroup/TPM): Reference code from the specification maintained by TCG [build steps](#tcg-tpm)
* [IBM (ibmswtpm2) / Ken Goldman](https://github.com/kgoldman/ibmswtpm2): Fork of reference code maintained by IBM (93% identical to official TCG) [build steps](#ibmswtpm2)
* [Microsoft - ms-tpm-20-ref](https://github.com/microsoft/ms-tpm-20-ref): Fork of reference code maintained by Microsoft (100% identical to official TCG) [build steps](#ms-tpm-20-ref)
* [libtpms/swtpm - Stefan Berger](https://github.com/stefanberger/swtpm): Uses libtpms front end interfaces. [build steps](#swtpm)

The software TPM transport is a socket connection by default, but we also support a UART.

This implementation only uses the TPM command interface typically on port 2321. It does not support the Platform interface typically on port 2322.

## wolfTPM SWTPM support

To enable the socket transport for SWTPM use `--enable-swtpm`. By default all software TPM simulators use TCP port 2321.

```sh
./configure --enable-swtpm
make
```

Note: It is not possible to enable more than one transport interface at a time. If building with SWTPM socket interface the built-in TIS and devtpm (/dev/tpm0) interfaces are not available.

Build Options:

* `WOLFTPM_SWTPM`: Use socket transport (no TIS layer)
* `TPM2_SWTPM_HOST`: The socket host (default is localhost)
* `TPM2_SWTPM_PORT`: The socket port (default is 2321)

## wolfTPM SWTPM UART support

To use the SWTPM protocol over a UART serial connection (instead of TCP sockets), use `--enable-swtpm=uart`. This is intended for communicating with a firmware TPM (fwTPM) running on an embedded target such as the wolfTPM fwTPM server on STM32H5.

```sh
./configure --enable-swtpm=uart
make
```

The serial device path and baud rate can be set at compile time or runtime:

```sh
# Runtime override via environment variable
TPM2_SWTPM_HOST=/dev/ttyACM0 ./examples/wrap/caps
```

Build Options:

* `WOLFTPM_SWTPM_UART`: Use UART serial transport (set automatically by `--enable-swtpm=uart`)
* `TPM2_SWTPM_HOST`: The serial device path (default is `/dev/ttyACM0` on Linux, `/dev/cu.usbmodem` on macOS). Can be overridden at runtime via the `TPM2_SWTPM_HOST` environment variable.
* `TPM2_SWTPM_PORT`: The baud rate (default is 115200)

The UART transport uses the same mssim protocol as the socket transport. The serial port is configured as 8N1 raw mode with no flow control. Unlike the socket transport, the serial port file descriptor is kept open across commands (no reconnect per command).

#### Security note: environment variable override

The `TPM2_SWTPM_HOST` environment variable is a development convenience that overrides the compile-time serial device path. On systems where untrusted local users share the environment with the TPM client, an attacker could redirect TPM I/O to a rogue device (e.g. a PTY they control). For production / hardened deployments:

* Unset `TPM2_SWTPM_HOST` in the process environment, and
* Rely on the compile-time default (set via `TPM2_SWTPM_HOST` as a build `-D` macro) to pin the serial path.

The same guidance applies to `TPM2_SWTPM_PORT` (baud rate) and, for the socket transport, to using the env var to redirect the TCP host.

### Example: wolfTPM fwTPM on STM32H5

The wolfTPM project includes a firmware TPM server port for STM32 Cortex-M33 targets with TrustZone support. See [wolftpm-examples/STM32/fwtpm-stm32h5](https://github.com/wolfSSL/wolftpm-examples/pull/1) for build, flash, and test instructions.

```sh
# Build host client with UART transport
./configure --enable-swtpm=uart
make

# Run examples against STM32 fwTPM (adjust device path as needed)
export TPM2_SWTPM_HOST=/dev/ttyACM0
./examples/wrap/caps
./examples/keygen/keygen -ecc
./examples/seal/seal
```

## Using a SWTPM

### SWTPM Power Up and Startup

The TCG TPM and Microsoft ms-tpm-20-ref implementations require sending power up and startup commands on the platform interface before the command interface is enabled. You can use these commands to issue the required power up and startup:

```sh
echo -ne "\x00\x00\x00\x01" | nc 127.0.0.1 2322
echo -ne "\x00\x00\x00\x0B" | nc 127.0.0.1 2322
```

### TCG TPM

```sh
clone git@github.com:TrustedComputingGroup/TPM.git
cd TPM
cd TPMCmd
./bootstrap
./configure
make
```

Run with: `./Simulator/src/tpm2-simulator`

Run power on and self test. See [SWTPM Power Up and Startup](#swtpm-power-up-and-startup).

### ibmswtpm2

Build steps:

```sh
git clone https://github.com/kgoldman/ibmswtpm2.git
cd ibmswtpm2/src/
make
```

Run with: `./tpm_server`

Note: You can use the `-rm` switch to remove the cache file NVChip. Alternatively you can delete the NVChip file (`rm NVChip`)


### ms-tpm-20-ref

Build steps:

```sh
git clone https://github.com/microsoft/ms-tpm-20-ref
cd ms-tpm-20-ref/TPMCmd
./bootstrap
./configure
make
```

Run with: `./Simulator/src/tpm2-simulator`

Run power on and self test. See [SWTPM Power Up and Startup](#swtpm-power-up-and-startup).


### swtpm

Build libtpms

```sh
git clone git@github.com:stefanberger/libtpms.git
cd libtpms
./autogen.sh --with-tpm2 --with-openssl --prefix=/usr
make install
```

Build swtpm

```sh
git clone git@github.com:stefanberger/swtpm.git
cd swtpm
./autogen.sh
make install
```

Note: On Mac OS X had to do the following first:

```sh
brew install openssl socat
pip3 install cryptography

export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
export CPPFLAGS="-I/usr/local/opt/openssl@1.1/include"

# libtpms had to use --prefix=/usr/local
```

Running swtpm

```sh
mkdir -p /tmp/myvtpm
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init
```

### swtpm with QEMU

This demonstrates using wolfTPM in QEMU to communicate using the linux
kernel device "/dev/tpmX". You will need to install or build
[swtpm](https://github.com/stefanberger/swtpm). Below are a short
method to build. You may need to consult the instructions for
[libtpms](https://github.com/stefanberger/libtpms/wiki#compile-and-install-on-linux)
and
[swtpm](https://github.com/stefanberger/swtpm/wiki#compile-and-install-on-linux)

```sh
PREFIX=$PWD/inst
git clone git@github.com:stefanberger/libtpms.git
cd libtpms/
./autogen.sh --with-openssl --with-tpm2 --prefix=$PREFIX && make install
cd ..
git clone git@github.com:stefanberger/swtpm.git
cd swtpm
PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig/ ./autogen.sh --with-openssl --with-tpm2 \
    --prefix=$PREFIX && \
  make install
cd ..
```

You can setup a basic linux installation. Other installation bases can
be used. This step will take some time to install the base linux
system.

```sh
# download mini install image
curl -O http://archive.ubuntu.com/ubuntu/dists/bionic-updates/main/installer-amd64/current/images/netboot/mini.iso
# create qemu image file
qemu-img create -f qcow2 lubuntu.qcow2 5G
# create directory for tpm state and socket
mkdir $PREFIX/mytpm
# start swtpm
$PREFIX/bin/swtpm socket --tpm2 --tpmstate dir=$PREFIX/mytpm \
  --ctrl type=unixio,path=$PREFIX/mytpm/swtpm-sock --log level=20 &
# start qemu for installation
qemu-system-x86_64 -m 1024 -boot d -bios bios-256k.bin -boot menu=on \
  -chardev socket,id=chrtpm,path=$PREFIX/mytpm/swtpm-sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 -hda lubuntu.qcow2 -cdrom mini.iso
```

Once a base system is installed it's ready to start the qemu and build
wolfSSL and wolfTPM in the qemu instance.

```sh
# start swtpm again
$PREFIX/bin/swtpm socket --tpm2 --tpmstate dir=$PREFIX/mytpm \
  --ctrl type=unixio,path=$PREFIX/mytpm/swtpm-sock --log level=20 &
# start qemu system to install and run wolfTPM
qemu-system-x86_64 -m 1024 -boot d -bios bios-256k.bin -boot menu=on \
  -chardev socket,id=chrtpm,path=$PREFIX/mytpm/swtpm-sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 -hda lubuntu.qcow2
```

To build checkout and build wolfTPM, in the QEMU terminal

```sh
sudo apt install automake libtool gcc git make

# get and build wolfSSL
git clone https://github.com/wolfssl/wolfssl.git
pushd wolfssl
./autogen.sh && \
  ./configure --enable-wolftpm --disable-examples --prefix=$PWD/../inst && \
  make install
popd

# get and build wolfTPM
git clone https://github.com/wolfssl/wolftpm.git
pushd wolftpm
./autogen.sh && \
  ./configure --enable-devtpm --prefix=$PWD/../inst --enable-debug && \
  make install
sudo make check
popd
```

You can now run the examples such as `sudo ./examples/wrap/wrap`
within QEMU. Using `sudo` maybe required for access to `/dev/tpm0`.


## Running examples

```sh
./examples/wrap/caps
./examples/pcr/extend
./examples/wrap/wrap_test
```

See [examples/README.md](../examples/README.md) for additional example usage.
