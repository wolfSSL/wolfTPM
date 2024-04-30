# wolfTPM with Software Simulator (SWTPM) support

wolfTPM is to be able to interface with software TPM (SW TPM) interfaces defined by section D.3 of [TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code.pdf)

The SWTPM interface is not compatible with TIS or devtpm (/dev/tpm0). Transport is a socket connection by default, but can also be a UART.

This implementation only uses the TPM command interface typically on port 2321. It does not support the Platform interface typically on port 2322.

Software TPM implementations tested:
* https://github.com/kgoldman/ibmswtpm2 or https://sourceforge.net/projects/ibmswtpm2/files/
* https://github.com/microsoft/ms-tpm-20-ref
* https://github.com/stefanberger/swtpm

## Building SW TPM support

By default a socket transport will be used.

```sh
./configure --enable-swtpm
make
```

### Build SW TPM with UART transport

```sh
./configure --enable-swtpm=uart
make
```

## Build Options

* `WOLFTPM_SWTPM`: Use socket transport (no TIS layer)
* `TPM2_SWTPM_HOST`: The serial device to use (default=/dev/ttyS0)
* `TPM2_SWTPM_PORT`: The baud rate (default=115200)
* `WOLFTPM_SWTPM_UART`: Use UART transport (no TIS layer)

## SWTPM simulator setup

### Xilinx UART

Alternatively for raw API calls with Xilinx

```sh
./cofnigure --enable-swtpm=uartns550
make
```

## Build Options

* `WOLFTPM_SWTPM`: Use socket transport (no TIS layer)
* `TPM2_SWTPM_PORT`: Used as the default baud rate (default=115200)
* `TPM2_SWTPM_HOST`: The device to connect with (default=XPAR_MB0_AXI_UART16550_2_DEVICE_ID)
* `WOLFTPM_SWTPM_UARTNS550`: Use Xilinx UART transport (no TIS layer)

### ibmswtpm2

Checkout and Build
```sh
git clone https://github.com/kgoldman/ibmswtpm2.git
cd ibmswtpm2/src/
make
```

Running:
```sh
./tpm_server -rm
```

The rm switch is optional and remove the cache file NVChip. Alternately you can `rm NVChip`

### ms-tpm-20-ref

```sh
git clone https://github.com/microsoft/ms-tpm-20-ref
cd ms-tpm-20-ref
./bootstrap
./configure
make
./Simulator/src/tpm2-simulator
```

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

## Running examples

```sh
./examples/pcr/extend
./examples/wrap/wrap_test
```

See `README.md` for more examples


### swtpm with QEMU

This demonstrates using wolfTPM in QEMU to communicate using the linux
kernel device "/dev/tpmX". You will need to install or build
[swtpm](https://github.com/stefanberger/swtpm). Below are a short
method to build. You may need to consult the instructions for
[libtpms](https://github.com/stefanberger/libtpms/wiki#compile-and-install-on-linux)
and
[swtpm](https://github.com/stefanberger/swtpm/wiki#compile-and-install-on-linux)

```
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

```
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

```
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

```
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
