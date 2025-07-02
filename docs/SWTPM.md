# wolfTPM with Software Simulator (SWTPM) support

wolfTPM is to be able to use Software TPM (SW TPM) defined by section D.3 of [TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code.pdf)

Software TPM implementations tested:
* [Official TCG Reference](https://github.com/TrustedComputingGroup/TPM): Reference code from the specification maintained by TCG [build steps](#tcg-tpm)
* [IBM / Ken Goldman](https://github.com/kgoldman/ibmswtpm2): Fork of reference code maintained by IBM [build steps](#ibmswtpm2)
* [Microsoft](https://github.com/microsoft/ms-tpm-20-ref): Fork of reference code maintained by Microsoft (93% identical to official TCG) [build steps](#ms-tpm-20-ref)
* [Stefan Berger](https://github.com/stefanberger/swtpm): Uses libtpms front end interfaces. [build steps](#swtpm)

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

Checkout and Build
```sh
git clone https://github.com/kgoldman/ibmswtpm2.git
cd ibmswtpm2/src/
make
```

Run with: `./tpm_server`

Note: You can use the `-rm` switch to remove the cache file NVChip. Alternatively you can delete the NVChip file (`rm NVChip`)


### ms-tpm-20-ref

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

See [examples/README.md](/examples/README.md) for additional example usage.
