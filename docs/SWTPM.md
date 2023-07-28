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
* `TPM2_SWTPM_HOST`: The host TPM address (default=localhost)
* `TPM2_SWTPM_PORT`: The socket port (default=2321)
* `WOLFTPM_SWTPM_UART`: Use UART transport (no TIS layer)


## SWTPM simulator setup

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
