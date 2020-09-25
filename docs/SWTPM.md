# Using wolfTPM with SWTPM

wolfTPM is to be able to interface with SW TPM interfaces defined by
section D.3 of
[TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code.pdf)

Using the socket connection for SWTPM is exclusive and not compatible
with TIS or devtpm.

Only a subset of functionality is implemented to support testing of
wolfTPM. The platform requests are not used by wolfTPM.

Two implementations were used in testing:

* https://sourceforge.net/projects/ibmswtpm2/files/
* https://github.com/stefanberger/swtpm

## Building with SW TPM support

```
./configure --enable-swtpm
make
```

## SWTPM simulator setup

### ibmswtpm2

Checkout and Build
```
git clone https://github.com/kgoldman/ibmswtpm2.git
cd ibmswtpm2/src/
make
```

Running:
```
./tpm_server --rm
```

The rm switch is optional and remove the cache file
NVChip. Alternately you can `rm NVChip`

### swtpm

Build libtpms

```
git clone git@github.com:stefanberger/libtpms.git
(cd libtpms && ./autogen.sh --with-tpm2 --with-openssl --prefix=/usr && make install)
```

Build swtpm

```
git clone git@github.com:stefanberger/swtpm.git
(cd swtpm && ./autogen.sh && make install)
```

Note: On Mac OS X had to do the following first:

```
brew install openssl socat
pip3 install cryptography

export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
export CPPFLAGS="-I/usr/local/opt/openssl@1.1/include"

# libtpms had to use --prefix=/usr/local
```

Running swtpm

```
mkdir -p /tmp/myvtpm
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init
```

## Running examples

```
./examples/pcr/extend
./examples/wrap/wrap_test
```

See `README.md` for more examples
