# Using wolfTPM with SWTPM

wolfTPM is to be able to interface with SW TPM interfaces defined by section D.3 of
[TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code.pdf)

Using the socket connection for SWTPM is exclusive and not compatible with TIS or devtpm.

Only a subset of functionality is implemented to support testing of wolfTPM. The platform requests are not used by wolfTPM.

Two implementations were used in testing:
* http://ibmswtpm.sourceforge.net/
* https://github.com/stefanberger/swtpm

## Building with SW TPM support
```
./configure --enable-swtpm
make
```

## Starting SWTPM simulator

```
git clone https://github.com/kgoldman/ibmswtpm2.git
cd ibmswtpm2/src/
make
```

```
./tpm_server --rm
```

The rm switch is optional and remove the cache file
NVChip. Alternately you can `rm NVChip`

## Running examples

```
./examples/pcr/extend
./examples/wrap/wrap_test
```
