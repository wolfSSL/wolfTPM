# wolfTPM (TPM 2.0) CSharp Wrappers

This directory contains the CSharp wrapper for the TPM 2.0 API wrapper API.


Once you have created the simulator, you can build wolfssl as described in the
`README.md` in the root of this repo. Then you can build wolfTPM:

## Windows

A Visual Studio solution is provided. This will allow you to build the
wrappers. In order to run the tests you will need to update the
`.runsettings` to add the location of the `wolftpm.dll`. There is a
placeholder to leverage a vcpkg build, but cmake can also be used to
build wolfTPM with Visual Studios.

When building wolfTPM with cmake on Windows here is an example of the settings used:

```
"WOLFTPM_INTERFACE": "WINAPI",
"WOLFTPM_EXAMPLES": "no",
"WOLFTPM_DEBUG": "yes",
"WITH_WOLFSSL": "C:/Users/[username]/wolfssl/out/install/windows-default"
```

## Linux

The wrapper has been tested with the swtpm TCP protocol for use with
the simulator. Please follow instructions in the `docs/SWTPM.md` file
for building and running the simulator.


```
./autogen.sh
./configure --enable-swtpm
make all
make check
```

Prerequisites for linux

```
apt install mono-tools-devel nunit nunit-console
```

You can then build wolfTPM as described above in the Linux or Windows section
of this document. After that, build and run the wolfTPM CSharp wrapper and run
some tests:

```
cd wrapper/CSharp
mcs wolfTPM.cs wolfTPM-tests.cs -r:/usr/lib/cli/nunit.framework-2.6.3/nunit.framework.dll -t:library

# run selftest case
LD_LIBRARY_PATH=../../src/.libs/ nunit-console wolfTPM.dll -run=tpm_csharp_test.WolfTPMTest.TrySelfTest
#run all tests
LD_LIBRARY_PATH=../../src/.libs/ nunit-console wolfTPM.dll
```


You should see something similar to the following output:

```
Selected test(s): tpm_csharp_test.WolfTPMTest.TrySelfTest

wolfSSL Entering wolfCrypt_Init
.
Tests run: 1, Errors: 0, Failures: 0, Inconclusive: 0, Time: 0.1530346 seconds

  Not run: 0, Invalid: 0, Ignored: 0, Skipped: 0

wolfSSL Entering wolfCrypt_Cleanup
```
