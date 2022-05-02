# wolfTPM (TPM 2.0) CSharp Wrappers

This directory contains the CSharp wrapper for the TPM 2.0 API wrapper API.


Once you have created the simulator, you can build wolfssl as described in the
README.md in the root of this repo. Then you can build wolfTPM:

## Windows

A Visual Studio solution is provided. This will allow you to build the
wrappers. In order to run the tests you will need to update the
`.runsettings` to add the location of the `wolftpm.dll`. There is a
placeholder to leverage a vcpkg build, but cmake can also be used to
build wolfTPM with Visual Studios.

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
apt install mono-tools-devel nunit
```

You can then build and run the test wolfTPM:

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
NUnit-Console version 2.6.4.0
Copyright (C) 2002-2012 Charlie Poole.
Copyright (C) 2002-2004 James W. Newkirk, Michael C. Two, Alexei A. Vorontsov.
Copyright (C) 2000-2002 Philip Craig.
All Rights Reserved.

Runtime Environment - 
   OS Version: Unix 5.13.0.40
  CLR Version: 4.0.30319.42000 ( Mono 4.0 ( 6.8.0.105 (Debian 6.8.0.105+dfsg-2 Wed Feb 26 23:23:50 UTC 2020) ) )

ProcessModel: Default    DomainUsage: Single
Execution Runtime: mono-4.0
Selected test(s): tpm_csharp_test.WolfTPMTest.TryFillBufferWithRandom
.wolfSSL Entering wolfCrypt_Init
wolfSSL Entering wolfCrypt_Cleanup
buf: { 44, 95, 206, 69, 252, 157, 173, 149, 26, 160, 21, 5, 35, 19, 255, 29, 251, 228, 206, 36, 77, 79, 160, 42, 25, 172, 82, 172, 152, 143, 179, 147, 52, 211, 238, 63, 34, 227, 243, 155, 17, 77, 135, 233, 103, 39, 211, 180, 55, 54, 36, 180, 87, 168, 28, 143, 104, 175, 176, 156, 154, 8, 114, 143, 123, 99, 110, 247, 46, 193, 93, 54, 208, 128, 162, 190, 225, 255, 109, 44, 8, 153, 21, 162, 139, 70, 7, 73, 13, 145, 157, 111, 20, 151, 101, 44, 45, 154, 159, 139, 153, 48, 117, 69, 179, 186, 48, 225, 20, 145, 120, 78, 58, 228, 4, 146, 241, 195, 121, 94, 44, 92, 246, 198, 71, 122, 176, 133, 21, 27, 41, 17, 7, 96, 122, 155, 105, 57, 150, 45, 63, 165, 136, 195, 173, 160, 137, 136, 207, 19, 60, 140, 2, 203, 246, 248, 179, 170, 203, 153, 154, 229, 104, 200, 141, 94, 139, 25, 103, 235, 116, 97, 186, 29, 32, 133, 205, 122, 230, 51, 88, 195, 69, 158, 199, 255, 212, 117, 3, 110, 201, 179, 138, 242, 172, 160, 121, 46, 117, 41, 185, 11, 22, 99, 4, 214, 37, 179, 246, 71, 146, 168, 116, 28, 146, 221, 53, 21, 5, 18, 84, 57, 137, 171, 237, 233, 215, 91, 88, 4, 205, 207, 218, 74, 46, 105, 106, 55, 254, 211, 186, 151, 136, 81, 128, 33, 77, 218, 203, 19, 164, 76, 177, 2, 185, 212, } (256 bytes)

Tests run: 1, Errors: 0, Failures: 0, Inconclusive: 0, Time: 0.0747956 seconds
  Not run: 0, Invalid: 0, Ignored: 0, Skipped: 0
```

If you run this multiple time, you will see the content of the buffer changing
for each execution.

