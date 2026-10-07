# C# Wrapper

The `wrapper/CSharp` directory contains a C# wrapper for the wolfTPM TPM 2.0 API. It binds to the native `wolftpm` library through P/Invoke, so the native library must be built first. The tests use NUnit and run on .NET (Windows) or Mono (Linux).

Build wolfSSL as described in the wolfTPM `README.md`, then build wolfTPM as described below for your platform. On Linux, tests use the swtpm TCP simulator.

## Windows

A Visual Studio solution is provided for building the wrappers. To run the tests, update the `.runsettings` file to add the location of `wolftpm.dll`. The file has a placeholder for a vcpkg build, but CMake can also be used to build wolfTPM with Visual Studio.

Example CMake settings for building wolfTPM on Windows:

```
"WOLFTPM_INTERFACE": "WINAPI",
"WOLFTPM_EXAMPLES": "no",
"WOLFTPM_DEBUG": "yes",
"WITH_WOLFSSL": "C:/Users/[username]/wolfssl/out/install/windows-default"
```

## Linux

The wrapper has been tested with the swtpm TCP protocol for use with the simulator. See [SWTPM](system-interfaces.md) for building and running the simulator.

Build wolfTPM:

```sh
./autogen.sh
./configure --enable-swtpm
make all
make check
```

Install the prerequisites for Mono and NUnit:

```sh
apt install mono-tools-devel nunit nunit-console
```

Then build the wrapper and its tests, and run them:

```sh
cd wrapper/CSharp
mcs wolfTPM.cs wolfTPM-tests.cs -r:/usr/lib/cli/nunit.framework-2.6.3/nunit.framework.dll -t:library

# run the selftest case
LD_LIBRARY_PATH=../../src/.libs/ nunit-console wolfTPM.dll -run=tpm_csharp_test.WolfTPMTest.TrySelfTest

# run all tests
LD_LIBRARY_PATH=../../src/.libs/ nunit-console wolfTPM.dll
```

The selftest run prints output similar to the following:

```
Selected test(s): tpm_csharp_test.WolfTPMTest.TrySelfTest

wolfSSL Entering wolfCrypt_Init
.
Tests run: 1, Errors: 0, Failures: 0, Inconclusive: 0, Time: 0.1530346 seconds

  Not run: 0, Invalid: 0, Ignored: 0, Skipped: 0

wolfSSL Entering wolfCrypt_Cleanup
```

!!! note
    The source README does not describe the wrapper API surface. This page needs new prose later covering the exposed classes and a usage example.

## See Also

- [SWTPM](system-interfaces.md)
- [Build Options](build-options.md)
- [Rust Wrapper](rust-wrapper.md)
