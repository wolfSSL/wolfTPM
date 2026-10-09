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

## API Overview

All wrapper types are in the `wolfTPM` namespace in `wrapper/CSharp/wolfTPM.cs`. Each one is a thin class around a native wolfTPM object that is allocated and freed through P/Invoke calls into the `wolftpm` library.

| Type | Purpose |
| --- | --- |
| `Device` | The TPM connection. Holds the native `WOLFTPM2_DEV` and exposes every TPM operation. |
| `Key` | A loaded TPM key, such as the storage root key (SRK) or a primary key. |
| `KeyBlob` | A created key (public and private parts) that can be loaded, used, and saved to a byte array. |
| `Template` | A TPM public template that describes the type and attributes of a new key. |
| `Session` | A TPM authorization session, used for HMAC sessions with parameter encryption. |
| `Csr` | A certificate signing request helper that holds the subject, key usage, and custom extensions. |
| `WolfTpm2Exception` | The exception thrown when a native call fails. |
| `Status` | Enum of common return codes: `TPM_RC_SUCCESS`, `TPM_RC_HANDLE`, `TPM_RC_NV_UNAVAILABLE`, `TPM_RC_SIGNATURE`, `BAD_FUNC_ARG`, and `NOT_COMPILED_IN`. |

The file also defines enums that mirror native values: `TPM2_Object` (object attribute bits such as `sensitiveDataOrigin`, `userWithAuth`, `decrypt`, `sign`, `noDA`), `TPM2_Alg` (for example `RSA`, `ECC`, `SHA256`, `RSASSA`, `CFB`, `XOR`, `NULL`), `TPM2_ECC` (curves), `SE` (session type), `SESSION_mask`, `TPM_RH` (hierarchies such as `OWNER`, `ENDORSEMENT`, `PLATFORM`), and `X509_Format` (`PEM` or `DER`).

### Device Lifetime

`Device` implements `IDisposable`. The constructor calls the native `wolfTPM2_New()`, which also initializes the TPM, so a new `Device` is ready to use. `Dispose()` calls `wolfTPM2_Free()` and clears the pointer. A finalizer calls the same cleanup if you forget, but you should wrap the device in a `using` statement or call `Dispose()` yourself.

`Key`, `KeyBlob`, `Template`, `Session`, and `Csr` follow the same pattern: the constructor allocates the native object and `Dispose()` frees it. The native return code from the free call is ignored.

`Device.Ref` returns the native device pointer. `Device` also defines these constants: `MAX_KEYBLOB_BYTES` (2048), `MAX_TPM_BUFFER` (2048), and `INVALID_DEVID` (-2). The first two are buffer sizes used by the tests and may need to be larger on your platform.

### Errors and Return Values

Most methods return an `int` and throw `WolfTpm2Exception` on failure, so you do not need to check the result for the common case. The exception has an `ErrorCode` property with the native return code. Its `Message` includes the native function name, the code in hex, and the text from `TPM2_GetRCString`. `Device.GetErrorString(int)` and `Device.GetErrorString(Status)` give the same text for any code.

A few methods treat some codes as non-fatal and return them instead of throwing:

- `ReadPublicKey` returns `TPM_RC_HANDLE` when no object exists at the handle.
- `StoreKey` returns `TPM_RC_NV_UNAVAILABLE`.
- `VerifyHashScheme` returns `TPM_RC_SIGNATURE` when the signature does not match.
- `Csr.SetCustomExtension` returns `NOT_COMPILED_IN` when the native library was built without support for it.

Methods that produce data return a positive size on success: `KeyBlob.GetKeyBlobAsBuffer`, `Device.RsaEncrypt`, `Device.RsaDecrypt`, `Device.SignHashScheme`, `Device.GenerateCSR`, and `Csr.MakeAndSign`. `UnloadHandle` calls the native function directly and returns its code without throwing.

### Keys, Blobs, and Sessions

- A `Key` is filled by `CreateSRK`, `CreatePrimaryKey`, `ReadPublicKey`, `LoadRsaPublicKey`, `LoadRsaPrivateKey`, or `ImportRsaPrivateKey`. `GetHandle()` returns the native handle pointer, and `SetKeyAuthPassword` sets the key password.
- A `KeyBlob` is filled by `CreateKey` using a parent `Key` and a `Template`, then loaded with `LoadKey`. `GetKeyBlobAsBuffer` exports it so it can be stored on disk and restored in another process with `SetKeyBlobFromBuffer`. After restoring, load it again with `LoadKey` and call `SetKeyAuthPassword` before using it.
- `Device.StoreKey` and `Device.DeleteKey` move a key or key blob into or out of persistent storage (NV) under a hierarchy such as `TPM_RH.OWNER`.
- Loaded TPM objects stay loaded in the TPM until you free them. Call `Device.UnloadHandle` with the `Key`, `KeyBlob`, or `Session` when you are done. `Dispose()` only frees the managed wrapper and its native memory.
- A `Session` is started with `StartAuth(device, parentKey, encDecAlg)` where `encDecAlg` is `TPM2_Alg.NULL`, `CFB`, or `XOR`. It starts an HMAC session, binds it to authorization slot 1 (or the index given to `Session(int index)`), and enables parameter encryption. End it with `StopAuth(device)`. `Device.StartSession`, `SetAuthSession`, and `ClearAuthSession` are the lower-level calls behind this.

### Template and Csr

`Template` fills a native key template: `GetKeyTemplate_RSA`, `GetKeyTemplate_ECC`, `GetKeyTemplate_Symmetric`, the EK, SRK, and AIK variants (`GetKeyTemplate_RSA_EK`, `GetKeyTemplate_ECC_EK`, `GetKeyTemplate_RSA_SRK`, `GetKeyTemplate_ECC_SRK`, `GetKeyTemplate_RSA_AIK`, `GetKeyTemplate_ECC_AIK`), and `SetKeyTemplate_Unique`.

For a one-call certificate request, use `Device.GenerateCSR` with a subject string, a key usage string, and an `X509_Format`. For more control, build a `Csr` with `SetSubject`, `SetKeyUsage`, and `SetCustomExtension`, then call `MakeAndSign`. Set the `selfSign` argument of the extended overloads to a non-zero value to get a self-signed certificate instead of a request. The extended `Csr.MakeAndSign(..., sigType, selfSign)` overload currently throws on every successful call (it treats the returned output size as an error), so for a self-signed certificate use `Device.GenerateCSR(..., selfSignCert)` until the wrapper is fixed.

### Other Device Methods

`SelfTest`, `GetRandom`, `RsaEncrypt`, `RsaDecrypt`, `SignHashScheme`, `VerifyHashScheme`, and `GetHandleValue` are also on `Device`. See the XML comments in `wolfTPM.cs` for each parameter.

### Example

This example creates a storage root key, creates and loads an RSA key under it, signs a digest, and verifies the signature. It follows the pattern used in `wolfTPM-tests.cs`.

```csharp
using System;
using wolfTPM;

class Example
{
    static void Main()
    {
        using (Device device = new Device())
        using (Key srk = new Key())
        using (KeyBlob blob = new KeyBlob())
        using (Template template = new Template())
        {
            try
            {
                device.SelfTest();
                device.CreateSRK(srk, TPM2_Alg.RSA, "StorageKeyAuth");

                template.GetKeyTemplate_RSA((ulong)(
                    TPM2_Object.sensitiveDataOrigin |
                    TPM2_Object.userWithAuth |
                    TPM2_Object.decrypt |
                    TPM2_Object.sign |
                    TPM2_Object.noDA));

                device.CreateKey(blob, srk, template, "MyKeyAuth");
                device.LoadKey(blob, srk);

                byte[] digest = new byte[32];
                device.GetRandom(digest);

                byte[] sig = new byte[256];
                int sigSz = device.SignHashScheme(blob, digest, sig,
                    TPM2_Alg.RSASSA, TPM2_Alg.SHA256);
                Console.WriteLine("Signature is {0} bytes", sigSz);

                int rc = device.VerifyHashScheme(blob, sig, digest,
                    TPM2_Alg.RSASSA, TPM2_Alg.SHA256);
                Console.WriteLine(rc == (int)Status.TPM_RC_SUCCESS ?
                    "Signature verified" : "Signature invalid");

                device.UnloadHandle(blob);
                device.UnloadHandle(srk);
            }
            catch (WolfTpm2Exception e)
            {
                Console.WriteLine("TPM error: " + e.Message);
            }
        }
    }
}
```

## See Also

- [SWTPM](system-interfaces.md)
- [Build Options](build-options.md)
- [Rust Wrapper](rust-wrapper.md)
