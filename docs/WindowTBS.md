# Using wolfTPM with Windows TBS

wolfTPM can be built to use Windows native TBS (TPM Base Services)

When using the Windows TBS interface the NV access is blocked by default. TPM NV storage space is very limited and when filled can cause undefined behaviors, such as failures loading key handles. These are not managed by TBS.

The TPM is designed to return an encrypted private key blob on key creation using `TPM2_Create`, which you can safely store on the disk and load when needed. The symmetric encryption key used to protect the private key blob is only known by the TPM. When you load a key using `TPM2_Load` you get a transient handle, which can be used for signing and even encryption/decryption.

For primary keys created with `TPM2_CreatePrimary` you get back a handle. There is no encrypted private data returned. That handle will remain loaded until `TPM2_FlushContext` is called.

For normal key creation using `TPM2_Create` you get back a `TPM2B_PRIVATE outPrivate`, which is the encrypted blob that you can store and load anytime using `TPM2_Load`.

## Limitations

wolfTPM has been tested on Windows 10 with TPM 2.0 devices. While
Windows does support TPM 1.2, functionality is limited and not
supported by wolfTPM.

Presence of TPM 2.0 can be checked by opening PowerShell
and running `Get-PnpDevice -Class SecurityDevices`

```
Status     Class           FriendlyName
------     -----           ------------
OK         SecurityDevices Trusted Platform Module 2.0
Unknown    SecurityDevices Trusted Platform Module 2.0
```

## Building in MSYS2

Tested using MSYS2

```
export PREFIX=$PWD/tmp_install

cd wolfssl
./autogen.sh
./configure --prefix="$PREFIX" --enable-wolftpm
make
make install

cd wolftpm/
./autogen.sh
./configure --prefix="$PREFIX" --enable-winapi
make
./examples
```

## Building on linux

Tested using mingw-w32-bin_x86_64-linux_20131221.tar.bz2
[source](https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win32/Automated%20Builds/)

Extract the tools and add them to the `PATH`
```
mkdir mingw_tools
cd mingw_tools
tar xjvf ../mingw-w32-bin_x86_64-linux_20131221.tar.bz2
export PATH=$PWD/bin/:$PWD/i686-w64-mingw32/bin:$PATH
cd ..
```

Build
```
export PREFIX=$PWD/tmp_install
export CFLAGS="-DWIN32 -DMINGW -D_WIN32_WINNT=0x0600 -DUSE_WOLF_STRTOK"
export LIBS="-lws2_32"

cd wolfssl
./autogen.sh
./configure --host=i686 CC=i686-w64-mingw32-gcc --prefix="$PREFIX" --enable-wolftpm
make
make install

cd ../wolftpm/
./autogen.sh
./configure --host=i686 CC=i686-w64-mingw32-gcc --prefix="$PREFIX" --enable-winapi
make
cd ..
```

## Running on Windows

To confirm presence and status of TPM on the machine run `tpm.msc`

See [examples/README.md](/examples/README.md)
