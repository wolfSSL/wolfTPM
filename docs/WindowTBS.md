# Using wolfTPM with Windows TBS

wolfTPM can be built to use Windows native TBS (TPM Base Services)

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
./configure --prefix="$PREFIX" --enable-certgen --enable-certreq --enable-certext --enable-pkcs7 --enable-cryptocb
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

cd wolfssl
./autogen.sh
./configure --host=i686 CC=i686-w64-mingw32-gcc CFLAGS="-DWIN32 -DMINGW -D_WIN32_WINNT=0x0600" LIBS="-lws2_32" --prefix="$PREFIX" --enable-certgen --enable-certreq --enable-certext --enable-pkcs7 --enable-cryptocb
make
make install

cd ../wolftpm/
./autogen.sh
./configure --host=i686 CC=i686-w64-mingw32-gcc CFLAGS="-DWIN32 -DMINGW -D_WIN32_WINNT=0x0600" LIBS="-lws2_32" --prefix="$PREFIX" --enable-winapi
make
```

## Running on Windows

To confirm presence and status of TPM on the machine run `tpm.msc`

See [examples/README.md](examples/README.md)


