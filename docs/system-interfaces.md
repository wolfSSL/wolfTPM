# System Interfaces

Besides talking directly to a TPM chip over SPI or I2C, wolfTPM can reach a TPM through an operating system interface or a software simulator. This page covers the three of them: the software TPM simulators (SWTPM), the Linux kernel device (`/dev/tpmX`), and the Windows TBS API. Only one transport can be enabled in a given build.

## Software simulator (SWTPM)

wolfTPM can use a software TPM defined by section D.3 of [TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code.pdf).

Software TPM implementations tested:

* [Official TCG Reference](https://github.com/TrustedComputingGroup/TPM): reference code from the specification maintained by TCG. See [TCG TPM](#tcg-tpm).
* [IBM (ibmswtpm2) / Ken Goldman](https://github.com/kgoldman/ibmswtpm2): a fork of the reference code maintained by IBM (93% identical to the official TCG code). See [ibmswtpm2](#ibmswtpm2).
* [Microsoft ms-tpm-20-ref](https://github.com/microsoft/ms-tpm-20-ref): a fork of the reference code maintained by Microsoft (100% identical to the official TCG code). See [ms-tpm-20-ref](#ms-tpm-20-ref).
* [libtpms/swtpm by Stefan Berger](https://github.com/stefanberger/swtpm): uses the libtpms front end interfaces. See [swtpm](#swtpm).

The software TPM transport is a socket connection by default. A UART is also supported. This implementation only uses the TPM command interface, typically on port 2321. It does not support the platform interface, typically on port 2322.

### wolfTPM SWTPM support

To enable the socket transport for SWTPM use `--enable-swtpm`. By default all software TPM simulators use TCP port 2321.

```sh
./configure --enable-swtpm
make
```

!!! note
    It is not possible to enable more than one transport interface at a time. When building with the SWTPM socket interface, the built-in TIS and devtpm (`/dev/tpm0`) interfaces are not available.

Build options:

* `WOLFTPM_SWTPM`: use the socket transport (no TIS layer)
* `TPM2_SWTPM_HOST`: the socket host (default is localhost)
* `TPM2_SWTPM_PORT`: the socket port (default is 2321)

### wolfTPM SWTPM UART support

To use the SWTPM protocol over a UART serial connection instead of TCP sockets, use `--enable-swtpm=uart`. This is intended for talking to a firmware TPM (fwTPM) running on an embedded target, such as the wolfTPM fwTPM server on STM32H5.

```sh
./configure --enable-swtpm=uart
make
```

The serial device path and baud rate can be set at compile time or at runtime:

```sh
# Runtime override via environment variable
TPM2_SWTPM_HOST=/dev/ttyACM0 ./examples/wrap/caps
```

Build options:

* `WOLFTPM_SWTPM_UART`: use the UART serial transport (set automatically by `--enable-swtpm=uart`)
* `TPM2_SWTPM_HOST`: the serial device path (default is `/dev/ttyACM0` on Linux and `/dev/cu.usbmodem` on macOS). It can be overridden at runtime with the `TPM2_SWTPM_HOST` environment variable.
* `TPM2_SWTPM_PORT`: the baud rate (default is 115200)

The UART transport uses the same mssim protocol as the socket transport. The serial port is configured as 8N1 raw mode with no flow control. Like the socket transport, the serial port file descriptor is kept open across commands (no reconnect per command). Both transports close the connection during `wolfTPM2_Cleanup`. On the socket transport, any transmit or receive failure also closes the connection so the next command reconnects. The UART transport closes only when the per-command `TPM_SESSION_END` write fails.

#### Security note: environment variable override

The `TPM2_SWTPM_HOST` environment variable is a development convenience that overrides the compile-time serial device path. On systems where untrusted local users share the environment with the TPM client, an attacker could redirect TPM I/O to a rogue device, such as a PTY they control. For production and hardened deployments:

* Unset `TPM2_SWTPM_HOST` in the process environment.
* Rely on the compile-time default (set via `TPM2_SWTPM_HOST` as a build `-D` macro) to pin the serial path.

The same guidance applies to `TPM2_SWTPM_PORT` (baud rate) and, for the socket transport, to using the environment variable to redirect the TCP host.

#### Example: wolfTPM fwTPM on STM32H5

The wolfTPM project includes a firmware TPM server port for STM32 Cortex-M33 targets with TrustZone support. See [wolftpm-examples/STM32/fwtpm-stm32h5](https://github.com/wolfSSL/wolftpm-examples/tree/main/STM32/fwtpm-stm32h5) for build, flash, and test instructions.

```sh
# Build host client with UART transport
./configure --enable-swtpm=uart
make

# Run examples against STM32 fwTPM (adjust device path as needed)
export TPM2_SWTPM_HOST=/dev/ttyACM0
./examples/wrap/caps
./examples/keygen/keygen -ecc
./examples/seal/seal
```

### Using a SWTPM

#### SWTPM Power Up and Startup

The TCG TPM and Microsoft ms-tpm-20-ref implementations require power up and startup commands on the platform interface before the command interface is enabled. Use these commands to issue the required power up and startup:

```sh
echo -ne "\x00\x00\x00\x01" | nc 127.0.0.1 2322
echo -ne "\x00\x00\x00\x0B" | nc 127.0.0.1 2322
```

#### TCG TPM

```sh
git clone git@github.com:TrustedComputingGroup/TPM.git
cd TPM
cd TPMCmd
./bootstrap
./configure
make
```

Run with `./Simulator/src/tpm2-simulator`, then run power on and self test. See [SWTPM Power Up and Startup](#swtpm-power-up-and-startup).

#### ibmswtpm2

```sh
git clone https://github.com/kgoldman/ibmswtpm2.git
cd ibmswtpm2/src/
make
```

Run with `./tpm_server`.

!!! note
    You can use the `-rm` switch to remove the cache file NVChip. Alternatively, delete the NVChip file (`rm NVChip`).

#### ms-tpm-20-ref

```sh
git clone https://github.com/microsoft/ms-tpm-20-ref
cd ms-tpm-20-ref/TPMCmd
./bootstrap
./configure
make
```

Run with `./Simulator/src/tpm2-simulator`, then run power on and self test. See [SWTPM Power Up and Startup](#swtpm-power-up-and-startup).

#### swtpm

Build libtpms:

```sh
git clone git@github.com:stefanberger/libtpms.git
cd libtpms
./autogen.sh --with-tpm2 --with-openssl --prefix=/usr
make install
```

Build swtpm:

```sh
git clone git@github.com:stefanberger/swtpm.git
cd swtpm
./autogen.sh
make install
```

On macOS, do the following first:

```sh
brew install openssl socat
pip3 install cryptography

export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
export CPPFLAGS="-I/usr/local/opt/openssl@1.1/include"

# libtpms had to use --prefix=/usr/local
```

Run swtpm:

```sh
mkdir -p /tmp/myvtpm
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init
```

#### swtpm with QEMU

This demonstrates using wolfTPM in QEMU to communicate through the Linux kernel device `/dev/tpmX`. You need to install or build [swtpm](https://github.com/stefanberger/swtpm). A short build method is below. You may need to consult the instructions for [libtpms](https://github.com/stefanberger/libtpms/wiki#compile-and-install-on-linux) and [swtpm](https://github.com/stefanberger/swtpm/wiki#compile-and-install-on-linux).

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

Set up a basic Linux installation. Other installation bases can be used. This step takes some time to install the base Linux system.

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

Once a base system is installed, start QEMU again and build wolfSSL and wolfTPM in the QEMU instance.

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

In the QEMU terminal, check out and build wolfTPM:

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

You can now run examples such as `sudo ./examples/wrap/wrap` within QEMU. `sudo` may be required for access to `/dev/tpm0`.

### Running examples

```sh
./examples/wrap/caps
./examples/pcr/extend
./examples/wrap/wrap_test
```

See `examples/README.md` in the source tree for additional example usage.

## Linux kernel device (/dev/tpmX)

On Linux the kernel TPM driver stack exposes a TPM through a character device, and wolfTPM can use it directly instead of driving SPI or I2C itself. This is the right transport whenever the kernel already owns the TPM: a discrete chip bound to a kernel driver, a Windows-style firmware TPM, or a TEE-resident firmware TPM such as the one on NVIDIA Jetson platforms.

With `--enable-devtpm` there is no TIS layer and no HAL IO callback. `hal/tpm_io.c` is compiled out entirely and `TPM2_IoCb` is `NULL` (see `hal/tpm_io.h`), so pass `NULL` for the callback argument of `TPM2_Init` and `wolfTPM2_Init`.

With `--enable-autodetect` this is not the case. The TIS/SPI HAL stays compiled in on purpose, because it is the fallback, and `TPM2_IoCb` is a real function. Keep passing it, or the SPI fallback that build exists to provide is unreachable.

### Two device nodes

The kernel presents up to two nodes per TPM:

* `/dev/tpm0`: the raw device. One user at a time, no resource management. Whatever you send reaches the TPM.
* `/dev/tpmrm0`: the in-kernel resource manager (kernel 4.12 and later, practical from 5.12). It virtualizes handles, swaps transient objects and sessions in and out as needed, and flushes everything belonging to a connection when that connection closes.

wolfTPM prefers `/dev/tpmrm0` and falls back to `/dev/tpm0`. The resource manager is the better default: a TPM has very few transient object slots, and without it a program that leaks a handle wedges the TPM for everything else on the system.

Build-time overrides, honored by both `--enable-devtpm` and `--enable-autodetect`:

* `-DWOLFTPM_USE_TPMRM`: use `/dev/tpmrm0` only, with no fallback to the raw device.
* `CFLAGS='-DTPM2_LINUX_DEV="/dev/tpm1"'`: use a specific node. The inner quotes are required, because the macro is used directly as a C string literal and an unquoted value does not compile.

### Startup, shutdown, and shared state

The TPM is started by firmware long before Linux runs, and on the resource manager it is shared with every other process on the system. Restarting or shutting it down is therefore not an individual caller's decision, so wolfTPM stays out of the way on this transport:

* `wolfTPM2_Init` skips the startup and self-test sequence.
* `wolfTPM2_Reset` and `wolfTPM2_Shutdown` send no TPM command and return `NOT_COMPILED_IN` (-174), the same way `wolfTPM2_SetLocality` does on this transport. A `wolfTPM2_Reset(dev, 0, 0)` that asked for neither a shutdown nor a startup still returns `TPM_RC_SUCCESS`, since nothing was declined. Treat `NOT_COMPILED_IN` here as "the OS owns this", not as a failure.
* `wolfTPM2_SetLocality` returns `NOT_COMPILED_IN` because the kernel owns the locality.

The kernel does not reliably stop you here. Command filtering on `/dev/tpmrm0` is primarily about handle isolation, not about blocking global state changes, and behavior varies by kernel version and TPM implementation. On Linux 5.15 with the Jetson OP-TEE fTPM, a `TPM2_Shutdown(TPM_SU_CLEAR)` sent through the resource manager is passed straight through and returns success, both from wolfTPM and from `tpm2_shutdown`. So this is a case where the library declining to send the command is what protects other users of the TPM, rather than the kernel doing it for you.

If you need to control TPM startup state, you need `/dev/tpm0` and exclusive use of the TPM, or direct SPI access with the wolfTPM TIS driver.

### What the native API does on autodetect builds

Two behaviors matter if you use `TPM2_Init` or `TPM2_Init_ex` directly rather than the `wolfTPM2_*` wrapper.

The kernel device wins over your callback. If `/dev/tpmrm0` or `/dev/tpm0` opens, every command is routed there and the HAL IO callback you passed is never invoked. On a host that has both a kernel-bound TPM and a discrete SPI part, that means you now talk to a different TPM than a pre-autodetect build did. Pin the part you want with `--enable-devtpm`, `--enable-spi` or `--enable-<vendor>`, or `-DTPM2_LINUX_DEV`.

Init now acquires a descriptor. `TPM2_Init*` opens the device on autodetect builds, and `TPM2_Cleanup()` is what closes it. Native callers that skipped cleanup previously leaked nothing, but now they leak a descriptor per context. This matters most on hosts exposing only the raw `/dev/tpm0`, which permits a single open. A context that merely initialized holds the TPM exclusively for its lifetime, and a second context in the same process falls through to a different transport.

`TPM2_Init_minimal()` is unaffected: it performs no IO and still succeeds with no device present.

### Transient handles do not outlive a process

This is the difference most likely to break an existing application.

On `/dev/tpmrm0` the kernel gives each open file description its own handle space. Transient object handles are virtualized (the value the TPM assigned is not the value you get back), and everything in that space is flushed when the file descriptor closes. A transient key created by one process is gone by the time a second process runs, and the handle number it printed is meaningless to anyone else.

Creating a primary key on the Jetson fTPM through the resource manager returns:

```
Create Primary Handle: 0x80ffffff
```

This is not the `0x80000000` a raw device would report. Query the transient handles from a separate process afterwards and the list is empty:

```bash
tpm2_getcap handles-transient      # no output, the space was torn down
```

Two practical consequences:

* A "create a key, keep it, use it from the next command" workflow does not work across processes. Do the whole sequence in one process, or make the object persistent with `TPM2_EvictControl` so it gets a stable `0x81xxxxxx` handle that does survive.
* Passing a hard-coded transient handle such as `0x80000000` on a command line fails. The kernel rejects the reference before it reaches the TPM, and because that happens at the file-descriptor layer the error surfaces as `errno 22 = Invalid argument` on `read()`, which wolfTPM reports as `TPM_RC_FAILURE` rather than as a handle error. If you see `TPM_RC_FAILURE` alongside `Failed to read from /dev/tpmrm0 ... errno 22`, suspect a stale or cross-process transient handle before suspecting the TPM.

The wolfTPM script `examples/run_examples.sh` hits exactly this: its provisioning section creates IAK and IDevID primaries with `-keep` in one process and then references `0x80000000` and `0x80000001` from another. That block cannot pass on the resource manager by construction. Everything on either side of it is unaffected. Use `/dev/tpm0` with exclusive access if you need to run it as written.

### Building

```bash
./autogen.sh
./configure --enable-devtpm
make
```

`--enable-devtpm` uses the kernel node only. Use `--enable-autodetect` instead if you want wolfTPM to try `/dev/tpmrm0`, then `/dev/tpm0`, and finally fall back to probing SPI. This is useful for one binary that has to run on several boards.

Only one transport can be enabled at a time. `--enable-devtpm` conflicts with `--enable-swtpm` and `--enable-winapi`, and configure stops if you ask for more than one.

#### The x86_64 and aarch64 default

A bare `./configure` on Linux x86_64 or aarch64 does not produce a build that talks to `/dev/tpmX`. On those hosts wolfTPM auto-enables the software TPMs (swTPM and fwTPM) so that `make check` passes with no hardware attached, and defining `WOLFTPM_SWTPM` suppresses the kernel-device autodetect path. The result talks to a simulator on TCP port 2321.

Selecting any hardware path explicitly turns that default back off: `--enable-autodetect`, `--enable-devtpm`, or any `--enable-<vendor>`. Configure prints a notice when the software default is taken, so check the end of its output if a build unexpectedly fails to find your TPM.

This matters most on single-board aarch64 machines with a firmware TPM, where the kernel device is the only transport there is.

### Permissions

The TPM character devices are not world-accessible. On a typical system they are mode `0660` owned by group `tss`:

```
crw-rw---- 1 tss root  10,   224 /dev/tpm0
crw-rw---- 1 tss tss  252, 65536 /dev/tpmrm0
```

wolfTPM detects `EACCES` and reports it plainly:

```
Permission denied on /dev/tpm0
Use sudo or add tss group to user.
```

The fix is to put your user in the owning group and start a new login session:

```bash
sudo usermod -aG tss $USER
```

The `tss` group is created by tpm2-tss. On distributions that ship it, the group frequently exists with no members, so this step is required even though the group looks correctly set up.

To use a group of your own instead, add a udev rule.

1. Create the group and add your user:

    ```bash
    sudo addgroup wolftpm
    sudo adduser [username] wolftpm
    ```

2. Create `/etc/udev/rules.d/wolftpm-udev.rules` containing:

    ```
    KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", GROUP="wolftpm"
    ```

3. Reload the rules with `sudo udevadm control -R`, then re-plug or reboot.

### NVIDIA Jetson Orin (Tegra234) firmware TPM

Jetson Orin platforms carry a TPM 2.0 implemented in firmware, running as a trusted application inside OP-TEE rather than as a discrete package on a bus. Linux reaches it through the `tpm_ftpm_tee` driver, which speaks to the TA over the TEE interface and registers an ordinary TPM chip. From the point of view of wolfTPM it is just another `/dev/tpmrm0`.

Confirm the device is present before building:

```bash
lsmod | grep tpm_ftpm_tee
ls -l /dev/tpm*
cat /sys/class/tpm/tpm0/tpm_version_major     # expect 2
```

If the module is missing, try `sudo modprobe tpm_ftpm_tee` and check that the kernel was configured with `CONFIG_TCG_FTPM_TEE`. On NVIDIA Jetson Linux (L4T) images the driver is present and an `fTPM Device Provisioning Service` systemd unit runs at boot. You can see it complete in the boot log.

An OP-TEE boot message about silicon-identity fTPM provisioning not being enabled refers to a separate NVIDIA feature. It does not mean the TPM 2.0 device is unavailable.

Build as above with `--enable-devtpm` or `--enable-autodetect`, then confirm with:

```bash
./examples/wrap/caps
```

Because this is a firmware TPM, expect two differences from a discrete part. There is no TIS bus, so the `TPM2: Caps/Did/Vid/Rid` values do not exist and the device is identified purely from `TPM2_GetCapability` properties. Under `--enable-devtpm` the `DEBUG_WOLFTPM` line is still printed but reads all zeros. Under `--enable-autodetect`, `wolfTPM2_Init_ex` returns as soon as the kernel device opens, before that printf, so the line is absent entirely. Also, the algorithm coverage of a firmware TPM is set by its firmware build rather than by a datasheet, so check it rather than assuming. Where an operation is absent, the benchmark reports it as unsupported rather than failing. The Jetson Orin fTPM supports every operation the benchmark exercises.

### Testing

The examples run unchanged on this transport:

```bash
./examples/wrap/caps
./examples/native/native_test
./examples/wrap/wrap_test
./examples/bench/bench
./examples/run_examples.sh
```

`run_examples.sh` already skips the locality test on backends that do not support it.

### CI coverage

Both `--enable-devtpm` and `--enable-autodetect` are build-tested in CI, but not run, because GitHub-hosted runners have no `/dev/tpm*` node. Runtime coverage of this transport requires a self-hosted runner with a real TPM bound to the kernel driver.

## Windows TBS API

wolfTPM can be built to use the Windows native TBS (TPM Base Services). When using the Windows TBS interface, NV access is blocked by default. TPM NV storage space is very limited, and when it fills up it can cause undefined behavior, such as failures loading key handles. NV space is not managed by TBS.

The TPM is designed to return an encrypted private key blob on key creation using `TPM2_Create`, which you can safely store on disk and load when needed. The symmetric encryption key used to protect the private key blob is only known by the TPM. When you load a key using `TPM2_Load` you get a transient handle, which can be used for signing and for encryption and decryption.

For primary keys created with `TPM2_CreatePrimary` you get back a handle. No encrypted private data is returned. That handle remains loaded until `TPM2_FlushContext` is called.

For normal key creation using `TPM2_Create` you get back a `TPM2B_PRIVATE outPrivate`, which is the encrypted blob that you can store and load at any time using `TPM2_Load`.

### Limitations

wolfTPM has been tested on Windows 10 with TPM 2.0 devices. Windows does support TPM 1.2, but functionality is limited and wolfTPM does not support it.

The presence of a TPM 2.0 can be checked by opening PowerShell and running `Get-PnpDevice -Class SecurityDevices`:

```
Status     Class           FriendlyName
------     -----           ------------
OK         SecurityDevices Trusted Platform Module 2.0
Unknown    SecurityDevices Trusted Platform Module 2.0
```

### Building in MSYS2

Tested using MSYS2:

```bash
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

To install the development base tools on MSYS2 use `pacman -S base-devel` and `pacman -S mingw-w64-x86_64-toolchain`.

### Building on Linux

Tested using mingw-w32-bin_x86_64-linux_20131221.tar.bz2 from the [MinGW-w64 Win32 toolchain builds](https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win32/Automated%20Builds/).

Extract the tools and add them to the `PATH`:

```bash
mkdir mingw_tools
cd mingw_tools
tar xjvf ../mingw-w32-bin_x86_64-linux_20131221.tar.bz2
export PATH=$PWD/bin/:$PWD/i686-w64-mingw32/bin:$PATH
cd ..
```

Build:

```bash
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

### Running on Windows

To confirm the presence and status of the TPM on the machine, run `tpm.msc`. See `examples/README.md` in the source tree for running the examples.

## See Also

- [Getting Started](getting-started.md)
- [Building wolfTPM](building.md)
- [Build Options](build-options.md)
- [Supported Hardware](supported-hardware.md)
