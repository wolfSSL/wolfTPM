# wolfTPM with the Linux Kernel TPM Device (/dev/tpmX)

On Linux the kernel's TPM driver stack exposes a TPM through a character device, and wolfTPM can use it directly instead of driving SPI or I2C itself. This is the right transport whenever the kernel already owns the TPM: a discrete chip bound to a kernel driver, a Windows-style firmware TPM, or a TEE-resident firmware TPM such as the one on NVIDIA Jetson platforms.

With `--enable-devtpm` there is **no TIS layer and no HAL IO callback**: `hal/tpm_io.c` is compiled out entirely and `TPM2_IoCb` is `NULL` (see `hal/tpm_io.h`), so pass `NULL` for the callback argument of `TPM2_Init` / `wolfTPM2_Init`.

With `--enable-autodetect` this is **not** the case. The TIS/SPI HAL stays compiled in on purpose - it is the fallback - and `TPM2_IoCb` is a real function. Keep passing it, or the SPI fallback that build exists to provide is unreachable.

## Two device nodes

The kernel presents up to two nodes per TPM:

* `/dev/tpm0` - the raw device. One user at a time, no resource management. Whatever you send reaches the TPM.
* `/dev/tpmrm0` - the in-kernel resource manager (kernel 4.12+, practical from 5.12+). It virtualizes handles, swaps transient objects and sessions in and out as needed, and flushes everything belonging to a connection when that connection closes.

wolfTPM prefers `/dev/tpmrm0` and falls back to `/dev/tpm0`. The resource manager is the better default: a TPM has very few transient object slots, and without it a program that leaks a handle wedges the TPM for everything else on the system.

Build-time overrides, honored by both `--enable-devtpm` and `--enable-autodetect`:

* `-DWOLFTPM_USE_TPMRM` - use `/dev/tpmrm0` only, with no fallback to the raw device.
* `CFLAGS='-DTPM2_LINUX_DEV="/dev/tpm1"'` - use a specific node. The inner quotes are required: the macro is used directly as a C string literal, so an unquoted value does not compile.

## Startup, shutdown, and shared state

The TPM is started by firmware long before Linux runs, and on the resource manager it is shared with every other process on the system. Restarting or shutting it down is therefore not an individual caller's decision, so wolfTPM stays out of the way on this transport:

* `wolfTPM2_Init` skips the startup and self-test sequence.
* `wolfTPM2_Reset` and `wolfTPM2_Shutdown` send no TPM command and return `NOT_COMPILED_IN` (-174), the same way `wolfTPM2_SetLocality` does on this transport. A `wolfTPM2_Reset(dev, 0, 0)` that asked for neither a shutdown nor a startup still returns `TPM_RC_SUCCESS`, since nothing was declined. Treat `NOT_COMPILED_IN` here as "the OS owns this", not as a failure.
* `wolfTPM2_SetLocality` returns `NOT_COMPILED_IN` - the kernel owns the locality.

Be aware that the kernel does **not** reliably stop you here. Command filtering on `/dev/tpmrm0` is primarily about handle isolation, not about blocking global state changes, and behavior varies by kernel version and TPM implementation. On Linux 5.15 with the Jetson OP-TEE fTPM, a `TPM2_Shutdown(TPM_SU_CLEAR)` sent through the resource manager is passed straight through and returns success - both from wolfTPM and from `tpm2_shutdown`. So this is a case where the library declining to send the command is what protects other users of the TPM, rather than the kernel doing it for you.

If you genuinely need to control TPM startup state, you need `/dev/tpm0` and exclusive use of the TPM, or direct SPI access with wolfTPM's own TIS driver.

## What the native API does on autodetect builds

Two behaviors worth knowing if you use `TPM2_Init` / `TPM2_Init_ex` directly rather than the `wolfTPM2_*` wrapper.

**The kernel device wins over your callback.** If `/dev/tpmrm0` or `/dev/tpm0` opens, every command is routed there and the HAL IO callback you passed is never invoked. On a host that has both a kernel-bound TPM and a discrete SPI part, that means you now talk to a different TPM than a pre-autodetect build did. Pin the part you want with `--enable-devtpm`, `--enable-spi` / `--enable-<vendor>`, or `-DTPM2_LINUX_DEV`.

**Init now acquires a descriptor.** `TPM2_Init*` opens the device on autodetect builds, and `TPM2_Cleanup()` is what closes it. Native callers that skipped cleanup previously leaked nothing; now they leak a descriptor per context. This matters most on hosts exposing only the raw `/dev/tpm0`, which permits a single open - a context that merely initialized holds the TPM exclusively for its lifetime, and a second context in the same process falls through to a different transport.

`TPM2_Init_minimal()` is unaffected: it performs no IO and still succeeds with no device present.

## Transient handles do not outlive a process

This is the difference most likely to break an existing application.

On `/dev/tpmrm0` the kernel gives each open file description its own handle space. Transient object handles are **virtualized** - the value the TPM assigned is not the value you get back - and everything in that space is **flushed when the file descriptor closes**. So a transient key created by one process is gone by the time a second process runs, and the handle number it printed is meaningless to anyone else.

Creating a primary key on the Jetson fTPM through the resource manager returns:

```
Create Primary Handle: 0x80ffffff
```

not the `0x80000000` a raw device would report. Query the transient handles from a separate process afterwards and the list is empty:

```bash
tpm2_getcap handles-transient      # no output - the space was torn down
```

Two practical consequences:

* A "create a key, keep it, use it from the next command" workflow does not work across processes. Do the whole sequence in one process, or make the object persistent with `TPM2_EvictControl` so it gets a stable `0x81xxxxxx` handle that does survive.
* Passing a hard-coded transient handle such as `0x80000000` on a command line will fail. The kernel rejects the reference before it reaches the TPM, and because that happens at the file-descriptor layer the error surfaces as an `errno 22 = Invalid argument` on `read()`, which wolfTPM reports as `TPM_RC_FAILURE` rather than as a handle error. If you see `TPM_RC_FAILURE` alongside `Failed to read from /dev/tpmrm0 ... errno 22`, suspect a stale or cross-process transient handle before suspecting the TPM.

wolfTPM's own `examples/run_examples.sh` hits exactly this: its provisioning section creates IAK and IDevID primaries with `-keep` in one process and then references `0x80000000` / `0x80000001` from another. That block cannot pass on the resource manager by construction. Everything either side of it is unaffected. Use `/dev/tpm0` with exclusive access if you need to run it as written.

## Building

```bash
./autogen.sh
./configure --enable-devtpm
make
```

`--enable-devtpm` uses the kernel node only. Use `--enable-autodetect` instead if you want wolfTPM to try `/dev/tpmrm0`, then `/dev/tpm0`, and finally fall back to probing SPI - useful for one binary that has to run on several boards.

Only one transport can be enabled at a time. `--enable-devtpm` conflicts with `--enable-swtpm` and `--enable-winapi`, and configure will stop if you ask for more than one.

### The x86_64 / aarch64 default

A bare `./configure` on Linux `x86_64` or `aarch64` does **not** produce a build that talks to `/dev/tpmX`. On those hosts wolfTPM auto-enables the software TPMs (swTPM and fwTPM) so that `make check` passes with no hardware attached, and defining `WOLFTPM_SWTPM` suppresses the kernel-device autodetect path. The result talks to a simulator on TCP port 2321.

Selecting any hardware path explicitly turns that default back off - `--enable-autodetect`, `--enable-devtpm`, or any `--enable-<vendor>`. Configure prints a notice when the software default is taken, so check the tail of its output if a build unexpectedly fails to find your TPM.

This bites hardest on single-board `aarch64` machines with a firmware TPM, where the kernel device is the only transport there is.

## Permissions

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

Note that the `tss` group is created by tpm2-tss, and on distributions that ship it the group frequently exists with no members - so this step is required even though the group looks correctly set up.

To use a group of your own instead, add a udev rule:

1) Create the group and add your user:

```bash
sudo addgroup wolftpm
sudo adduser [username] wolftpm
```

2) Create `/etc/udev/rules.d/wolftpm-udev.rules` containing:

```
KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", GROUP="wolftpm"
```

3) Reload the rules: `sudo udevadm control -R`, then re-plug or reboot.

## NVIDIA Jetson Orin (Tegra234) firmware TPM

Jetson Orin platforms carry a TPM 2.0 implemented in firmware, running as a trusted application inside OP-TEE rather than as a discrete package on a bus. Linux reaches it through the `tpm_ftpm_tee` driver, which speaks to the TA over the TEE interface and registers an ordinary TPM chip - so from wolfTPM's point of view it is just another `/dev/tpmrm0`.

Confirm the device is present before building:

```bash
lsmod | grep tpm_ftpm_tee
ls -l /dev/tpm*
cat /sys/class/tpm/tpm0/tpm_version_major     # expect 2
```

If the module is missing, try `sudo modprobe tpm_ftpm_tee` and check that the kernel was configured with `CONFIG_TCG_FTPM_TEE`. On NVIDIA's Jetson Linux (L4T) images the driver is present and an `fTPM Device Provisioning Service` systemd unit runs at boot; you can see it complete in the boot log.

Note that an OP-TEE boot message about silicon-identity fTPM provisioning not being enabled refers to a separate NVIDIA feature and does **not** mean the TPM 2.0 device is unavailable.

Build as above with `--enable-devtpm` or `--enable-autodetect`, then confirm with:

```bash
./examples/wrap/caps
```

Because this is a firmware TPM, expect two differences from a discrete part. There is no TIS bus, so the `TPM2: Caps/Did/Vid/Rid` values do not exist and the device is identified purely from `TPM2_GetCapability` properties. Under `--enable-devtpm` the `DEBUG_WOLFTPM` line is still printed but reads all zeros; under `--enable-autodetect` `wolfTPM2_Init_ex` returns as soon as the kernel device opens, before that printf, so the line is absent entirely. And a firmware TPM's algorithm coverage is set by its firmware build rather than by a datasheet, so it is worth checking rather than assuming; where an operation is absent the benchmark reports it as unsupported rather than failing. The Jetson Orin fTPM supports every operation the benchmark exercises - see the README results.

See the main [README.md](../README.md#device-identification) for this platform's identification values and benchmark results.

## Testing

The examples run unchanged on this transport:

```bash
./examples/wrap/caps
./examples/native/native_test
./examples/wrap/wrap_test
./examples/bench/bench
./examples/run_examples.sh
```

`run_examples.sh` already skips the locality test on backends that do not support it.

## CI coverage

Both `--enable-devtpm` and `--enable-autodetect` are build-tested in CI, but not run - GitHub-hosted runners have no `/dev/tpm*` node. Runtime coverage of this transport requires a self-hosted runner with a real TPM bound to the kernel driver.
