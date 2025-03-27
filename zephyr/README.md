Zephyr Project Port
===================

## Overview

This port is for the Zephyr RTOS Project, available [here](https://www.zephyrproject.org/).


It provides the following zephyr code.

- modules/lib/wolftpm
    - wolfTPM library code
- modules/lib/wolftpm/zephyr/
    - Configuration and CMake files for wolfTPM as a Zephyr module
- modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_caps
    - wolfTPM test application
- modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_test
    - wolfTPM test application

## How to setup as a Zephyr Module

Follow the [instructions](https://docs.zephyrproject.org/latest/develop/getting_started/index.html) to setup a zephyr project.

### Modify your project's west manifest

Add wolfTPM as a project to your west.yml:

```
manifest:
  remotes:
    # <your other remotes>
    - name: wolftpm
      url-base: https://github.com/wolfssl

  projects:
    # <your other projects>
    - name: wolftpm
      path: modules/lib/wolftpm
      revision: master
      remote: wolftpm
```

Note: wolfTPM has dependencies with wolfSSL so you need to also need to add wolfSSL into the west.yml like shown above.

Update west's modules:

```bash
west update
```

Now west recognizes 'wolftpm' as a module, and will include it's Kconfig and
CMakeFiles.txt in the build system.

## Build and Run Tests

### Build and Run wolfTPM wrap Test Application

If you want to run build apps without running `west zephyr-export` then it is
possible by setting the `CMAKE_PREFIX_PATH` variable to the location of the
zephyr sdk and building from the `zephyr` directory. For example:

```
CMAKE_PREFIX_PATH=/path/to/zephyr-sdk-<VERSION> west build -p always -b qemu_x86 ../modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_test/
```

build and execute `wolftpm_wrap_test`

```
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_test
west build -t run
```

### Build and Run wolfTPM wrap Capabilities Application

build and execute `wolftpm_wrap_caps`

```
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_caps
west build -t run
```
