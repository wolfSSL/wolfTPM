# CMakeList.txt
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# Usage:
# $ mkdir build
# $ cd build
# $ cmake ..
# $ cmake --build .
#
# To build with debugging use:
# $ cmake .. -DCMAKE_BUILD_TYPE=Debug
#
# See "Building with CMake" in INSTALL for more.

####################################################
# Project
####################################################

cmake_minimum_required(VERSION 3.16)

project(wolfTPM VERSION 4.1.0 LANGUAGES C)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(WOLFTPM_DEFINITIONS)

# Firmware TPM (fwTPM) server
set(WOLFTPM_FWTPM "no" CACHE STRING
    "Enable firmware TPM (fwTPM) server (default: disabled)")
set_property(CACHE WOLFTPM_FWTPM
    PROPERTY STRINGS "yes;no")
set(WOLFTPM_FWTPM_ONLY "no" CACHE STRING
    "Build only the fwTPM server, skip client library and examples (default: disabled)")
set_property(CACHE WOLFTPM_FWTPM_ONLY
    PROPERTY STRINGS "yes;no")
set(WOLFTPM_FWTPM_FUZZ "no" CACHE STRING
    "Enable fwTPM fuzz target (requires libFuzzer, default: disabled)")
set_property(CACHE WOLFTPM_FWTPM_FUZZ
    PROPERTY STRINGS "yes;no")
set(WOLFTPM_FWTPM_NV_APPEND_ONLY "no" CACHE STRING
    "Enable append-only NV journal for write-once flash fwTPM ports (default: disabled)")
set_property(CACHE WOLFTPM_FWTPM_NV_APPEND_ONLY
    PROPERTY STRINGS "yes;no")

# fwtpm-only forces fwtpm on
if(WOLFTPM_FWTPM_ONLY)
    set(WOLFTPM_FWTPM "yes" CACHE STRING "" FORCE)
endif()

# Build wolftpm client library unless fwtpm-only mode
if(WOLFTPM_FWTPM_ONLY)
    set(BUILD_WOLFTPM_LIB OFF)
else()
    set(BUILD_WOLFTPM_LIB ON)
endif()

set(TPM_SOURCES
    src/tpm2.c
    src/tpm2_linux.c
    src/tpm2_packet.c
    src/tpm2_param_enc.c
    src/tpm2_swtpm.c
    src/tpm2_tis.c
    src/tpm2_winapi.c
    src/tpm2_wrap.c
    src/tpm2_asn.c
    src/tpm2_crypto.c
    src/tpm2_util.c
    src/tpm2_cryptocb.c
    hal/tpm_io.c
    )


# default to build shared library
option(BUILD_SHARED_LIBS "Build shared libraries (.dll/.so) instead of static ones (.lib/.a)" ON)
if(BUILD_WOLFTPM_LIB)
    add_library(wolftpm ${TPM_SOURCES})
    target_compile_definitions(wolftpm PRIVATE
        "BUILDING_WOLFTPM"
        )
endif()

include(CheckIncludeFile)
check_include_file("fcntl.h" HAVE_FCNTL_H)
check_include_file("netdb.h" HAVE_NETDB_H)
check_include_file("time.h" HAVE_TIME_H)
check_include_file("sys/ioctl.h" HAVE_SYS_IOCTL_H)
check_include_file("sys/socket.h" HAVE_SYS_SOCKET_H)
check_include_file("sys/time.h" HAVE_SYS_TIME_H)
check_include_file("errno.h" HAVE_ERRNO_H)
check_include_file("stdint.h" HAVE_STDINT_H)
check_include_file("stdlib.h" HAVE_STDLIB_H)
check_include_file("string.h" HAVE_STRING_H)
check_include_file("sys/stat.h" HAVE_SYS_STAT_H)
check_include_file("sys/types.h" HAVE_SYS_TYPES_H)
check_include_file("unistd.h" HAVE_UNISTD_H)

include(CheckFunctionExists)
check_function_exists("gethostbyname" HAVE_GETHOSTBYNAME)
check_function_exists("getaddrinfo" HAVE_GETADDRINFO)
check_function_exists("gettimeofday" HAVE_GETTIMEOFDAY)
check_function_exists("getpid" HAVE_GETPID)



# TODO
# * (All major options have been implemented)

# Single threaded
set(WOLFTPM_SINGLE_THREADED "no" CACHE STRING
    "Enable wolfTPM single threaded (default: disabled)")
set_property(CACHE WOLFTPM_SINGLE_THREADED
    PROPERTY STRINGS "yes;no")
if(WOLFTPM_SINGLE_THREADED)
    list(APPEND WOLFTPM_DEFINITIONS
        "-DSINGLE_THREADED")
endif()

# Mutex locking
if(WOLFTPM_SINGLE_THREADED)
    set(_WOLFTPM_NO_LOCK_DEFAULT "yes")
else()
    set(_WOLFTPM_NO_LOCK_DEFAULT "no")
endif()
set(WOLFTPM_NO_LOCK "${_WOLFTPM_NO_LOCK_DEFAULT}" CACHE STRING
    "Disable thread mutex locking (default: ${_WOLFTPM_NO_LOCK_DEFAULT})")
set_property(CACHE WOLFTPM_NO_LOCK
    PROPERTY STRINGS "yes;no")
if(WOLFTPM_NO_LOCK)
    list(APPEND WOLFTPM_DEFINITIONS
        "-DWOLFTPM_NO_LOCK")
endif()

# Active TPM - Thread local storage
set(WOLFTPM_NO_ACTIVE_THREAD_LS "no" CACHE STRING
    "Disable active TPM thread local storage (default: disabled)")
set_property(CACHE WOLFTPM_NO_ACTIVE_THREAD_LS
    PROPERTY STRINGS "yes;no")
if(WOLFTPM_NO_ACTIVE_THREAD_LS)
    list(APPEND WOLFTPM_DEFINITIONS
        "-DWOLFTPM_NO_ACTIVE_THREAD_LS")
endif()

# Provisioning
set(WOLFTPM_PROVISIONING "yes" CACHE STRING
    "Enable support for Provisioning Initial Device Identity (IDevID) and Attestation Identity Keys (default: enabled)")
set_property(CACHE WOLFTPM_PROVISIONING
    PROPERTY STRINGS "yes;no")
if(WOLFTPM_PROVISIONING)
    list(APPEND WOLFTPM_DEFINITIONS
        "-DWOLFTPM_PROVISIONING")
endif()

# Enable Debugging
set(WOLFTPM_DEBUG "no" CACHE STRING
    "Enables option for debug (default: disabled)")
set_property(CACHE WOLFTPM_DEBUG
    PROPERTY STRINGS "no;yes;verbose;io")
if(NOT "${WOLFTPM_DEBUG}" STREQUAL "no")
    list(APPEND WOLFTPM_DEFINITIONS
        "-DDEBUG_WOLFTPM"
        "-DDEBUG")
    if("${WOLFTPM_DEBUG}" STREQUAL "verbose" OR "${WOLFTPM_DEBUG}" STREQUAL "io")
        list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_DEBUG_VERBOSE")
    endif()
    if("${WOLFTPM_DEBUG}" STREQUAL "io")
        list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_DEBUG_IO")
    endif()
endif()

# Device Interface
set(WOLFTPM_INTERFACE "auto" CACHE STRING
    "Select interface to TPM")
set_property(CACHE WOLFTPM_INTERFACE
    PROPERTY STRINGS "auto;SWTPM;WINAPI;DEVTPM;SPI;I2C;MMIO")

# automatically set
message("INTERFACE ${WOLFTPM_INTERFACE}")
if("${WOLFTPM_INTERFACE}" STREQUAL "auto")
    message("auto")
    if(WIN32 OR MINGW OR MSYS)
        message("Detected windows, using WIN TBS API")
        set_property(CACHE WOLFTPM_INTERFACE PROPERTY VALUE "WINAPI")
    elseif(UNIX)
        message("Detected *nix. using kernel device for interface")
        set_property(CACHE WOLFTPM_INTERFACE PROPERTY VALUE "DEVTPM")
    else()
        set_property(CACHE WOLFTPM_INTERFACE PROPERTY VALUE "SWTPM")
    endif(WIN32 OR MINGW OR MSYS)
endif("${WOLFTPM_INTERFACE}" STREQUAL "auto")


if(WIN32 AND BUILD_WOLFTPM_LIB)
    target_compile_definitions(wolftpm PRIVATE
        "WOLFTPM_DLL"
        )
endif()

if("${WOLFTPM_INTERFACE}" STREQUAL "SWTPM")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_SWTPM")

    # SWTPM port configuration
    set(WOLFTPM_SWTPM_PORT "2321" CACHE STRING
        "Set SWTPM socket port (default: 2321)")
    list(APPEND WOLFTPM_DEFINITIONS "-DTPM2_SWTPM_PORT=${WOLFTPM_SWTPM_PORT}")

    # Link Winsock for socket transport on Windows
    if(WIN32 AND BUILD_WOLFTPM_LIB)
        target_link_libraries(wolftpm PRIVATE ws2_32)
    endif()

elseif("${WOLFTPM_INTERFACE}" STREQUAL "DEVTPM")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_LINUX_DEV")

elseif("${WOLFTPM_INTERFACE}" STREQUAL "WINAPI")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_WINAPI")
    if(BUILD_WOLFTPM_LIB)
        target_link_libraries(wolftpm PRIVATE tbs)
    endif()

elseif("${WOLFTPM_INTERFACE}" STREQUAL "SPI")
    # SPI interface

elseif("${WOLFTPM_INTERFACE}" STREQUAL "I2C")
    # I2C interface - requires I2C (ADV_IO will be enabled automatically in ADV_IO section)
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_I2C")

elseif("${WOLFTPM_INTERFACE}" STREQUAL "MMIO")
    # MMIO interface - requires MMIO (ADV_IO will be enabled automatically in ADV_IO section)
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_MMIO")

else()
    get_property(INTERFACE_OPTS CACHE WOLFTPM_INTERFACE
        PROPERTY STRINGS)
    message(FATAL_ERROR "\"${WOLFTPM_INTERFACE}\" is not known WOLFTPM_INTERFACE:"
        " ${INTERFACE_OPTS}")
endif()

# TPM Module Selection
set(WOLFTPM_MODULE "auto" CACHE STRING
    "Select TPM hardware module (default: auto)")
set_property(CACHE WOLFTPM_MODULE
    PROPERTY STRINGS "auto;microchip;attpm20;mchp;st33;nuvoton;npct75x;slb9670;slb9672;slb9673")

message("TPM MODULE ${WOLFTPM_MODULE}")

if("${WOLFTPM_MODULE}" STREQUAL "auto")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_AUTODETECT")
elseif("${WOLFTPM_MODULE}" STREQUAL "microchip" OR
       "${WOLFTPM_MODULE}" STREQUAL "attpm20" OR
       "${WOLFTPM_MODULE}" STREQUAL "mchp")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_MICROCHIP")
elseif("${WOLFTPM_MODULE}" STREQUAL "st33")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_ST33")
elseif("${WOLFTPM_MODULE}" STREQUAL "nuvoton" OR
       "${WOLFTPM_MODULE}" STREQUAL "npct75x")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_NUVOTON")
elseif("${WOLFTPM_MODULE}" STREQUAL "slb9670")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_SLB9670")
elseif("${WOLFTPM_MODULE}" STREQUAL "slb9672")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_SLB9672")
elseif("${WOLFTPM_MODULE}" STREQUAL "slb9673")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_SLB9673")
else()
    get_property(MODULE_OPTS CACHE WOLFTPM_MODULE
        PROPERTY STRINGS)
    message(FATAL_ERROR "\"${WOLFTPM_MODULE}\" is not a known WOLFTPM_MODULE:"
        " ${MODULE_OPTS}")
endif()

# Wrapper
set(WOLFTPM_WRAPPER "yes" CACHE STRING
    "Enable wrapper code (default: enabled)")
set_property(CACHE WOLFTPM_WRAPPER
    PROPERTY STRINGS "yes;no")
if(NOT WOLFTPM_WRAPPER)
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM2_NO_WRAPPER")
endif()

# I2C Support (for backward compatibility - use WOLFTPM_INTERFACE=I2C for new code)
set(WOLFTPM_I2C "no" CACHE STRING
    "Enable I2C TPM Support (default: disabled, use WOLFTPM_INTERFACE=I2C for new code)")
set_property(CACHE WOLFTPM_I2C
    PROPERTY STRINGS "yes;no")

# Handle I2C option for backward compatibility
# If interface is not SPI or I2C, and I2C is explicitly enabled, set interface to I2C
if(WOLFTPM_I2C OR "${WOLFTPM_INTERFACE}" STREQUAL "I2C")
    # Backward compatibility: if I2C is enabled and interface is not SPI/I2C, enable I2C definition
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_I2C")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_ADV_IO")
endif()

# MMIO Support (deprecated - use WOLFTPM_INTERFACE=MMIO for new code)
set(WOLFTPM_MMIO "no" CACHE STRING
    "Enable built-in MMIO callbacks (deprecated: use WOLFTPM_INTERFACE=MMIO for new code)")
set_property(CACHE WOLFTPM_MMIO
    PROPERTY STRINGS "yes;no")
# Handle MMIO option for backward compatibility
# If interface is MMIO or MMIO is explicitly enabled, set MMIO definition
if(WOLFTPM_MMIO OR "${WOLFTPM_INTERFACE}" STREQUAL "MMIO")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_MMIO")
endif()

# Advanced IO
set(WOLFTPM_ADVIO "no" CACHE STRING
    "Enable Advanced IO (default: disabled)")
set_property(CACHE WOLFTPM_ADVIO
    PROPERTY STRINGS "yes;no")
# ADV_IO is automatically enabled for I2C or MMIO interfaces
if(WOLFTPM_ADVIO OR WOLFTPM_I2C OR WOLFTPM_MMIO OR
   "${WOLFTPM_INTERFACE}" STREQUAL "I2C" OR
   "${WOLFTPM_INTERFACE}" STREQUAL "MMIO")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_ADV_IO")
endif()

# TIS / SPI Check Wait State support
set(WOLFTPM_CHECK_WAIT_STATE "auto" CACHE STRING
    "Enable TIS / SPI Check Wait State support (default: auto - depends on chip)")
set_property(CACHE WOLFTPM_CHECK_WAIT_STATE
    PROPERTY STRINGS "yes;no;auto")
# Check wait state is required for all TPM except Infineon
if("${WOLFTPM_CHECK_WAIT_STATE}" STREQUAL "auto")
    if(NOT "${WOLFTPM_MODULE}" STREQUAL "infineon" AND
        NOT "${WOLFTPM_MODULE}" STREQUAL "slb9670" AND
        NOT "${WOLFTPM_MODULE}" STREQUAL "slb9672" AND
        NOT "${WOLFTPM_MODULE}" STREQUAL "slb9673")
        set(WOLFTPM_CHECK_WAIT_STATE_ENABLED ON)
    else()
        set(WOLFTPM_CHECK_WAIT_STATE_ENABLED OFF)
    endif()
elseif(WOLFTPM_CHECK_WAIT_STATE)
    set(WOLFTPM_CHECK_WAIT_STATE_ENABLED ON)
else()
    set(WOLFTPM_CHECK_WAIT_STATE_ENABLED OFF)
endif()
if(WOLFTPM_CHECK_WAIT_STATE_ENABLED)
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_CHECK_WAIT_STATE")
endif()

# TIS Layer Named Semaphore locking
set(WOLFTPM_TIS_LOCK "no" CACHE STRING
    "TIS Layer Named Semaphore locking for concurrent access between processes (default: disabled)")
set_property(CACHE WOLFTPM_TIS_LOCK
    PROPERTY STRINGS "yes;no")
if(WOLFTPM_TIS_LOCK)
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_TIS_LOCK")
endif()

# Small Stack
set(WOLFTPM_SMALL_STACK "no" CACHE STRING
    "Enable Small Stack Usage (default: disabled)")
set_property(CACHE WOLFTPM_SMALL_STACK
    PROPERTY STRINGS "yes;no")
if(WOLFTPM_SMALL_STACK)
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_SMALL_STACK")
    list(APPEND WOLFTPM_DEFINITIONS "-DMAX_COMMAND_SIZE=1024")
    list(APPEND WOLFTPM_DEFINITIONS "-DMAX_RESPONSE_SIZE=1350")
    list(APPEND WOLFTPM_DEFINITIONS "-DMAX_DIGEST_BUFFER=896")
    # If wolfCrypt is disabled, set MAX_SESSION_NUM=1
    if(NOT WITH_WOLFSSL AND NOT WITH_WOLFSSL_TREE AND NOT WOLFSSL_FOUND AND NOT wolfssl_FOUND)
        list(APPEND WOLFTPM_DEFINITIONS "-DMAX_SESSION_NUM=1")
    endif()
endif()

# Example HAL
set(WOLFTPM_HAL "yes" CACHE STRING
    "Enable example HAL interfaces (default: enabled)")
set_property(CACHE WOLFTPM_HAL
    PROPERTY STRINGS "yes;no")
if(WOLFTPM_HAL OR WOLFTPM_MMIO OR "${WOLFTPM_INTERFACE}" STREQUAL "MMIO")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_EXAMPLE_HAL")
endif()

# Firmware Upgrade
set(WOLFTPM_FIRMWARE "yes" CACHE STRING
    "Enable support for TPM firmware upgrades (default: enabled)")
set_property(CACHE WOLFTPM_FIRMWARE
    PROPERTY STRINGS "yes;no")
if(WOLFTPM_FIRMWARE)
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_FIRMWARE_UPGRADE")
endif()

# fwTPM definitions (after interface detection)
if(WOLFTPM_FWTPM)
    # WOLFTPM_FWTPM_BUILD goes into options.h for build detection
    # Note: WOLFTPM_FWTPM itself is only set per-target on fwtpm_server/unit_test
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_FWTPM_BUILD")
    # Determine TIS vs socket transport
    if(NOT "${WOLFTPM_INTERFACE}" STREQUAL "SWTPM")
        list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_FWTPM_HAL")
        list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_ADV_IO")
        set(WOLFTPM_FWTPM_TIS ON)
    else()
        set(WOLFTPM_FWTPM_TIS OFF)
    endif()
endif()

# If fwtpm-only, force examples off and disable wrapper
if(WOLFTPM_FWTPM_ONLY)
    set(WOLFTPM_EXAMPLES OFF CACHE BOOL "" FORCE)
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM2_NO_WRAPPER")
endif()

# Examples
set(WOLFTPM_EXAMPLES "yes" CACHE BOOL
    "Build examples")

if(BUILD_WOLFTPM_LIB)
    target_include_directories(wolftpm
        PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        )
endif()

# wolfSSL/wolfCrypt dependency (shared between wolftpm library and fwtpm targets)
add_library(wolftpm_wolfssl_dep INTERFACE)
set(WOLFCRYPT_AVAILABLE OFF)

if (WITH_WOLFSSL)
    target_link_libraries(wolftpm_wolfssl_dep INTERFACE wolfssl)
    target_include_directories(wolftpm_wolfssl_dep INTERFACE ${WITH_WOLFSSL}/include)
    target_link_directories(wolftpm_wolfssl_dep INTERFACE ${WITH_WOLFSSL}/lib)
    set(WOLFCRYPT_AVAILABLE ON)
elseif (WITH_WOLFSSL_TREE)
    set(WOLFSSL_TPM "yes" CACHE STRING "")
    set(WOLFSSL_EXAMPLES "no" CACHE STRING "")
    set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "")
    add_subdirectory(${WITH_WOLFSSL_TREE} wolfssl)
    target_link_libraries(wolftpm_wolfssl_dep INTERFACE wolfssl)
    set(WOLFCRYPT_AVAILABLE ON)
else()
    find_package(PkgConfig)
    pkg_check_modules(WOLFSSL wolfssl)

    if (WOLFSSL_FOUND)
        target_link_libraries(wolftpm_wolfssl_dep INTERFACE ${WOLFSSL_LIBRARIES})
        target_include_directories(wolftpm_wolfssl_dep INTERFACE ${WOLFSSL_INCLUDE_DIRS})
        target_link_directories(wolftpm_wolfssl_dep INTERFACE ${WOLFSSL_LIBRARY_DIRS})
        target_compile_options(wolftpm_wolfssl_dep INTERFACE ${WOLFSSL_CFLAGS_OTHER})
        set(WOLFCRYPT_AVAILABLE ON)
    else()
        # For support with vcpkg
        find_package(wolfssl CONFIG REQUIRED)
        if (wolfssl_FOUND)
            target_link_libraries(wolftpm_wolfssl_dep INTERFACE wolfssl::wolfssl)
            set(WOLFCRYPT_AVAILABLE ON)
        else()
            list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM2_NO_WOLFCRYPT")
        endif()
    endif()
endif()

# Link wolftpm library to wolfSSL.
# PRIVATE so the wolftpm_wolfssl_dep INTERFACE helper does not become part
# of wolftpm's export set (it is build-tree-only). Downstream consumers of
# wolftpm should `find_package(wolfssl)` themselves before find_package(wolftpm).
if(BUILD_WOLFTPM_LIB)
    target_link_libraries(wolftpm PRIVATE $<BUILD_INTERFACE:wolftpm_wolfssl_dep>)
endif()

# fwTPM requires wolfCrypt
if(WOLFTPM_FWTPM AND NOT WOLFCRYPT_AVAILABLE)
    message(FATAL_ERROR
        "fwTPM requires wolfCrypt. Provide wolfSSL via -DWITH_WOLFSSL=<path>, "
        "-DWITH_WOLFSSL_TREE=<path>, or install it system-wide.")
endif()

if (WOLFTPM_EXAMPLES AND BUILD_WOLFTPM_LIB)
    add_library(tpm_test_lib STATIC
        examples/tpm_test_keys.c
        )
    # wolftpm_wolfssl_dep is needed explicitly because wolftpm now links it
    # PRIVATE (so wolfSSL does not leak into wolftpm's installed export set).
    target_link_libraries(tpm_test_lib PRIVATE wolftpm wolftpm_wolfssl_dep)
endif()

function(add_tpm_example name src)
    add_executable(${name}
        examples/${src}
        )
    target_link_libraries(${name} PRIVATE wolftpm tpm_test_lib wolftpm_wolfssl_dep)
    if(WIN32)
        target_link_libraries(${name} PRIVATE ws2_32)
    endif()
endfunction()

####################################################
# fwTPM targets
####################################################

if(WOLFTPM_FWTPM)
    # Core fwTPM sources (shared between server, unit test, and fuzz)
    set(FWTPM_CORE_SOURCES
        src/fwtpm/fwtpm.c
        src/fwtpm/fwtpm_command.c
        src/fwtpm/fwtpm_crypto.c
        src/fwtpm/fwtpm_nv.c
        src/tpm2_util.c
        src/tpm2_packet.c
        src/tpm2_crypto.c
        src/tpm2_param_enc.c
    )

    # Server-specific sources
    set(FWTPM_SERVER_SOURCES
        ${FWTPM_CORE_SOURCES}
        src/fwtpm/fwtpm_io.c
        src/fwtpm/fwtpm_main.c
    )

    # TIS sources (when not using SWTPM socket transport)
    if(WOLFTPM_FWTPM_TIS)
        list(APPEND FWTPM_SERVER_SOURCES
            src/fwtpm/fwtpm_tis.c
            src/fwtpm/fwtpm_tis_shm.c
        )
    endif()

    # fwtpm_server executable
    add_executable(fwtpm_server ${FWTPM_SERVER_SOURCES})
    target_compile_definitions(fwtpm_server PRIVATE "WOLFTPM_FWTPM")
    if(WOLFTPM_FWTPM_TIS)
        target_compile_definitions(fwtpm_server PRIVATE "WOLFTPM_FWTPM_TIS")
    endif()
    if(WOLFTPM_FWTPM_NV_APPEND_ONLY)
        target_compile_definitions(fwtpm_server PRIVATE "WOLFTPM_FWTPM_NV_APPEND_ONLY")
    endif()
    target_link_libraries(fwtpm_server PRIVATE wolftpm_wolfssl_dep)
    target_include_directories(fwtpm_server PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    if(UNIX)
        target_link_libraries(fwtpm_server PRIVATE pthread)
        if(NOT APPLE)
            target_link_libraries(fwtpm_server PRIVATE rt)
        endif()
    elseif(WIN32)
        target_link_libraries(fwtpm_server PRIVATE ws2_32)
    endif()

    # fwtpm_unit_test executable
    add_executable(fwtpm_unit_test
        tests/fwtpm_unit_tests.c
        ${FWTPM_CORE_SOURCES}
    )
    target_compile_definitions(fwtpm_unit_test PRIVATE
        "WOLFTPM_FWTPM"
        "FWTPM_NV_FILE=\"fwtpm_test_nv.bin\""
    )
    if(WOLFTPM_FWTPM_NV_APPEND_ONLY)
        target_compile_definitions(fwtpm_unit_test PRIVATE "WOLFTPM_FWTPM_NV_APPEND_ONLY")
    endif()
    target_link_libraries(fwtpm_unit_test PRIVATE wolftpm_wolfssl_dep)
    target_include_directories(fwtpm_unit_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    if(UNIX)
        target_link_libraries(fwtpm_unit_test PRIVATE pthread)
    endif()

    # fwTPM fuzz target (libFuzzer)
    if(WOLFTPM_FWTPM_FUZZ)
        add_executable(fwtpm_fuzz
            tests/fuzz/fwtpm_fuzz.c
            ${FWTPM_CORE_SOURCES}
        )
        target_compile_definitions(fwtpm_fuzz PRIVATE "WOLFTPM_FWTPM")
        if(WOLFTPM_FWTPM_NV_APPEND_ONLY)
            target_compile_definitions(fwtpm_fuzz PRIVATE "WOLFTPM_FWTPM_NV_APPEND_ONLY")
        endif()
        target_link_libraries(fwtpm_fuzz PRIVATE wolftpm_wolfssl_dep)
        target_include_directories(fwtpm_fuzz PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_BINARY_DIR}
        )
        target_compile_options(fwtpm_fuzz PRIVATE "-fsanitize=fuzzer-no-link")
        target_link_options(fwtpm_fuzz PRIVATE "-fsanitize=fuzzer")
    endif()

    # CTest integration
    enable_testing()
    add_test(NAME fwtpm_unit_test
        COMMAND fwtpm_unit_test
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    message(STATUS "fwTPM server: enabled")
    if(WOLFTPM_FWTPM_TIS)
        message(STATUS "fwTPM transport: TIS/shared-memory")
    else()
        message(STATUS "fwTPM transport: socket (SWTPM)")
    endif()
    if(WOLFTPM_FWTPM_ONLY)
        message(STATUS "fwTPM mode: server-only (no client library)")
    endif()
endif()

function(add_to_options_file DEFINITIONS OPTION_FILE)
    list(REMOVE_DUPLICATES DEFINITIONS)
    foreach(DEF IN LISTS DEFINITIONS)
        if(DEF MATCHES "^-D")
            if(DEF MATCHES "^-D(N)?DEBUG(=.+)?")
                message("not outputting (N)DEBUG to ${OPTION_FILE}")
            endif()

            string(REGEX REPLACE "^-D" "" DEF_NO_PREFIX ${DEF})
            string(REGEX REPLACE "=.*$" "" DEF_NO_EQUAL_NO_VAL ${DEF_NO_PREFIX})
            string(REPLACE "=" " " DEF_NO_EQUAL ${DEF_NO_PREFIX})

            file(APPEND ${OPTION_FILE} "#undef  ${DEF_NO_EQUAL_NO_VAL}\n")
            file(APPEND ${OPTION_FILE} "#define ${DEF_NO_EQUAL}\n")

            file(APPEND ${OPTION_FILE} "\n")
        else()
            message("option w/o begin -D is ${DEF}, not saving to ${OPTION_FILE}")
        endif()
    endforeach()
endfunction()

add_definitions(${WOLFTPM_DEFINITIONS})

# generate options file
message("Generating user options header...")
if (${CMAKE_DISABLE_SOURCE_CHANGES})
    set(WOLFTPM_BUILD_OUT_OF_TREE_DEFAULT "${CMAKE_DISABLE_SOURCE_CHANGES}")
else()
    set(WOLFTPM_BUILD_OUT_OF_TREE_DEFAULT "no")
endif()

set(WOLFTPM_BUILD_OUT_OF_TREE "${WOLFTPM_BUILD_OUT_OF_TREE_DEFAULT}" CACHE STRING
    "Don't generate files in the source tree (default: ${WOLFTPM_BUILD_OUT_OF_TREE_DEFAULT})")
set_property(CACHE WOLFTPM_BUILD_OUT_OF_TREE
    PROPERTY STRINGS "yes;no")

if (${WOLFTPM_BUILD_OUT_OF_TREE})
   set(WOLFTPM_OUTPUT_BASE ${CMAKE_CURRENT_BINARY_DIR})
else()
   set(WOLFTPM_OUTPUT_BASE ${CMAKE_CURRENT_SOURCE_DIR})
endif()
set(OPTION_FILE "${WOLFTPM_OUTPUT_BASE}/wolftpm/options.h")

file(REMOVE ${OPTION_FILE})

file(APPEND ${OPTION_FILE} "/* wolftpm options.h\n")
file(APPEND ${OPTION_FILE} " * generated from cmake configure options\n")
file(APPEND ${OPTION_FILE} " *\n")
file(APPEND ${OPTION_FILE} " * Copyright (C) 2006-2026 wolfSSL Inc.\n")
file(APPEND ${OPTION_FILE} " *\n")
file(APPEND ${OPTION_FILE} " * This file is part of wolfSSL.\n")
file(APPEND ${OPTION_FILE} " *\n")
file(APPEND ${OPTION_FILE} " */\n\n")
file(APPEND ${OPTION_FILE} "#ifndef WOLFTPM_OPTIONS_H\n")
file(APPEND ${OPTION_FILE} "#define WOLFTPM_OPTIONS_H\n\n\n")
file(APPEND ${OPTION_FILE} "#ifdef __cplusplus\n")
file(APPEND ${OPTION_FILE} "extern \"C\" {\n")
file(APPEND ${OPTION_FILE} "#endif\n\n")

add_to_options_file("${WOLFTPM_DEFINITIONS}" "${OPTION_FILE}")
# CMAKE_C_FLAGS is just a string of space-separated flags to pass to the C
# compiler. We need to replace those spaces with semicolons in order to treat it
# as a CMake list.
string(REPLACE " " ";" CMAKE_C_FLAGS_LIST "${CMAKE_C_FLAGS}")
add_to_options_file("${CMAKE_C_FLAGS_LIST}" "${OPTION_FILE}")

file(APPEND ${OPTION_FILE} "\n#ifdef __cplusplus\n")
file(APPEND ${OPTION_FILE} "}\n")
file(APPEND ${OPTION_FILE} "#endif\n\n\n")
file(APPEND ${OPTION_FILE} "#endif /* WOLFTPM_OPTIONS_H */\n\n")



# generate config.h
message("Generating config header...")
set(WOLFTPM_CONFIG_H "yes" CACHE STRING
"Enable generation of config.h and define HAVE_CONFIG_H (default: enabled)")
set_property(CACHE WOLFTPM_DEBUG
    PROPERTY STRINGS "yes;no;verbose;io")
if(WOLFTPM_CONFIG_H)
    add_definitions("-DHAVE_CONFIG_H")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/config.h" )
    # If config.h exists, delete it to avoid a mixup with build/config.h
    if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/config.h")
        file(REMOVE "${CMAKE_CURRENT_SOURCE_DIR}/config.h")
    endif()
endif()




if (WOLFTPM_EXAMPLES AND BUILD_WOLFTPM_LIB)
    add_tpm_example(activate_credential attestation/activate_credential.c)
    add_tpm_example(certify attestation/certify.c)
    add_tpm_example(make_credential attestation/make_credential.c)
    add_tpm_example(bench bench/bench.c)
    add_tpm_example(secret_seal boot/secret_seal.c)
    add_tpm_example(secret_unseal boot/secret_unseal.c)
    add_tpm_example(secure_rot boot/secure_rot.c)
    add_tpm_example(csr csr/csr.c)
    add_tpm_example(get_ek_certs endorsement/get_ek_certs.c)
    add_tpm_example(ifx_fw_update firmware/ifx_fw_update.c)
    add_tpm_example(gpio_config gpio/gpio_config.c)
    add_tpm_example(gpio_read gpio/gpio_read.c)
    add_tpm_example(gpio_set gpio/gpio_set.c)
    add_tpm_example(create_primary keygen/create_primary.c)
    add_tpm_example(external_import keygen/external_import.c)
    add_tpm_example(keygen keygen/keygen.c)
    add_tpm_example(keyimport keygen/keyimport.c)
    add_tpm_example(keyload keygen/keyload.c)
    add_tpm_example(flush management/flush.c)
    add_tpm_example(tpmclear management/tpmclear.c)
    add_tpm_example(native_test native/native_test.c)
    add_tpm_example(counter nvram/counter.c)
    add_tpm_example(nvextend nvram/extend.c)
    add_tpm_example(policy_nv nvram/policy_nv.c)
    add_tpm_example(read nvram/read.c)
    add_tpm_example(store nvram/store.c)
    add_tpm_example(seal_nv nvram/seal_nv.c)
    add_tpm_example(extend pcr/extend.c)
    add_tpm_example(policy_sign pcr/policy_sign.c)
    add_tpm_example(policy pcr/policy.c)
    add_tpm_example(quote pcr/quote.c)
    add_tpm_example(read_pcr pcr/read_pcr.c)
    add_tpm_example(reset pcr/reset.c)
    add_tpm_example(pkcs7 pkcs7/pkcs7.c)
    add_tpm_example(seal seal/seal.c)
    add_tpm_example(unseal seal/unseal.c)
    add_tpm_example(seal_pcr seal/seal_pcr.c)
    add_tpm_example(seal_policy_auth seal/seal_policy_auth.c)
    add_tpm_example(clock_set timestamp/clock_set.c)
    add_tpm_example(signed_timestamp timestamp/signed_timestamp.c)
    add_tpm_example(tls_client_notpm tls/tls_client_notpm.c)
    add_tpm_example(tls_client tls/tls_client.c)
    add_tpm_example(tls_server tls/tls_server.c)
    add_tpm_example(caps wrap/caps.c)
    add_tpm_example(wrap_test wrap/wrap_test.c)
endif()


####################################################
# Installation
####################################################

include(GNUInstallDirs)

if(BUILD_WOLFTPM_LIB)
    # Note: wolftpm_wolfssl_dep is an INTERFACE helper used only at build
    # time to share wolfSSL include/link settings. It is intentionally NOT
    # installed/exported — downstream `find_package(wolftpm)` should only
    # see the real wolftpm target and discover wolfSSL via its own config.
    install(TARGETS wolftpm
            EXPORT  wolftpm-targets
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib
            RUNTIME DESTINATION bin
            )

    # Install the export set
    install(EXPORT wolftpm-targets
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wolftpm
            FILE wolftpm-config.cmake
            NAMESPACE wolfssl::)
endif()

# Install fwTPM server
if(WOLFTPM_FWTPM)
    install(TARGETS fwtpm_server
            RUNTIME DESTINATION bin
            )
endif()

# Install the headers
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/wolftpm/
        DESTINATION include/wolftpm
        FILES_MATCHING PATTERN "*.h")
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/wolftpm/
        DESTINATION include/wolftpm
        FILES_MATCHING PATTERN "*.h")


####################################################
# SBOM generation target
####################################################
#
# Usage:
#   cmake -B build -DWOLFSSL_DIR=/path/to/wolfssl/source .
#   cmake --build build
#   cmake --build build --target sbom
#
# WOLFSSL_DIR must point to a wolfssl source tree that contains
# scripts/gen-sbom (available on the feat/sbom-embedded branch).
#
# Outputs written to the build directory:
#   wolftpm-<version>.cdx.json   (CycloneDX)
#   wolftpm-<version>.spdx.json  (SPDX JSON)
#   wolftpm-<version>.spdx       (SPDX tag-value, pyspdxtools validation output)

if(BUILD_WOLFTPM_LIB)
    set(WOLFSSL_DIR "" CACHE PATH
        "Path to wolfssl source tree with scripts/gen-sbom")

    # wolfTPM is GPLv3-or-later (per the per-file source headers: "either
    # version 3 of the License, or (at your option) any later version") or
    # commercial.  Pin the header-accurate SPDX id so the SBOM is correct
    # regardless of the gen-sbom version's licence detection; commercial
    # licensees can override it (e.g. LicenseRef-wolfSSL-Commercial).  This
    # mirrors SBOM_LICENSE_OVERRIDE in the autotools build.
    set(SBOM_LICENSE_OVERRIDE "GPL-3.0-or-later" CACHE STRING
        "SPDX licence expression recorded in the SBOM")

    # Derive the version from wolftpm/version.h, NOT from PROJECT_VERSION.
    # autotools `make sbom` uses PACKAGE_VERSION, which is sourced from
    # version.h. Reading the same header here keeps the cmake and autotools
    # SBOMs bit-identical in the version field even if the project() call in
    # this file drifts out of sync with the header.
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/wolftpm/version.h"
         _sbom_version_line
         REGEX "^#define[ 	]+LIBWOLFTPM_VERSION_STRING[ 	]+\"")
    string(REGEX REPLACE
           "^#define[ 	]+LIBWOLFTPM_VERSION_STRING[ 	]+\"([^\"]+)\".*" "\\1"
           SBOM_VERSION "${_sbom_version_line}")
    if(NOT SBOM_VERSION)
        message(FATAL_ERROR
            "sbom: could not parse LIBWOLFTPM_VERSION_STRING from "
            "wolftpm/version.h")
    endif()

    # Validate the SBOM prerequisites at configure time so the user learns
    # what is missing immediately, instead of after a full library build.
    #
    # These checks must NOT abort configuration of a normal build: someone who
    # just wants `cmake -B build && cmake --build build` should never be forced
    # to set WOLFSSL_DIR. So when a prerequisite is missing we still define a
    # `sbom` target, but one that prints the reason and fails at build time.
    # Only when the user explicitly opts in via -DWOLFSSL_DIR=... and that path
    # turns out to be wrong do we hard-error at configure time, because at that
    # point the user clearly intends to build SBOMs and a typo'd path is a
    # mistake worth surfacing right away.
    find_program(PYTHON3_CMD python3)
    find_program(PYSPDXTOOLS_CMD pyspdxtools)

    set(_sbom_error "")
    if(WOLFSSL_DIR STREQUAL "")
        set(_sbom_error
            "WOLFSSL_DIR is not set. Re-run cmake with -DWOLFSSL_DIR=/path/to/wolfssl")
    elseif(NOT EXISTS "${WOLFSSL_DIR}/scripts/gen-sbom")
        # User opted in with a bad path -> fail configure now, not at build.
        message(FATAL_ERROR
            "sbom: ${WOLFSSL_DIR}/scripts/gen-sbom not found.\n"
            "      Check that WOLFSSL_DIR points to a wolfSSL tree with "
            "SBOM support.")
    elseif(NOT PYTHON3_CMD)
        set(_sbom_error "'python3' not found in PATH. Cannot generate SBOM.")
    elseif(NOT PYSPDXTOOLS_CMD)
        set(_sbom_error
            "'pyspdxtools' not found in PATH (install: pip install spdx-tools)")
    endif()

    if(NOT _sbom_error STREQUAL "")
        # Prerequisite missing: keep configuration working, but make the sbom
        # target fail loudly if someone actually invokes it.
        add_custom_target(sbom
            VERBATIM
            COMMAND ${CMAKE_COMMAND} -E echo "sbom: ${_sbom_error}"
            COMMAND ${CMAKE_COMMAND} -E false
            COMMENT "SBOM prerequisites missing")
        return()
    endif()

    set(SBOM_CDX     "${CMAKE_BINARY_DIR}/wolftpm-${SBOM_VERSION}.cdx.json")
    set(SBOM_SPDX    "${CMAKE_BINARY_DIR}/wolftpm-${SBOM_VERSION}.spdx.json")
    set(SBOM_SPDX_TV "${CMAKE_BINARY_DIR}/wolftpm-${SBOM_VERSION}.spdx")
    set(SBOM_STAGING "${CMAKE_BINARY_DIR}/_sbom_staging")

    # Staged install path. Derive the installed artifact name from the target
    # itself so it tracks the real output - a versioned .so/.dylib, a static
    # .a/.lib, or the Windows DLL - instead of a hardcoded
    # libwolftpm${CMAKE_SHARED_LIBRARY_SUFFIX} that only matches a Unix shared
    # build. install(TARGETS) sends the Windows DLL (RUNTIME) to bin/ and
    # everything else (LIBRARY/ARCHIVE) to lib/.
    if(WIN32 AND BUILD_SHARED_LIBS)
        set(SBOM_LIB "${SBOM_STAGING}/bin/$<TARGET_FILE_NAME:wolftpm>")
    else()
        set(SBOM_LIB "${SBOM_STAGING}/lib/$<TARGET_FILE_NAME:wolftpm>")
    endif()

    # wolfTPM links wolfSSL/wolfCrypt, so record wolfSSL as a dependency in the
    # SBOM (matches the autotools SBOM_DEP_WOLFSSL=yes).  Recording it needs the
    # gen-sbom from wolfSSL/wolfssl#10343; older gen-sbom rejects unknown flags,
    # so probe --help and only pass --dep-wolfssl when supported.  Against an
    # older gen-sbom the SBOM is still valid but omits the wolfSSL entry.
    set(_sbom_dep_wolfssl "")
    execute_process(
        COMMAND ${PYTHON3_CMD} ${WOLFSSL_DIR}/scripts/gen-sbom --help
        OUTPUT_VARIABLE _sbom_help
        ERROR_QUIET)
    if(_sbom_help MATCHES "--dep-wolfssl")
        set(_sbom_dep_wolfssl --dep-wolfssl yes)
    else()
        message(WARNING
            "sbom: ${WOLFSSL_DIR}/scripts/gen-sbom has no --dep-wolfssl; "
            "the SBOM will omit the wolfSSL dependency entry. Use the gen-sbom "
            "from wolfSSL/wolfssl#10343 (or master once merged) to record it.")
    endif()

    # ${OPTION_FILE} is the generated wolftpm/options.h, the same compile-time
    # option fingerprint autotools `make sbom` feeds to gen-sbom via
    # --options-h. Using it (rather than a raw `cc -dM` dump, which would only
    # capture compiler builtins) keeps the cmake SBOM consistent with autotools.
    add_custom_target(sbom
        VERBATIM
        # Stage a clean install so gen-sbom inspects the same artifact layout
        # the user would actually ship.
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${SBOM_STAGING}
        COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR}
                --prefix ${SBOM_STAGING} --config $<CONFIG>
        COMMAND ${PYTHON3_CMD} ${WOLFSSL_DIR}/scripts/gen-sbom
                --name wolftpm
                --version ${SBOM_VERSION}
                --supplier "wolfSSL Inc."
                --license-file ${CMAKE_SOURCE_DIR}/COPYING
                --options-h ${OPTION_FILE}
                --lib ${SBOM_LIB}
                --license-override ${SBOM_LICENSE_OVERRIDE}
                ${_sbom_dep_wolfssl}
                --cdx-out ${SBOM_CDX}
                --spdx-out ${SBOM_SPDX}
        # Validate the SPDX JSON and emit the tag-value rendering as a side
        # effect; a malformed SBOM makes pyspdxtools exit non-zero and fails
        # the target.
        COMMAND ${PYSPDXTOOLS_CMD} --infile ${SBOM_SPDX}
                --outfile ${SBOM_SPDX_TV}
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${SBOM_STAGING}
        COMMENT "Generating SBOM for wolfTPM ${SBOM_VERSION}")

    # gen-sbom reads the staged library, so the library must build first.
    add_dependencies(sbom wolftpm)
endif()
