# CMakeList.txt
#
# Copyright (C) 2006-2025 wolfSSL Inc.
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

project(wolfTPM VERSION 3.9.2 LANGUAGES C)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(WOLFTPM_DEFINITIONS)

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
    src/tpm2_cryptocb.c
    hal/tpm_io.c
    )


# default to build shared library
option(BUILD_SHARED_LIBS "Build shared libraries (.dll/.so) instead of static ones (.lib/.a)" ON)
add_library(wolftpm ${TPM_SOURCES})
target_compile_definitions(wolftpm PRIVATE
    "BUILDING_WOLFTPM"
    )

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


if(WIN32)
    target_compile_definitions(wolftpm PRIVATE
        "WOLFTPM_DLL"
        )
endif(WIN32)

if("${WOLFTPM_INTERFACE}" STREQUAL "SWTPM")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_SWTPM")

    # SWTPM port configuration
    set(WOLFTPM_SWTPM_PORT "2321" CACHE STRING
        "Set SWTPM socket port (default: 2321)")
    list(APPEND WOLFTPM_DEFINITIONS "-DTPM2_SWTPM_PORT=\"${WOLFTPM_SWTPM_PORT}\"")

elseif("${WOLFTPM_INTERFACE}" STREQUAL "DEVTPM")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_LINUX_DEV")

elseif("${WOLFTPM_INTERFACE}" STREQUAL "WINAPI")
    list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM_WINAPI")
    target_link_libraries(wolftpm PRIVATE tbs)

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

# Examples
set(WOLFTPM_EXAMPLES "yes" CACHE BOOL
    "Build examples")

target_include_directories(wolftpm
    PUBLIC
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    )


if (WITH_WOLFSSL)
    target_link_libraries(wolftpm PUBLIC wolfssl)
    target_include_directories(wolftpm PUBLIC ${WITH_WOLFSSL}/include)
    target_link_directories(wolftpm PUBLIC ${WITH_WOLFSSL}/lib)
elseif (WITH_WOLFSSL_TREE)
    set(WOLFSSL_TPM "yes" CACHE STRING "")
    set(WOLFSSL_EXAMPLES "no" CACHE STRING "")
    set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "")
    add_subdirectory(${WITH_WOLFSSL_TREE} wolfssl)
    target_link_libraries(wolftpm PUBLIC wolfssl)
else()
    find_package(PkgConfig)
    pkg_check_modules(WOLFSSL wolfssl)

    if (WOLFSSL_FOUND)
        target_link_libraries(wolftpm PUBLIC ${WOLFSSL_LIBRARIES})
        target_include_directories(wolftpm PUBLIC ${WOLFSSL_INCLUDE_DIRS})
        target_link_directories(wolftpm PUBLIC ${WOLFSSL_LIBRARY_DIRS})
        target_compile_options(wolftpm PUBLIC ${WOLFSSL_CFLAGS_OTHER})
    else()
        # For support with vcpkg
        find_package(wolfssl CONFIG REQUIRED)
        if (wolfssl_FOUND)
            target_link_libraries(wolftpm PUBLIC wolfssl::wolfssl)
        else()
            list(APPEND WOLFTPM_DEFINITIONS "-DWOLFTPM2_NO_WOLFCRYPT")
        endif()
    endif()
endif()

if (WOLFTPM_EXAMPLES)
    add_library(tpm_test_lib STATIC
        examples/tpm_test_keys.c
        )
    target_link_libraries(tpm_test_lib wolftpm)
endif()

function(add_tpm_example name src)
    add_executable(${name}
        examples/${src}
        )
    target_link_libraries(${name} wolftpm tpm_test_lib)
endfunction()

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
file(APPEND ${OPTION_FILE} " * Copyright (C) 2006-2025 wolfSSL Inc.\n")
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




if (WOLFTPM_EXAMPLES)
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
    add_tpm_example(extend pcr/extend.c)
    add_tpm_example(policy_sign pcr/policy_sign.c)
    add_tpm_example(policy pcr/policy.c)
    add_tpm_example(quote pcr/quote.c)
    add_tpm_example(read_pcr pcr/read_pcr.c)
    add_tpm_example(reset pcr/reset.c)
    add_tpm_example(pkcs7 pkcs7/pkcs7.c)
    add_tpm_example(seal seal/seal.c)
    add_tpm_example(unseal seal/unseal.c)
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

# Install the headers
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/wolftpm/
        DESTINATION include/wolftpm
        FILES_MATCHING PATTERN "*.h")
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/wolftpm/
        DESTINATION include/wolftpm
        FILES_MATCHING PATTERN "*.h")
