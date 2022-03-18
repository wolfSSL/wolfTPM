# CMakeList.txt
#
# Copyright (C) 2006-2022 wolfSSL Inc.
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

project(wolfTPM VERSION 1.1.1 LANGUAGES C)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(TPM_SOURCES
    src/tpm2.c
    src/tpm2_linux.c
    src/tpm2_packet.c
    src/tpm2_param_enc.c
    src/tpm2_swtpm.c
    src/tpm2_tis.c
    src/tpm2_winapi.c
    src/tpm2_wrap.c
    )

add_library(wolftpm SHARED ${TPM_SOURCES})
target_compile_definitions(wolftpm PRIVATE
    "BUILDING_WOLFTPM"
    )

if (WITH_WOLFSSL)
    target_link_libraries(wolftpm wolfssl)
    target_include_directories(wolftpm PUBLIC ${WITH_WOLFSSL}/include)
    target_link_directories(wolftpm PUBLIC ${WITH_WOLFSSL}/lib)
elseif (WITH_WOLFSSL_TREE)
    set(WOLFSSL_TPM "yes" CACHE STRING "")
    add_subdirectory(${WITH_WOLFSSL_TREE} wolfssl)
    target_link_libraries(wolftpm wolfssl)
else()
    find_package(PkgConfig)
    pkg_check_modules(WOLFSSL wolfssl)

    if (WOLFSSL_FOUND)
        target_link_libraries(wolftpm ${WOLFSSL_LIBRARIES})
        target_include_directories(wolftpm PUBLIC ${WOLFSSL_INCLUDE_DIRS})
        target_link_directories(wolftpm PUBLIC ${WOLFSSL_LIBRARY_DIRS})
        target_compile_options(wolftpm PUBLIC ${WOLFSSL_CFLAGS_OTHER})
    else()
        target_compile_definitions(wolftpm PUBLIC
            "WOLFTPM2_NO_WOLFCRYPT"
            )
    endif()
endif()

# TODO
# * Debug/logging
# * EXAMPLES
# * wrapper
# * wolfcrypt
# * I2C
# * Advanced IO
# * Device specific (ST33, ATTPM20, NPCT, SLB, automatic)
# * wait state
# * small stack

set(WOLFTPM_INTERFACE "auto" CACHE STRING
    "Select interface to TPM")
set_property(CACHE WOLFTPM_INTERFACE
    PROPERTY STRINGS "auto;SWTPM;WINAPI;DEVTPM")

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
        "_WINDLL"
        )
endif(WIN32)

if("${WOLFTPM_INTERFACE}" STREQUAL "SWTPM")
    target_compile_definitions(wolftpm PUBLIC
        "WOLFTPM_SWTPM"
        )
elseif("${WOLFTPM_INTERFACE}" STREQUAL "DEVTPM")
    target_compile_definitions(wolftpm PUBLIC
        "WOLFTPM_LINUX_DEV"
        )
elseif("${WOLFTPM_INTERFACE}" STREQUAL "WINAPI")
    target_compile_definitions(wolftpm PUBLIC
        "WOLFTPM_WINAPI"
        )
    target_link_libraries(wolftpm tbs)
else()
    get_property(INTERFACE_OPTS CACHE WOLFTPM_INTERFACE
        PROPERTY STRINGS)
    message(FATAL_ERROR "\"${WOLFTPM_INTERFACE}\" is not known WOLFTPM_INTERFACE:"
        " ${INTERFACE_OPTS}")
endif("${WOLFTPM_INTERFACE}" STREQUAL "SWTPM")

target_include_directories(wolftpm
    PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
    $<INSTALL_INTERFACE:wolftpm>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    )

add_library(tpm_test_lib STATIC
    examples/tpm_io.c
    examples/tpm_test_keys.c
    )
target_link_libraries(tpm_test_lib wolftpm)

function(add_tpm_example name src)
    add_executable(${name}
        examples/${src}
        )
    target_link_libraries(${name} wolftpm tpm_test_lib)
endfunction()

#TODO generate options file
configure_file(wolftpm/options.h.in wolftpm/options.h)


add_tpm_example(activate_credential attestation/activate_credential.c)
add_tpm_example(make_credential attestation/make_credential.c)
add_tpm_example(bench bench/bench.c)
add_tpm_example(csr csr/csr.c)
add_tpm_example(gpio_config gpio/gpio_config.c)
add_tpm_example(gpio_read gpio/gpio_read.c)
add_tpm_example(gpio_set gpio/gpio_set.c)
add_tpm_example(keygen keygen/keygen.c)
add_tpm_example(keyimport keygen/keyimport.c)
add_tpm_example(keyload keygen/keyload.c)
add_tpm_example(flush management/flush.c)
add_tpm_example(native_test native/native_test.c)
add_tpm_example(read nvram/read.c)
add_tpm_example(store nvram/store.c)
add_tpm_example(extend pcr/extend.c)
add_tpm_example(quote pcr/quote.c)
add_tpm_example(read_pcr pcr/read_pcr.c)
add_tpm_example(reset pcr/reset.c)
add_tpm_example(pkcs7 pkcs7/pkcs7.c)
add_tpm_example(seal seal/seal.c)
add_tpm_example(unseal seal/unseal.c)
add_tpm_example(clock_set timestamp/clock_set.c)
add_tpm_example(signed_timestamp timestamp/signed_timestamp.c)
add_tpm_example(tls_client tls/tls_client.c)
add_tpm_example(tls_client_notpm tls/tls_client_notpm.c)
add_tpm_example(tls_server tls/tls_server.c)
add_tpm_example(wrap_test wrap/wrap_test.c)

include(GNUInstallDirs)

install(TARGETS wolftpm
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY)
# Install the headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/wolftpm/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wolftpm
        FILES_MATCHING PATTERN "*.h")
