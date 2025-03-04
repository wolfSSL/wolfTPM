cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolftpm_wrap_test)

# Include source code for wrap test
target_sources(app PRIVATE ${ZEPHYR_WOLFTPM_MODULE_DIR}/examples/wrap/wrap_test.c)
target_sources(app PRIVATE ${app_sources})

# Include header files
target_include_directories(app PRIVATE
    ${ZEPHYR_BASE}/include
    ${ZEPHYR_BASE}/include/zephyr
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/zephyr
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/hal
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/tests
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/wolftpm
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/examples/wrap
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/examples
    ${ZEPHYR_WOLFTPM_MODULE_DIR}
)

add_definitions(-DWOLFSSL_ZEPHYR)
add_definitions(-DWOLFSSL_USER_SETTINGS)
add_definitions(-DWOLFTPM_USER_SETTINGS)
add_definitions(-DWOLFSSL_USER_IO)
