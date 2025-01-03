cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolftpm_test)

# Include source code for test
target_sources(app PRIVATE ${ZEPHYR_WOLFTPM_MODULE_DIR}/tests/unit_tests.c)
target_sources(app PRIVATE ${app_sources})

# Include header files
target_include_directories(app PRIVATE
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/src
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/hal
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/tests
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/wolftpm
    ${ZEPHYR_WOLFTPM_MODULE_DIR}
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/wolfssl
    ${ZEPHYR_WOLFTPM_MODULE_DIR}/zephyr
)
add_definitions(-DWOLFTPM_USER_SETTINGS)
