cmake_minimum_required(VERSION 3.2.0) # what version
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolftpm_test)

target_sources(app PRIVATE ${ZEPHYR_WOLFTPM_MODULE_DIR}/tests/unit_tests.c)
target_include_directories(app PRIVATE ${ZEPHYR_WOLFTPM_MODULE_DIR}/tests)
target_sources(app PRIVATE ${app_sources})
