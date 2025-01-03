cmake_minimum_required(VERSION 3.2.0) # what version
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolftpm_bench)

target_sources(app PRIVATE ${ZEPHYR_WOLFTPM_MODULE_DIR}/examples/bench/bench.c)
target_include_directories(app PRIVATE ${ZEPHYR_WOLFTPM_MODULE_DIR}/examples/bench)
target_sources(app PRIVATE ${app_sources})
