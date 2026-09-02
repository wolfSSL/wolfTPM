cmake_minimum_required(VERSION 3.16)

project(wolftpm_static_consumer C)

find_package(wolftpm CONFIG REQUIRED)

add_library(wolftpm_static_consumer INTERFACE)
target_link_libraries(wolftpm_static_consumer INTERFACE wolfssl::wolftpm)
