if(CONFIG_WOLFTPM)
  zephyr_include_directories(${ZEPHYR_CURRENT_MODULE_DIR})
  zephyr_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/zephyr)
  zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR})

  FILE(GLOB wolftpm_sources
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/*.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/hal/tpm_io.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/examples/wrap/*.c
  )
  target_sources(app PRIVATE ${wolftpm_sources})

  if(CONFIG_WOLFTPM_DEBUG)
    target_compile_definitions(app PUBLIC DEBUG_WOLFTPM)
  endif()

  target_compile_definitions(app PUBLIC WOLFTPM_ZEPHYR)
endif()
