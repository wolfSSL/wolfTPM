/* Compile the socket transport for focused unit testing without pulling the
 * optional SPDM responder into the core fwTPM unit-test target. */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/fwtpm/fwtpm.h>

#ifdef HAVE_CONFIG_H
    #undef HAVE_CONFIG_H
#endif
#ifdef WOLFTPM_SPDM_RESPONDER
    #undef WOLFTPM_SPDM_RESPONDER
#endif

#include "../src/fwtpm/fwtpm_io.c"
