/* fwtpm_main.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* fwTPM Server - Standalone firmware TPM 2.0 simulator */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#ifdef WOLFTPM_FWTPM

#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_nv.h>
#include <wolftpm/fwtpm/fwtpm_io.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/* Signal handler does only async-signal-safe work: it calls
 * FWTPM_IO_RequestStop(), which sets a volatile sig_atomic_t. The server
 * loop polls that flag and clears ctx->running from normal control flow. */
static void sigterm_handler(int sig)
{
    (void)sig;
    FWTPM_IO_RequestStop();
}

static void usage(const char* progname)
{
    printf("wolfTPM fwTPM Server v%s\n", FWTPM_GetVersionString());
    printf("Usage: %s [options]\n", progname);
    printf("Options:\n");
    printf("  --help, -h             Show this help message\n");
    printf("  --version, -v          Show version information\n");
    printf("  --clear                Delete NV state file before starting\n");
#ifndef WOLFTPM_FWTPM_TIS
    printf("  --port <port>          Command port (default: %d)\n",
        FWTPM_CMD_PORT);
    printf("  --platform-port <port> Platform port (default: %d)\n",
        FWTPM_PLAT_PORT);
#endif
}

int main(int argc, char* argv[])
{
    int rc, rcCleanup;
    static FWTPM_CTX ctx;
    int i;
    int clearNv = 0;
    struct sigaction sa;

    /* Zero context before init (required so HAL save/restore works) */
    XMEMSET(&ctx, 0, sizeof(ctx));

    /* Parse command line arguments */
    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "--help") == 0 ||
            XSTRCMP(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
        else if (XSTRCMP(argv[i], "--version") == 0 ||
                 XSTRCMP(argv[i], "-v") == 0) {
            printf("wolfTPM fwTPM Server v%s\n", FWTPM_GetVersionString());
            return 0;
        }
        else if (XSTRCMP(argv[i], "--clear") == 0) {
            clearNv = 1;
        }
    #ifndef WOLFTPM_FWTPM_TIS
        else if (XSTRCMP(argv[i], "--port") == 0 && i + 1 < argc) {
            /* Port is set after init */
            i++; /* skip value for now, handled below */
        }
        else if (XSTRCMP(argv[i], "--platform-port") == 0 && i + 1 < argc) {
            i++; /* skip value for now, handled below */
        }
    #endif
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    /* Delete NV state file if --clear was requested */
    if (clearNv) {
        printf("Clearing NV state file: %s\n", FWTPM_NV_FILE);
        remove(FWTPM_NV_FILE);
    }

    /* Initialize fwTPM */
    rc = FWTPM_Init(&ctx);
    if (rc != 0) {
        fprintf(stderr, "FWTPM_Init failed: %d\n", rc);
        return 1;
    }

#ifndef WOLFTPM_FWTPM_TIS
    /* Apply command line port overrides */
    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "--port") == 0 && i + 1 < argc) {
            long port = strtol(argv[++i], NULL, 10);
            if (port > 0 && port <= 65535) {
                ctx.cmdPort = (int)port;
            }
            else {
                fprintf(stderr, "Invalid port: %s\n", argv[i]);
                FWTPM_Cleanup(&ctx);
                return 1;
            }
        }
        else if (XSTRCMP(argv[i], "--platform-port") == 0 && i + 1 < argc) {
            long port = strtol(argv[++i], NULL, 10);
            if (port > 0 && port <= 65535) {
                ctx.platPort = (int)port;
            }
            else {
                fprintf(stderr, "Invalid platform port: %s\n", argv[i]);
                FWTPM_Cleanup(&ctx);
                return 1;
            }
        }
    }
#endif

    printf("wolfTPM fwTPM Server v%s\n", FWTPM_GetVersionString());
#ifndef WOLFTPM_FWTPM_TIS
    printf("  Command port:  %d\n", ctx.cmdPort);
    printf("  Platform port: %d\n", ctx.platPort);
#endif
    printf("  Manufacturer:  %s\n", FWTPM_MANUFACTURER);
    printf("  Model:         %s\n", FWTPM_MODEL);

    /* Install signal handler for graceful shutdown with NV save */
    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    /* Initialize socket transport */
    rc = FWTPM_IO_Init(&ctx);
    if (rc != 0) {
        fprintf(stderr, "FWTPM_IO_Init failed: %d\n", rc);
        FWTPM_Cleanup(&ctx);
        return 1;
    }

    /* Run server loop (blocks until stopped) */
    rc = FWTPM_IO_ServerLoop(&ctx);

    printf("fwTPM server shutting down (rc=%d)\n", rc);
    FWTPM_IO_Cleanup(&ctx);
    rcCleanup = FWTPM_Cleanup(&ctx);
    if (rcCleanup != TPM_RC_SUCCESS) {
        fprintf(stderr, "fwTPM: NV save failed during cleanup (rc=%d)\n", rcCleanup);
        if (rc == TPM_RC_SUCCESS)
            rc = rcCleanup;
    }

    return (rc == TPM_RC_SUCCESS) ? 0 : 1;
}

#else /* !WOLFTPM_FWTPM */

#include <stdio.h>

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    fprintf(stderr, "fwTPM server requires WOLFTPM_FWTPM to be defined.\n");
    fprintf(stderr, "Build with: ./configure --enable-fwtpm\n");
    return 1;
}

#endif /* WOLFTPM_FWTPM */
