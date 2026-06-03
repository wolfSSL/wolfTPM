/* fwtpm_main.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
#include <wolftpm/fwtpm/fwtpm_command.h>

#ifdef WOLFTPM_SPDM_RESPONDER
    #include <wolftpm/spdm/spdm_responder.h>
    #include <wolfssl/wolfcrypt/ecc.h>
    #include <wolfssl/wolfcrypt/random.h>
#endif

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
#ifdef WOLFTPM_SPDM_RESPONDER
    printf("\nSPDM responder (TCG SPDM Binding v1.0 / DSP0274 1.3):\n");
    printf("  --spdm-tcg             Speak SPDM in TCG Binding mode\n");
    printf("  --spdm-psk             Speak SPDM in PSK mode\n");
    printf("  --no-spdm              Disable SPDM (default)\n");
    printf("  --spdm-psk-hex <hex>   PSK as hex (PSK mode)\n");
    printf("\nWith SPDM enabled, raw TPM2 / MSSIM frames are rejected\n");
    printf("(bus-snooping defence). Every TPM command must arrive inside\n");
    printf("a decrypted SPDM secured-message envelope.\n");
#endif
}

#ifdef WOLFTPM_SPDM_RESPONDER
static int fwtpmSpdmTpmDispatch(void* userCtx,
    const byte* cmd, word32 cmdSz,
    byte* resp, word32 respBufSz, word32* respSz)
{
    FWTPM_CTX* ctx = (FWTPM_CTX*)userCtx;
    int rc;
    int rspSize;

    if (ctx == NULL || cmd == NULL || resp == NULL || respSz == NULL) {
        return BAD_FUNC_ARG;
    }
    rspSize = (int)respBufSz;
    rc = FWTPM_ProcessCommand(ctx, cmd, (int)cmdSz, resp, &rspSize, 0);
    /* A non-zero TPM_RC is a valid TPM response - the requester must see
     * the actual error code. If the dispatcher didn't write one (rspSize
     * left at zero or partial), synthesize a 10-byte TPM_ST_NO_SESSIONS
     * error frame here so the SPDM layer encrypts and sends it back. */
    if ((rc != TPM_RC_SUCCESS || rspSize < TPM2_HEADER_SIZE) &&
        respBufSz >= TPM2_HEADER_SIZE) {
        resp[0] = 0x80; resp[1] = 0x01;  /* TPM_ST_NO_SESSIONS */
        resp[2] = 0x00; resp[3] = 0x00; resp[4] = 0x00; resp[5] = 0x0A;
        resp[6] = (byte)((rc >> 24) & 0xFF);
        resp[7] = (byte)((rc >> 16) & 0xFF);
        resp[8] = (byte)((rc >> 8) & 0xFF);
        resp[9] = (byte)(rc & 0xFF);
        rspSize = TPM2_HEADER_SIZE;
    }
    *respSz = (word32)rspSize;
    return 0;  /* I/O layer succeeded; TPM error code is in the response. */
}

/* Generate a fresh P-384 identity key for the SPDM responder. The
 * requester verifies KEY_EXCHANGE_RSP signatures against the public half
 * (delivered via GET_PUBK). Re-generated every startup - for production
 * use this would be backed by a stable per-device key. */
static int fwtpmSpdmGenIdentityKey(byte* privOut, word32 privCap,
    byte* pubOut, word32 pubCap)
{
    WC_RNG rng;
    ecc_key key;
    byte tmpX[48];
    byte tmpY[48];
    word32 privSz;
    word32 xSz;
    word32 ySz;
    int rc;
    int keyInit = 0;

    if (privCap < 48 || pubCap < 96) {
        return BAD_FUNC_ARG;
    }
    /* wolfCrypt may trim leading zeros from exported scalars/coords -
     * zero the destinations and left-pad each value into a 48-byte slot
     * so the responder always sees fixed-width P-384 material. */
    XMEMSET(privOut, 0, 48);
    XMEMSET(pubOut, 0, 96);
    XMEMSET(tmpX, 0, sizeof(tmpX));
    XMEMSET(tmpY, 0, sizeof(tmpY));

    rc = wc_InitRng(&rng);
    if (rc != 0) {
        return rc;
    }
    rc = wc_ecc_init(&key);
    if (rc == 0) {
        keyInit = 1;
        rc = wc_ecc_make_key_ex(&rng, 48, &key, ECC_SECP384R1);
    }
    if (rc == 0) {
        privSz = sizeof(tmpX);
        rc = wc_ecc_export_private_only(&key, tmpX, &privSz);
        if (rc == 0) {
            if (privSz > 48) {
                /* Fail loudly - silently leaving privOut zeroed would
                 * give the responder a publicly-known identity key. */
                rc = BAD_FUNC_ARG;
            }
            else {
                XMEMCPY(privOut + (48 - privSz), tmpX, privSz);
            }
        }
    }
    if (rc == 0) {
        XMEMSET(tmpX, 0, sizeof(tmpX));
        xSz = sizeof(tmpX);
        ySz = sizeof(tmpY);
        rc = wc_ecc_export_public_raw(&key, tmpX, &xSz, tmpY, &ySz);
        if (rc == 0) {
            if (xSz > 48 || ySz > 48) {
                rc = BAD_FUNC_ARG;
            }
            else {
                XMEMCPY(pubOut + (48 - xSz), tmpX, xSz);
                XMEMCPY(pubOut + 48 + (48 - ySz), tmpY, ySz);
            }
        }
    }
    wc_ForceZero(tmpX, sizeof(tmpX));
    wc_ForceZero(tmpY, sizeof(tmpY));
    if (keyInit) {
        wc_ecc_free(&key);
    }
    wc_FreeRng(&rng);
    return rc;
}

static int fwtpmHexDecode(const char* hex, byte* out, word32 outCap)
{
    word32 len, i;

    if (hex == NULL || out == NULL) {
        return -1;
    }
    len = (word32)XSTRLEN(hex);
    if ((len & 1) != 0 || (len / 2) > outCap) {
        return -1;
    }
    for (i = 0; i < len / 2; i++) {
        unsigned int v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (byte)v;
    }
    return (int)(len / 2);
}
#endif /* WOLFTPM_SPDM_RESPONDER */

int main(int argc, char* argv[])
{
    int rc, rcCleanup;
    static FWTPM_CTX ctx;
    int i;
    int clearNv = 0;
#ifdef WOLFTPM_SPDM_RESPONDER
    int spdmMode = FWTPM_SPDM_MODE_OFF;
    const char* spdmPskHex = NULL;
#endif
#ifndef _WIN32
    struct sigaction sa;
#endif

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
    #ifdef WOLFTPM_SPDM_RESPONDER
        else if (XSTRCMP(argv[i], "--spdm-tcg") == 0) {
            spdmMode |= FWTPM_SPDM_MODE_TCG;
        }
        else if (XSTRCMP(argv[i], "--spdm-psk") == 0) {
            spdmMode |= FWTPM_SPDM_MODE_PSK;
        }
        else if (XSTRCMP(argv[i], "--no-spdm") == 0) {
            spdmMode = FWTPM_SPDM_MODE_OFF;
        }
        else if (XSTRCMP(argv[i], "--spdm-psk-hex") == 0 && i + 1 < argc) {
            spdmPskHex = argv[++i];
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
        (void)remove(FWTPM_NV_FILE);
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

#ifdef WOLFTPM_SPDM_RESPONDER
    /* Failure here is fatal - never fall back to plaintext when SPDM was
     * requested (bus-snooping defence). */
    if (spdmMode != FWTPM_SPDM_MODE_OFF) {
        int useTcg, usePsk;

        useTcg = (spdmMode & FWTPM_SPDM_MODE_TCG) ? 1 : 0;
        usePsk = (spdmMode & FWTPM_SPDM_MODE_PSK) ? 1 : 0;
        ctx.spdmRespCtx = (struct WOLFSPDM_RESP_CTX*)
            XMALLOC((size_t)wolfSPDM_RespGetCtxSize(),
                    NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (ctx.spdmRespCtx == NULL) {
            fprintf(stderr, "fwTPM: SPDM responder context alloc failed\n");
            FWTPM_Cleanup(&ctx);
            return 1;
        }
        rc = wolfSPDM_RespInit(ctx.spdmRespCtx);
        if (rc == 0) {
            rc = wolfSPDM_RespSetMode(ctx.spdmRespCtx, useTcg, usePsk);
        }
        if (rc == 0 && spdmPskHex != NULL) {
            byte pskBuf[64];
            int pskLen = fwtpmHexDecode(spdmPskHex, pskBuf, sizeof(pskBuf));
            if (pskLen < 0) {
                fprintf(stderr, "fwTPM: invalid --spdm-psk-hex value\n");
                rc = -1;
            }
            else {
                rc = wolfSPDM_RespSetPSK(ctx.spdmRespCtx,
                    pskBuf, (word32)pskLen, NULL, 0);
            }
            wc_ForceZero(pskBuf, sizeof(pskBuf));
        }
        if (rc == 0) {
            rc = wolfSPDM_RespSetTpmCallback(ctx.spdmRespCtx,
                fwtpmSpdmTpmDispatch, &ctx);
        }
        if (rc == 0) {
            byte idPriv[48];
            byte idPub[96];
            rc = fwtpmSpdmGenIdentityKey(idPriv, sizeof(idPriv),
                idPub, sizeof(idPub));
            if (rc == 0) {
                rc = wolfSPDM_RespSetIdentityKey(ctx.spdmRespCtx,
                    idPriv, sizeof(idPriv), idPub, sizeof(idPub));
            }
            wc_ForceZero(idPriv, sizeof(idPriv));
        }
        if (rc != 0) {
            fprintf(stderr, "fwTPM: SPDM responder init failed (rc=%d)\n",
                rc);
            wolfSPDM_RespFree(ctx.spdmRespCtx);
            XFREE(ctx.spdmRespCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            ctx.spdmRespCtx = NULL;
            FWTPM_Cleanup(&ctx);
            return 1;
        }
        ctx.spdmMode = spdmMode;
        printf("  SPDM mode:    %s%s%s\n",
            useTcg ? "TCG" : "",
            (useTcg && usePsk) ? "+" : "",
            usePsk ? "PSK" : "");
        printf("  Bus-snooping defence: armed (plaintext rejected after SPDMONLY lock)\n");
    }
#endif

    /* Install signal handler for graceful shutdown with NV save */
#ifdef _WIN32
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);
#else
    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
#endif

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
#ifdef WOLFTPM_SPDM_RESPONDER
    if (ctx.spdmRespCtx != NULL) {
        wolfSPDM_RespFree(ctx.spdmRespCtx);
        XFREE(ctx.spdmRespCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        ctx.spdmRespCtx = NULL;
    }
#endif
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
