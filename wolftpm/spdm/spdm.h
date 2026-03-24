/* spdm.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSPDM.
 *
 * wolfSPDM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSPDM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFSPDM_SPDM_H
#define WOLFSPDM_SPDM_H

#ifndef HAVE_CONFIG_H
    #include <wolftpm/spdm/options.h>
#endif

#include <wolftpm/spdm/spdm_types.h>
#include <wolftpm/spdm/spdm_error.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol mode: TCG binding + vendor commands.
 * For standard SPDM (emulator, measurements, challenge), see wolfSPDM standalone. */
typedef enum {
    WOLFSPDM_MODE_NUVOTON     = 1,
    WOLFSPDM_MODE_NATIONS     = 2,
    WOLFSPDM_MODE_NATIONS_PSK = 3
} WOLFSPDM_MODE;

/* wolfSPDM: Lightweight SPDM requester using wolfCrypt.
 * Algorithm Set B fixed: P-384/SHA-384/AES-256-GCM.
 *
 * Usage (static, zero-malloc):
 *   WOLFSPDM_CTX ctx;
 *   wolfSPDM_Init(&ctx);
 *   wolfSPDM_SetIO(&ctx, callback, userPtr);
 *   wolfSPDM_Connect(&ctx);
 *   wolfSPDM_SecuredExchange(&ctx, ...);
 *   wolfSPDM_Disconnect(&ctx);
 *   wolfSPDM_Free(&ctx);
 *
 * Dynamic (requires --enable-dynamic-mem):
 *   ctx = wolfSPDM_New();
 *   // ... same as above ...
 *   wolfSPDM_Free(ctx);
 *
 * WOLFSPDM_CTX is ~22KB. Use static global on small-stack systems.
 * SecuredExchange call chain uses ~20KB stack for message buffers. */

/* Compile-time buffer size for static allocation (32KB, runtime-verified) */
#define WOLFSPDM_CTX_STATIC_SIZE  32768

struct WOLFSPDM_CTX;
typedef struct WOLFSPDM_CTX WOLFSPDM_CTX;

#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)
    #include <wolftpm/spdm/spdm_tcg.h>
#endif
#ifdef WOLFSPDM_NUVOTON
    #include <wolftpm/spdm/spdm_nuvoton.h>
#endif
#ifdef WOLFSPDM_NATIONS
    #include <wolftpm/spdm/spdm_nations.h>
#endif
#ifdef WOLFTPM_SPDM_PSK
    #include <wolftpm/spdm/spdm_psk.h>
#endif

/* I/O callback: transport-agnostic send/receive.
 * Returns 0 on success, negative on error.
 * rxSz: [in] buffer size, [out] actual received size. */
typedef int (*WOLFSPDM_IO_CB)(
    WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx
);

/* Context management */
WOLFSPDM_API int wolfSPDM_Init(WOLFSPDM_CTX* ctx);
#ifdef WOLFSPDM_DYNAMIC_MEMORY
WOLFSPDM_API WOLFSPDM_CTX* wolfSPDM_New(void);
#endif
WOLFSPDM_API void wolfSPDM_Free(WOLFSPDM_CTX* ctx);
WOLFSPDM_API int wolfSPDM_GetCtxSize(void);
WOLFSPDM_API int wolfSPDM_InitStatic(WOLFSPDM_CTX* ctx, int size);

/* Configuration */
WOLFSPDM_API int wolfSPDM_SetIO(WOLFSPDM_CTX* ctx, WOLFSPDM_IO_CB ioCb,
    void* userCtx);
WOLFSPDM_API int wolfSPDM_SetMode(WOLFSPDM_CTX* ctx, WOLFSPDM_MODE mode);
WOLFSPDM_API WOLFSPDM_MODE wolfSPDM_GetMode(WOLFSPDM_CTX* ctx);
/* Set responder pub key for cert-less operation (96 bytes P-384 X||Y) */
WOLFSPDM_API int wolfSPDM_SetResponderPubKey(WOLFSPDM_CTX* ctx,
    const byte* pubKey, word32 pubKeySz);
/* Set requester key pair for mutual auth (privKey=48, pubKey=96 bytes) */
WOLFSPDM_API int wolfSPDM_SetRequesterKeyPair(WOLFSPDM_CTX* ctx,
    const byte* privKey, word32 privKeySz,
    const byte* pubKey, word32 pubKeySz);

/* Session establishment */
WOLFSPDM_API int wolfSPDM_Connect(WOLFSPDM_CTX* ctx);
WOLFSPDM_API int wolfSPDM_IsConnected(WOLFSPDM_CTX* ctx);
WOLFSPDM_API int wolfSPDM_Disconnect(WOLFSPDM_CTX* ctx);

/* Individual handshake steps (for fine-grained control) */
WOLFSPDM_API int wolfSPDM_GetVersion(WOLFSPDM_CTX* ctx);
WOLFSPDM_API int wolfSPDM_KeyExchange(WOLFSPDM_CTX* ctx);
WOLFSPDM_API int wolfSPDM_Finish(WOLFSPDM_CTX* ctx);

/* Secured messaging: encrypt, send, receive, decrypt in one call */
WOLFSPDM_API int wolfSPDM_SecuredExchange(WOLFSPDM_CTX* ctx,
    const byte* cmdPlain, word32 cmdSz,
    byte* rspPlain, word32* rspSz);

/* Session info */
WOLFSPDM_API word32 wolfSPDM_GetSessionId(WOLFSPDM_CTX* ctx);
WOLFSPDM_API byte wolfSPDM_GetNegotiatedVersion(WOLFSPDM_CTX* ctx);
#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS)
WOLFSPDM_API word32 wolfSPDM_GetConnectionHandle(WOLFSPDM_CTX* ctx);
WOLFSPDM_API word16 wolfSPDM_GetFipsIndicator(WOLFSPDM_CTX* ctx);
#endif

/* wolfSPDM_SetPSK declared in spdm_psk.h */

/* Debug */
WOLFSPDM_API void wolfSPDM_SetDebug(WOLFSPDM_CTX* ctx, int enable);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_SPDM_H */
