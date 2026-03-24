/* spdm_session.c
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

#include "spdm_internal.h"

/* Callback types for build/parse functions */
typedef int (*wolfSPDM_BuildFn)(WOLFSPDM_CTX*, byte*, word32*);
typedef int (*wolfSPDM_ParseFn)(WOLFSPDM_CTX*, const byte*, word32);

/* Exchange helper: build -> transcript(tx) -> sendrecv -> transcript(rx) -> parse */
static int wolfSPDM_ExchangeMsg(WOLFSPDM_CTX* ctx,
    wolfSPDM_BuildFn buildFn, wolfSPDM_ParseFn parseFn,
    byte* txBuf, word32 txBufSz, byte* rxBuf, word32 rxBufSz)
{
    word32 txSz = txBufSz;
    word32 rxSz = rxBufSz;
    int rc;

    rc = buildFn(ctx, txBuf, &txSz);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, rxBuf, rxSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = parseFn(ctx, rxBuf, rxSz);
    }

    return rc;
}

/* Adapter: BuildGetVersion doesn't take ctx */
static int wolfSPDM_BuildGetVersionAdapter(WOLFSPDM_CTX* ctx, byte* buf,
    word32* bufSz)
{
    (void)ctx;
    return wolfSPDM_BuildGetVersion(buf, bufSz);
}

int wolfSPDM_GetVersion(WOLFSPDM_CTX* ctx)
{
    byte txBuf[8];
    byte rxBuf[32];  /* VERSION: 4 hdr + 2 count + up to 8 entries * 2 = 22 */

    return wolfSPDM_ExchangeMsg(ctx, wolfSPDM_BuildGetVersionAdapter,
        wolfSPDM_ParseVersion, txBuf, sizeof(txBuf), rxBuf, sizeof(rxBuf));
}

int wolfSPDM_KeyExchange(WOLFSPDM_CTX* ctx)
{
    byte txBuf[WOLFSPDM_KEY_EX_TX_SZ];
    byte rxBuf[WOLFSPDM_KEY_EX_RX_SZ];
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    rc = wolfSPDM_BuildKeyExchange(ctx, txBuf, &txSz);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE: SendReceive failed: %d\n", rc);
        }
    }
    if (rc == WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE_RSP: received %u bytes\n", rxSz);
        rc = wolfSPDM_ParseKeyExchangeRsp(ctx, rxBuf, rxSz);
    }

    return rc;
}

int wolfSPDM_Finish(WOLFSPDM_CTX* ctx)
{
    byte finishBuf[WOLFSPDM_FINISH_BUF_SZ];
    byte encBuf[WOLFSPDM_VENDOR_BUF_SZ];
    byte rxBuf[128];      /* Encrypted FINISH_RSP: ~94 bytes max */
    byte decBuf[64];      /* Decrypted FINISH_RSP: 4 hdr + 48 verify = 52 */
    word32 finishSz = sizeof(finishBuf);
    word32 encSz = sizeof(encBuf);
    word32 rxSz = sizeof(rxBuf);
    word32 decSz = sizeof(decBuf);
    int rc;

    rc = wolfSPDM_BuildFinish(ctx, finishBuf, &finishSz);

    /* FINISH must be sent encrypted (HANDSHAKE_IN_THE_CLEAR not negotiated) */
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_EncryptInternal(ctx, finishBuf, finishSz, encBuf,
            &encSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SendReceive(ctx, encBuf, encSz, rxBuf, &rxSz);
    }

    /* Check for unencrypted SPDM error response */
    if (rc == WOLFSPDM_SUCCESS &&
        rxSz >= 2 && rxBuf[0] >= 0x10 && rxBuf[0] <= 0x1F) {
    #ifdef DEBUG_WOLFTPM
        if (rxBuf[1] == 0x7F) {
            byte errCode = (rxSz >= 3) ? rxBuf[2] : 0xFF;
            wolfSPDM_DebugPrint(ctx, "FINISH: SPDM ERROR 0x%02x\n", errCode);
        }
    #endif
        rc = WOLFSPDM_E_PEER_ERROR;
    }

    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, decBuf, &decSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_ParseFinishRsp(ctx, decBuf, decSz);
    }

    /* Derive application data keys (transition from handshake to app phase) */
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_DeriveAppDataKeys(ctx);
    }

    /* Always zero sensitive stack buffers */
    wc_ForceZero(finishBuf, sizeof(finishBuf));
    wc_ForceZero(decBuf, sizeof(decBuf));
    return rc;
}
