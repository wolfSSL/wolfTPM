/* fwtpm.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#ifdef WOLFTPM_FWTPM

#ifdef WOLFTPM2_NO_WOLFCRYPT
    #error "fwTPM requires wolfCrypt. Do not use --disable-wolfcrypt with --enable-fwtpm."
#endif

#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_nv.h>
#include <string.h>

int FWTPM_Init(FWTPM_CTX* ctx)
{
    int rc;
    int rngInit = 0;
    FWTPM_NV_HAL savedNvHal;
    struct FWTPM_CLOCK_HAL_S savedClockHal;
#ifdef WOLFTPM_FWTPM_TIS
    FWTPM_TIS_HAL savedTisHal;
#endif

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Save any pre-configured HALs before zeroing context */
    XMEMCPY(&savedNvHal, &ctx->nvHal, sizeof(savedNvHal));
    XMEMCPY(&savedClockHal, &ctx->clockHal, sizeof(savedClockHal));
#ifdef WOLFTPM_FWTPM_TIS
    XMEMCPY(&savedTisHal, &ctx->tisHal, sizeof(savedTisHal));
#endif

    XMEMSET(ctx, 0, sizeof(FWTPM_CTX));

    /* Restore HALs if they were set before init */
    if (savedNvHal.read != NULL) {
        XMEMCPY(&ctx->nvHal, &savedNvHal, sizeof(savedNvHal));
    }
    if (savedClockHal.get_ms != NULL) {
        XMEMCPY(&ctx->clockHal, &savedClockHal, sizeof(savedClockHal));
    }
#ifdef WOLFTPM_FWTPM_TIS
    if (savedTisHal.init != NULL) {
        XMEMCPY(&ctx->tisHal, &savedTisHal, sizeof(savedTisHal));
    }
#endif

#ifndef WOLFTPM_FWTPM_TIS
    /* Set default ports (socket transport only) */
    ctx->cmdPort = FWTPM_CMD_PORT;
    ctx->platPort = FWTPM_PLAT_PORT;
#endif

    /* Default to powered on - the server process being running means
     * the TPM is powered. Platform port can still toggle this. */
    ctx->powerOn = 1;

    /* Initialize wolfCrypt RNG */
    rc = wolfCrypt_Init();
    if (rc == 0) {
        rc = wc_InitRng(&ctx->rng);
        if (rc == 0) {
            rngInit = 1;
        }
    }

    /* Generate per-boot context protection key (volatile only) for
     * ContextSave/ContextLoad HMAC + AES-CFB session blob protection. */
    if (rc == 0) {
        rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->ctxProtectKey,
            sizeof(ctx->ctxProtectKey));
        if (rc == 0) {
            ctx->ctxProtectKeyValid = 1;
        }
    }

    /* Initialize NV storage - loads existing state or creates fresh seeds */
#ifndef FWTPM_NO_NV
    if (rc == 0) {
        rc = FWTPM_NV_Init(ctx);
    }
#else
    /* No NV: generate ephemeral seeds (lost on reset) */
    if (rc == 0)
        rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->ownerSeed, FWTPM_SEED_SIZE);
    if (rc == 0)
        rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->endorsementSeed,
            FWTPM_SEED_SIZE);
    if (rc == 0)
        rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->platformSeed,
            FWTPM_SEED_SIZE);
    if (rc == 0)
        rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->nullSeed,
            FWTPM_SEED_SIZE);
    if (rc == 0) {
        ctx->pcrAllocatedBanks = FWTPM_PCR_ALLOC_DEFAULT;
    }
#endif

    if (rc != 0) {
        if (rngInit) {
            wc_FreeRng(&ctx->rng);
        }
        wolfCrypt_Cleanup();
    }

    return rc;
}

int FWTPM_Cleanup(FWTPM_CTX* ctx)
{
    int rc;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Save NV state before cleanup */
#ifndef FWTPM_NO_NV
    rc = FWTPM_NV_Save(ctx);
#else
    rc = TPM_RC_SUCCESS;
#endif

    wc_FreeRng(&ctx->rng);
    wolfCrypt_Cleanup();

    XMEMSET(ctx, 0, sizeof(FWTPM_CTX));

    return rc;
}

const char* FWTPM_GetVersionString(void)
{
    return FWTPM_VERSION_STRING;
}

int FWTPM_Clock_SetHAL(FWTPM_CTX* ctx,
    UINT64 (*get_ms)(void* halCtx), void* halCtx)
{
    if (ctx == NULL || get_ms == NULL) {
        return BAD_FUNC_ARG;
    }
    ctx->clockHal.get_ms = get_ms;
    ctx->clockHal.ctx = halCtx;
    return 0;
}

UINT64 FWTPM_Clock_GetMs(FWTPM_CTX* ctx)
{
    UINT64 now = 0;
    if (ctx == NULL) {
        return 0;
    }
    /* If a clock HAL is registered, use it as the time base */
    if (ctx->clockHal.get_ms != NULL) {
        now = ctx->clockHal.get_ms(ctx->clockHal.ctx);
    }
    return now + ctx->clockOffset;
}

#endif /* WOLFTPM_FWTPM */
