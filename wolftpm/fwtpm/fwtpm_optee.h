/* fwtpm_optee.h
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

/* fwTPM as an OP-TEE trusted application. Platform independent: anything
 * with an OP-TEE secure world and the TEE Internal Core API can use it. */

#ifndef _FWTPM_OPTEE_H_
#define _FWTPM_OPTEE_H_

/* Only an OP-TEE trusted application build has libutee, and WOLFSSL_OPTEE is
 * what says so. WOLFTPM_FWTPM alone is not enough: a plain Linux fwTPM build
 * defines that too, and an "every .c file" build would then reach for headers
 * that are not there. */
#if defined(WOLFTPM_FWTPM) && defined(WOLFSSL_OPTEE)

#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_nv.h>

#include <tee_internal_api.h>

#endif /* WOLFTPM_FWTPM && WOLFSSL_OPTEE */

#ifdef __cplusplus
    extern "C" {
#endif

/* Command IDs and the trusted application's UUID. Shared with the
 * normal-world client, so they stay outside WOLFTPM_FWTPM: a client holding
 * only libteec can include this header and use them. A source that wants the
 * secure-world declarations below must include <wolftpm/tpm2_types.h> first,
 * since that is what defines WOLFTPM_FWTPM. */

/* Every OP-TEE trusted application is identified by a UUID rather than a
 * name. It is not cosmetic and not per-build: the TEE loads a filesystem
 * trusted application from /lib/optee_armtz/<uuid>.ta, and a client opens a
 * session by UUID, so the same value has to appear in three places that are
 * built separately.
 *
 *   1. the trusted application's TA_UUID, via user_ta_header_defines.h
 *   2. the signed binary's filename
 *   3. the client, which is WOLFTPM_OPTEE_TA_UUID below
 *
 * This is the UUID wolfTPM's fwTPM trusted application uses, so a stock
 * client and a stock trusted application interoperate with no configuration.
 * A port that wants its own identity overrides these and must change all
 * three together; a mismatch shows up only at run time, as
 * TEEC_ERROR_ITEM_NOT_FOUND (0xffff0008) from TEEC_OpenSession.
 *
 * Derive every form from these rather than restating the digits. */
#ifndef WOLFTPM_OPTEE_TA_UUID_STR
#define WOLFTPM_OPTEE_TA_UUID_STR "9013be0e-39b0-4ed4-80e0-1242c0daf382"
#define WOLFTPM_OPTEE_TA_UUID_P1  0x9013be0e
#define WOLFTPM_OPTEE_TA_UUID_P2  0x39b0
#define WOLFTPM_OPTEE_TA_UUID_P3  0x4ed4
#define WOLFTPM_OPTEE_TA_UUID_P4  { 0x80, 0xe0, 0x12, 0x42, \
                                    0xc0, 0xda, 0xf3, 0x82 }
#endif

/* params[0] memref-input:  TPM 2.0 command packet
 * params[1] memref-output: TPM 2.0 response packet, resized to the response
 * Both buffers are normal-world memory, so the TA copies in and out. */
#define FWTPM_OPTEE_CMD_SUBMIT      0

/* Flush transient objects, sessions and sequences. No parameters. The TA
 * does this on session close as well; the command exists so a client can
 * drop its own transient state without reconnecting. */
#define FWTPM_OPTEE_CMD_RESET       1

/* params[0] value-output a: FWTPM_OPTEE_ABI_VERSION
 * params[0] value-output b: FWTPM_MAX_COMMAND_SIZE of the built TA */
#define FWTPM_OPTEE_CMD_GET_INFO    2

/* Bumped when the command IDs or their parameter layout change. */
#define FWTPM_OPTEE_ABI_VERSION     1

/* The TA is the TPM, so the client passes no locality and the TA reports a
 * fixed one. Locality is stored verbatim into the command context, so it must
 * never come from the normal world. */
#define FWTPM_OPTEE_LOCALITY        0

#if defined(WOLFTPM_FWTPM) && defined(WOLFSSL_OPTEE)

/* Object ID of the NV journal in TEE_STORAGE_PRIVATE. Private storage is
 * keyed to the TA UUID, so the name only has to be unique within the TA. */
#ifndef FWTPM_OPTEE_NV_OBJECT_ID
#define FWTPM_OPTEE_NV_OBJECT_ID "wolftpm.fwtpm.nv"
#endif

/* Object ID of the fallback integrity key, used only when the platform has
 * no system PTA to derive a TA unique key from. */
#ifndef FWTPM_OPTEE_KEY_OBJECT_ID
#define FWTPM_OPTEE_KEY_OBJECT_ID "wolftpm.fwtpm.nvkey"
#endif

#ifndef FWTPM_OPTEE_NV_MAX_SIZE
#define FWTPM_OPTEE_NV_MAX_SIZE (64 * 1024)
#endif

/* NV journal backed by OP-TEE secure storage. One of these must outlive the
 * FWTPM_CTX it is registered with: FWTPM_NV_SetHAL copies the HAL struct but
 * keeps the hal.ctx pointer, which points here. */
typedef struct FWTPM_OPTEE_NV {
    FWTPM_NV_HAL hal;
    TEE_ObjectHandle obj;
    word32 maxSize;
} FWTPM_OPTEE_NV;

/*!
    \brief Open (or create) the secure storage NV journal and register it as
    the NV HAL for ctx. Must be called before FWTPM_Init, which is what runs
    FWTPM_NV_Init.

    \return TPM_RC_SUCCESS on success
    \return TPM_RC_FAILURE if secure storage is unavailable
    \return BAD_FUNC_ARG if ctx or nv is NULL

    \param ctx pointer to a zeroed FWTPM_CTX
    \param nv pointer to a zeroed FWTPM_OPTEE_NV that outlives ctx
*/
int FWTPM_OPTEE_NV_SetHAL(FWTPM_CTX* ctx, FWTPM_OPTEE_NV* nv);

/*!
    \brief Close the secure storage object. Call after FWTPM_Cleanup, which
    performs the final journal write.

    \param nv pointer to the FWTPM_OPTEE_NV passed to FWTPM_OPTEE_NV_SetHAL
*/
void FWTPM_OPTEE_NV_Close(FWTPM_OPTEE_NV* nv);

/*!
    \brief Millisecond clock HAL backed by TEE_GetSystemTime, for
    FWTPM_Clock_SetHAL. The TEE system time is monotonic across the TA
    instance but has no relation to wall clock, which is what the TPM clock
    needs.

    \return milliseconds since an arbitrary fixed point

    \param ctx unused
*/
UINT64 FWTPM_OPTEE_Clock_GetMs(void* ctx);

#endif /* WOLFTPM_FWTPM && WOLFSSL_OPTEE */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _FWTPM_OPTEE_H_ */
