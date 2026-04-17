/* fwtpm_nv.h
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

#ifndef _FWTPM_NV_H_
#define _FWTPM_NV_H_

#ifdef WOLFTPM_FWTPM

#include <wolftpm/fwtpm/fwtpm.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* NV storage file path */
#ifndef FWTPM_NV_FILE
#define FWTPM_NV_FILE "fwtpm_nv.bin"
#endif

/* NV file header magic and version */
#define FWTPM_NV_MAGIC     0x66775450  /* "fwTP" */
#define FWTPM_NV_VERSION   4           /* TLV journal format */

/* Hierarchy seed size (SHA-384 digest length) */
#define FWTPM_SEED_SIZE    TPM_SHA384_DIGEST_SIZE

/* Maximum NV region size (default 128 KB) */
#ifndef FWTPM_NV_MAX_SIZE
#define FWTPM_NV_MAX_SIZE  (128 * 1024)
#endif

/* NV marshal size estimates (conservative upper bounds).
 * PUBAREA_EST must cover TPMT_PUBLIC including the largest unique arm.
 * Under v1.85 ML-DSA-87 public keys are 2592 bytes; lift conditionally. */
#ifdef WOLFTPM_V185
#define FWTPM_NV_PUBAREA_EST  2720   /* MLDSA-87 pub + TPMT_PUBLIC header */
#else
#define FWTPM_NV_PUBAREA_EST   600   /* Classical TPMT_PUBLIC max */
#endif
#define FWTPM_NV_NAME_EST       66   /* 2 (alg) + 64 (SHA-512 digest) */
#define FWTPM_NV_AUTH_EST       68   /* 2 (size) + 2 (alg) + 64 (digest) */

/* Maximum single TLV entry value size (PCR state is largest) */
#define FWTPM_NV_MAX_ENTRY (IMPLEMENTATION_PCR * FWTPM_PCR_BANKS * \
                            TPM_MAX_DIGEST_SIZE + 4)

/* NV HAL type alias - struct defined in fwtpm.h as part of FWTPM_CTX */
typedef struct FWTPM_NV_HAL_S FWTPM_NV_HAL;

/* NV file header (stored at start of NV image) */
typedef struct FWTPM_NV_HEADER {
    UINT32 magic;
    UINT32 version;
    UINT32 writePos;    /* Current write position (next append offset) */
    UINT32 maxSize;     /* Total NV region size */
} FWTPM_NV_HEADER;

/* --- TLV Tag definitions ---
 * Each NV entry is: [UINT16 tag][UINT16 length][byte value[length]]
 * Tags 0x0000 = invalid/deleted, 0xFFFF = free space (erased flash).
 * For multi-instance tags (NV index, persistent, cache), the value
 * starts with a UINT32 handle for identification. */

#define FWTPM_NV_TAG_FREE              0xFFFF  /* Erased flash */
#define FWTPM_NV_TAG_INVALID           0x0000  /* Sentinel/deleted */

/* Hierarchy seeds (48 bytes each) */
#define FWTPM_NV_TAG_OWNER_SEED        0x0001
#define FWTPM_NV_TAG_ENDORSEMENT_SEED  0x0002
#define FWTPM_NV_TAG_PLATFORM_SEED     0x0003

/* Hierarchy auth values (variable: 0-48 bytes) */
#define FWTPM_NV_TAG_OWNER_AUTH        0x0010
#define FWTPM_NV_TAG_ENDORSEMENT_AUTH  0x0011
#define FWTPM_NV_TAG_PLATFORM_AUTH     0x0012
#define FWTPM_NV_TAG_LOCKOUT_AUTH      0x0013

/* PCR state (all banks + counter) */
#define FWTPM_NV_TAG_PCR_STATE         0x0020
#define FWTPM_NV_TAG_PCR_AUTH          0x0025  /* Per-PCR auth/policy state */

/* Flags (disableClear, DA params, etc.) */
#define FWTPM_NV_TAG_FLAGS             0x0030

/* Hierarchy policies (value: UINT32 hierarchy + UINT16 alg + digest) */
#define FWTPM_NV_TAG_HIERARCHY_POLICY  0x0035

/* Clock offset (value: UINT64 clockOffset, survives reboot) */
#define FWTPM_NV_TAG_CLOCK             0x0038

/* NV indices (value starts with UINT32 nvHandle) */
#define FWTPM_NV_TAG_NV_INDEX          0x0040
#define FWTPM_NV_TAG_NV_INDEX_DEL      0x0041

/* Persistent objects (value starts with UINT32 handle) */
#define FWTPM_NV_TAG_PERSISTENT        0x0050
#define FWTPM_NV_TAG_PERSISTENT_DEL    0x0051

/* Primary cache (value: UINT32 hierarchy + byte[32] templateHash + ...) */
#define FWTPM_NV_TAG_PRIMARY_CACHE     0x0060
#define FWTPM_NV_TAG_PRIMARY_CACHE_DEL 0x0061

/** @defgroup wolfTPM_fwTPM_NV wolfTPM fwTPM NV Storage
 *
 * NV (non-volatile) storage API for the fwTPM. The default backend is
 * a single file (fwtpm_nv.bin) that holds a TLV journal of all state
 * that must survive reboot: hierarchy seeds, auth values, PCR state,
 * NV indices, persistent objects, and the primary-key cache.
 *
 * Embedded platforms register a raw read/write/erase HAL via
 * FWTPM_NV_SetHAL; the same journal format is used on flash / EEPROM.
 */

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Initialize the NV subsystem. Loads an existing journal (via
    the file backend or the registered HAL) or creates a new empty one.

    \return 0 on success
    \return negative on I/O or format error

    \param ctx pointer to an initialized FWTPM_CTX

    \sa FWTPM_NV_Save
    \sa FWTPM_NV_SetHAL
*/
WOLFTPM_API int FWTPM_NV_Init(FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Compact the NV journal and write the full state. Called
    explicitly during shutdown or when the journal free space drops
    below the compaction threshold.

    \return 0 on success
    \return negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
*/
WOLFTPM_API int FWTPM_NV_Save(FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Register a custom NV HAL. Call after FWTPM_Init and before
    FWTPM_NV_Init to replace the default file-based backend. Typical
    use is a flash / EEPROM driver on embedded targets.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx or hal is NULL

    \param ctx pointer to an initialized FWTPM_CTX
    \param hal pointer to a caller-populated FWTPM_NV_HAL (the struct
        must remain valid for the lifetime of the context)

    \sa FWTPM_NV_Init
*/
WOLFTPM_API int FWTPM_NV_SetHAL(FWTPM_CTX* ctx, FWTPM_NV_HAL* hal);

/* --- Targeted saves — append single entry to journal --- */

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Append the four hierarchy seeds (owner, endorsement,
    platform, null) to the NV journal.

    \return 0 on success
    \return negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
*/
WOLFTPM_API int FWTPM_NV_SaveSeeds(FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Append a single hierarchy auth value to the NV journal.

    \return 0 on success
    \return negative on I/O error
    \return BAD_FUNC_ARG for unknown hierarchy

    \param ctx pointer to an initialized FWTPM_CTX
    \param hierarchy one of TPM_RH_OWNER, TPM_RH_ENDORSEMENT,
        TPM_RH_PLATFORM, TPM_RH_LOCKOUT
*/
WOLFTPM_API int FWTPM_NV_SaveAuth(FWTPM_CTX* ctx, UINT32 hierarchy);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Append the current PCR bank state and update counter.

    \return 0 on success; negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
*/
WOLFTPM_API int FWTPM_NV_SavePcrState(FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Append per-PCR auth values and policies to the NV journal.

    \return 0 on success; negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
*/
WOLFTPM_API int FWTPM_NV_SavePcrAuth(FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Append the flags blob (disableClear, DA parameters, etc.).

    \return 0 on success; negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
*/
WOLFTPM_API int FWTPM_NV_SaveFlags(FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Append the TPM clock offset to the NV journal so that time
    survives a reboot.

    \return 0 on success; negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
*/
WOLFTPM_API int FWTPM_NV_SaveClock(FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Append a single hierarchy policy (digest + alg) to the NV
    journal.

    \return 0 on success; negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
    \param hierarchy one of TPM_RH_OWNER, TPM_RH_ENDORSEMENT,
        TPM_RH_PLATFORM, TPM_RH_LOCKOUT
*/
WOLFTPM_API int FWTPM_NV_SaveHierarchyPolicy(FWTPM_CTX* ctx,
    UINT32 hierarchy);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Append the contents of one NV index slot to the NV journal.

    \return 0 on success; negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
    \param slot index into ctx->nvIndices
*/
WOLFTPM_API int FWTPM_NV_SaveNvIndex(FWTPM_CTX* ctx, int slot);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Mark an NV index as deleted in the NV journal. Space is
    reclaimed on the next compaction.

    \return 0 on success; negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
    \param nvHandle NV index handle (0x01xxxxxx)
*/
WOLFTPM_API int FWTPM_NV_DeleteNvIndex(FWTPM_CTX* ctx, UINT32 nvHandle);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Append a persistent object slot to the NV journal.

    \return 0 on success; negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
    \param slot index into ctx->persistent
*/
WOLFTPM_API int FWTPM_NV_SavePersistent(FWTPM_CTX* ctx, int slot);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Mark a persistent object as deleted in the NV journal.

    \return 0 on success; negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
    \param handle persistent object handle (0x81xxxxxx)
*/
WOLFTPM_API int FWTPM_NV_DeletePersistent(FWTPM_CTX* ctx, UINT32 handle);

/*!
    \ingroup wolfTPM_fwTPM_NV
    \brief Append a primary-key cache entry to the NV journal. The
    primary-key cache ensures CreatePrimary is deterministic per seed.

    \return 0 on success; negative on I/O error

    \param ctx pointer to an initialized FWTPM_CTX
    \param slot index into ctx->primaryCache
*/
WOLFTPM_API int FWTPM_NV_SavePrimaryCache(FWTPM_CTX* ctx, int slot);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFTPM_FWTPM */

#endif /* _FWTPM_NV_H_ */
