/* fwtpm_optee_nv.c
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

/* fwTPM NV journal on OP-TEE secure storage.
 *
 * Secure storage is byte addressable and fully rewritable, so the journal
 * runs in its default mode: appendOnly and writeAlign stay 0 and no
 * append-only build option is needed. The backing object is encrypted with
 * the hardware unique key and bound to this TA's UUID by the TEE, so the
 * journal MAC on top of it is defense in depth rather than the only
 * protection.
 */

#include <wolftpm/tpm2_types.h>

#include <wolftpm/fwtpm/fwtpm_optee.h>

/* Only an OP-TEE trusted application build has libutee. WOLFSSL_OPTEE is what
 * says so and is what wolfCrypt keys its own TEE support off; WOLFTPM_FWTPM
 * alone is not enough, since a plain Linux fwTPM build defines that too and
 * would then compile this against headers it does not have. */
#if defined(WOLFTPM_FWTPM) && defined(WOLFSSL_OPTEE)

#include <pta_system.h>

/* An erased byte reads as 0xFF, matching the convention the journal uses to
 * recognize unwritten NV. Secure storage reads short at end of stream rather
 * than returning erased bytes, so the gap is filled here. */
#define FWTPM_OPTEE_ERASED_BYTE 0xFF

/* Chunk used to write filler without a large stack buffer. */
#define FWTPM_OPTEE_FILL_CHUNK 256

/* Salt for the TA unique key derivation. Changing it changes the derived
 * key and makes an existing journal fail its integrity check. */
#define FWTPM_OPTEE_KEY_SALT "wolfTPM fwTPM NV journal"

static int FwOpteeNvFill(TEE_ObjectHandle obj, word32 offset, word32 size)
{
    byte chunk[FWTPM_OPTEE_FILL_CHUNK];
    TEE_Result res;
    word32 left = size;
    word32 n;

    XMEMSET(chunk, FWTPM_OPTEE_ERASED_BYTE, sizeof(chunk));

    res = TEE_SeekObjectData(obj, (intmax_t)offset, TEE_DATA_SEEK_SET);
    if (res != TEE_SUCCESS) {
        return TPM_RC_FAILURE;
    }
    while (left > 0) {
        n = (left > sizeof(chunk)) ? (word32)sizeof(chunk) : left;
        res = TEE_WriteObjectData(obj, chunk, (size_t)n);
        if (res != TEE_SUCCESS) {
            return TPM_RC_FAILURE;
        }
        left -= n;
    }
    return TPM_RC_SUCCESS;
}

static int FwOpteeNvRead(void* ctx, word32 offset, byte* buf, word32 size)
{
    FWTPM_OPTEE_NV* nv = (FWTPM_OPTEE_NV*)ctx;
    TEE_Result res;
    size_t got = 0;

    if (nv == NULL || buf == NULL || nv->obj == TEE_HANDLE_NULL) {
        return TPM_RC_FAILURE;
    }
    if (size == 0) {
        return TPM_RC_SUCCESS;
    }
    if (offset > nv->maxSize || size > nv->maxSize - offset) {
        return TPM_RC_FAILURE;
    }

    res = TEE_SeekObjectData(nv->obj, (intmax_t)offset, TEE_DATA_SEEK_SET);
    if (res != TEE_SUCCESS) {
        return TPM_RC_FAILURE;
    }
    res = TEE_ReadObjectData(nv->obj, buf, (size_t)size, &got);
    if (res != TEE_SUCCESS) {
        return TPM_RC_FAILURE;
    }
    /* Short read means end of stream: the rest of the region has never been
     * written, so report it erased. */
    if (got < (size_t)size) {
        XMEMSET(buf + got, FWTPM_OPTEE_ERASED_BYTE, (size_t)size - got);
    }
    return TPM_RC_SUCCESS;
}

static int FwOpteeNvWrite(void* ctx, word32 offset, const byte* buf,
    word32 size)
{
    FWTPM_OPTEE_NV* nv = (FWTPM_OPTEE_NV*)ctx;
    TEE_ObjectInfo info;
    TEE_Result res;
    int rc;

    if (nv == NULL || buf == NULL || nv->obj == TEE_HANDLE_NULL) {
        return TPM_RC_FAILURE;
    }
    if (size == 0) {
        return TPM_RC_SUCCESS;
    }
    if (offset > nv->maxSize || size > nv->maxSize - offset) {
        return TPM_RC_FAILURE;
    }

    /* A seek past the end of the stream makes the TEE fill the gap with
     * zeroes, which the journal would read as written data rather than as
     * erased NV. Fill it explicitly instead. */
    res = TEE_GetObjectInfo1(nv->obj, &info);
    if (res != TEE_SUCCESS) {
        return TPM_RC_FAILURE;
    }
    if (offset > (word32)info.dataSize) {
        rc = FwOpteeNvFill(nv->obj, (word32)info.dataSize,
            offset - (word32)info.dataSize);
        if (rc != TPM_RC_SUCCESS) {
            return rc;
        }
    }

    res = TEE_SeekObjectData(nv->obj, (intmax_t)offset, TEE_DATA_SEEK_SET);
    if (res != TEE_SUCCESS) {
        return TPM_RC_FAILURE;
    }
    res = TEE_WriteObjectData(nv->obj, buf, (size_t)size);
    if (res != TEE_SUCCESS) {
        return TPM_RC_FAILURE;
    }
    return TPM_RC_SUCCESS;
}

static int FwOpteeNvErase(void* ctx, word32 offset, word32 size)
{
    FWTPM_OPTEE_NV* nv = (FWTPM_OPTEE_NV*)ctx;
    TEE_ObjectInfo info;
    TEE_Result res;

    if (nv == NULL || nv->obj == TEE_HANDLE_NULL) {
        return TPM_RC_FAILURE;
    }
    if (size == 0) {
        return TPM_RC_SUCCESS;
    }
    if (offset > nv->maxSize || size > nv->maxSize - offset) {
        return TPM_RC_FAILURE;
    }

    res = TEE_GetObjectInfo1(nv->obj, &info);
    if (res != TEE_SUCCESS) {
        return TPM_RC_FAILURE;
    }
    /* Erasing to the end of the stream is the common case and truncation is
     * cheaper than overwriting: a later read past the end reports erased. */
    if (offset + size >= (word32)info.dataSize) {
        res = TEE_TruncateObjectData(nv->obj, (size_t)offset);
        if (res != TEE_SUCCESS) {
            return TPM_RC_FAILURE;
        }
        return TPM_RC_SUCCESS;
    }
    return FwOpteeNvFill(nv->obj, offset, size);
}

/* Ask the system PTA to derive a key from the hardware unique key, bound to
 * this TA's UUID. Not every platform builds the system PTA in, so the caller
 * falls back when this fails. */
static int FwOpteeDeriveTaKey(byte* key, word32 keySz)
{
    static const TEE_UUID sysUuid = PTA_SYSTEM_UUID;
    TEE_TASessionHandle sess = TEE_HANDLE_NULL;
    TEE_Param params[TEE_NUM_PARAMS];
    TEE_Result res;
    uint32_t origin = 0;
    uint32_t types;

    res = TEE_OpenTASession(&sysUuid, TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
        &origin);
    if (res != TEE_SUCCESS) {
        return TPM_RC_FAILURE;
    }

    XMEMSET(params, 0, sizeof(params));
    params[0].memref.buffer = (void*)FWTPM_OPTEE_KEY_SALT;
    params[0].memref.size = sizeof(FWTPM_OPTEE_KEY_SALT) - 1;
    params[1].memref.buffer = key;
    params[1].memref.size = keySz;
    types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                            TEE_PARAM_TYPE_NONE,
                            TEE_PARAM_TYPE_NONE);

    res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
        PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY, types, params, &origin);
    TEE_CloseTASession(sess);

    if (res != TEE_SUCCESS || params[1].memref.size != keySz) {
        return TPM_RC_FAILURE;
    }
    return TPM_RC_SUCCESS;
}

/* Fallback: a random key held in its own secure storage object. Secure
 * storage is already hardware-unique-key encrypted and TA bound, so this is
 * as strong as the journal it protects, just not re-derivable. */
static int FwOpteeStoredKey(byte* key, word32 keySz)
{
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    TEE_Result res;
    size_t got = 0;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
        FWTPM_OPTEE_KEY_OBJECT_ID, sizeof(FWTPM_OPTEE_KEY_OBJECT_ID) - 1,
        TEE_DATA_FLAG_ACCESS_READ, &obj);
    if (res == TEE_SUCCESS) {
        res = TEE_ReadObjectData(obj, key, (size_t)keySz, &got);
        TEE_CloseObject(obj);
        if (res != TEE_SUCCESS || got != (size_t)keySz) {
            /* A short or failed read can still have written key bytes. */
            TPM2_ForceZero(key, keySz);
            return TPM_RC_FAILURE;
        }
        return TPM_RC_SUCCESS;
    }
    if (res != TEE_ERROR_ITEM_NOT_FOUND) {
        return TPM_RC_FAILURE;
    }

    TEE_GenerateRandom(key, keySz);
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
        FWTPM_OPTEE_KEY_OBJECT_ID, sizeof(FWTPM_OPTEE_KEY_OBJECT_ID) - 1,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
        TEE_HANDLE_NULL, key, (size_t)keySz, &obj);
    if (res != TEE_SUCCESS) {
        TPM2_ForceZero(key, keySz);
        return TPM_RC_FAILURE;
    }
    TEE_CloseObject(obj);
    return TPM_RC_SUCCESS;
}

static int FwOpteeNvIntegrityKey(void* ctx, byte* key, word32* keySz)
{
    int rc;

    (void)ctx;
    /* keySz is output only: the journal zeroes it before the call, so it
     * carries no capacity to check against. The buffer is FWTPM_NV_KEY_SIZE
     * bytes, which is WC_SHA256_DIGEST_SIZE. */
    if (key == NULL || keySz == NULL) {
        return TPM_RC_FAILURE;
    }

    rc = FwOpteeDeriveTaKey(key, WC_SHA256_DIGEST_SIZE);
    if (rc != TPM_RC_SUCCESS) {
        rc = FwOpteeStoredKey(key, WC_SHA256_DIGEST_SIZE);
    }
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    *keySz = WC_SHA256_DIGEST_SIZE;
    return TPM_RC_SUCCESS;
}

UINT64 FWTPM_OPTEE_Clock_GetMs(void* ctx)
{
    TEE_Time now;

    (void)ctx;
    TEE_GetSystemTime(&now);
    return ((UINT64)now.seconds * 1000) + (UINT64)now.millis;
}

int FWTPM_OPTEE_NV_SetHAL(FWTPM_CTX* ctx, FWTPM_OPTEE_NV* nv)
{
    TEE_Result res;

    if (ctx == NULL || nv == NULL) {
        return BAD_FUNC_ARG;
    }

    nv->obj = TEE_HANDLE_NULL;
    nv->maxSize = FWTPM_OPTEE_NV_MAX_SIZE;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
        FWTPM_OPTEE_NV_OBJECT_ID, sizeof(FWTPM_OPTEE_NV_OBJECT_ID) - 1,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
        &nv->obj);
    if (res == TEE_ERROR_ITEM_NOT_FOUND) {
        /* First boot: an empty object reads as erased, which is how the
         * journal decides to generate fresh seeds. */
        res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
            FWTPM_OPTEE_NV_OBJECT_ID, sizeof(FWTPM_OPTEE_NV_OBJECT_ID) - 1,
            TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
            TEE_HANDLE_NULL, NULL, 0, &nv->obj);
    }
    if (res != TEE_SUCCESS) {
        nv->obj = TEE_HANDLE_NULL;
        return TPM_RC_FAILURE;
    }

    /* Zeroed first: appendOnly is a bit-field and must not be indeterminate,
     * or the journal can select write-once behavior. */
    XMEMSET(&nv->hal, 0, sizeof(nv->hal));
    nv->hal.read = FwOpteeNvRead;
    nv->hal.write = FwOpteeNvWrite;
    nv->hal.erase = FwOpteeNvErase;
    nv->hal.get_integrity_key = FwOpteeNvIntegrityKey;
    nv->hal.ctx = nv;
    nv->hal.maxSize = nv->maxSize;

    return FWTPM_NV_SetHAL(ctx, &nv->hal);
}

void FWTPM_OPTEE_NV_Close(FWTPM_OPTEE_NV* nv)
{
    if (nv != NULL && nv->obj != TEE_HANDLE_NULL) {
        TEE_CloseObject(nv->obj);
        nv->obj = TEE_HANDLE_NULL;
    }
}

#endif /* WOLFTPM_FWTPM && WOLFSSL_OPTEE */
