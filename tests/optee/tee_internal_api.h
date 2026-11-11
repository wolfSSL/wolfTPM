/* tee_internal_api.h
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

/* Host stand-in for the parts of OP-TEE's TEE Internal Core API that the
 * fwTPM trusted application and wolfCrypt's WOLFSSL_OPTEE support use, so
 * both can be built and tested without a TEE. Implemented in mock_tee.c. */

#ifndef MOCK_TEE_INTERNAL_API_H
#define MOCK_TEE_INTERNAL_API_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
    extern "C" {
#endif

typedef uint32_t TEE_Result;

typedef struct {
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[8];
} TEE_UUID;

typedef struct {
    uint32_t seconds;
    uint32_t millis;
} TEE_Time;

typedef union {
    struct {
        void* buffer;
        size_t size;
    } memref;
    struct {
        uint32_t a;
        uint32_t b;
    } value;
} TEE_Param;

typedef struct {
    size_t dataSize;
} TEE_ObjectInfo;

typedef struct MockTeeObject* TEE_ObjectHandle;
typedef struct MockTeeSession* TEE_TASessionHandle;

#define TEE_NUM_PARAMS                  4
#define TEE_HANDLE_NULL                 NULL

#define TEE_SUCCESS                     0x00000000u
#define TEE_ERROR_GENERIC               0xFFFF0000u
#define TEE_ERROR_BAD_FORMAT            0xFFFF0005u
#define TEE_ERROR_BAD_PARAMETERS        0xFFFF0006u
#define TEE_ERROR_ITEM_NOT_FOUND        0xFFFF0008u
#define TEE_ERROR_NOT_SUPPORTED         0xFFFF000Au
#define TEE_ERROR_OUT_OF_MEMORY         0xFFFF000Cu
#define TEE_ERROR_BUSY                  0xFFFF000Du
#define TEE_ERROR_SHORT_BUFFER          0xFFFF0010u
#define TEE_ERROR_STORAGE_NOT_AVAILABLE 0xF0100003u
#define TEE_ERROR_STORAGE_NO_SPACE      0xF0100005u

#define TEE_STORAGE_PRIVATE             0x00000001u
#define TEE_DATA_FLAG_ACCESS_READ       0x00000001u
#define TEE_DATA_FLAG_ACCESS_WRITE      0x00000002u
#define TEE_DATA_SEEK_SET               0
#define TEE_TIMEOUT_INFINITE            0xFFFFFFFFu
#define TEE_MALLOC_FILL_ZERO            0x00000000u

#define TEE_PARAM_TYPE_NONE             0u
#define TEE_PARAM_TYPE_VALUE_INPUT      1u
#define TEE_PARAM_TYPE_VALUE_OUTPUT     2u
#define TEE_PARAM_TYPE_VALUE_INOUT      3u
#define TEE_PARAM_TYPE_MEMREF_INPUT     5u
#define TEE_PARAM_TYPE_MEMREF_OUTPUT    6u
#define TEE_PARAM_TYPE_MEMREF_INOUT     7u
#define TEE_PARAM_TYPES(t0, t1, t2, t3) \
    ((t0) | ((t1) << 4) | ((t2) << 8) | ((t3) << 12))

#define EMSG(...) do { } while (0)
#define IMSG(...) do { } while (0)
#define DMSG(...) do { } while (0)

void* TEE_Malloc(size_t size, uint32_t hint);
void* TEE_Realloc(void* buffer, size_t newSize);
void TEE_Free(void* buffer);

void TEE_GenerateRandom(void* randomBuffer, size_t randomBufferLen);
void TEE_GetSystemTime(TEE_Time* time);
void TEE_GetREETime(TEE_Time* time);

TEE_Result TEE_OpenPersistentObject(uint32_t storageID, const void* objectID,
    size_t objectIDLen, uint32_t flags, TEE_ObjectHandle* object);
TEE_Result TEE_CreatePersistentObject(uint32_t storageID,
    const void* objectID, size_t objectIDLen, uint32_t flags,
    TEE_ObjectHandle attributes, const void* initialData,
    size_t initialDataLen, TEE_ObjectHandle* object);
void TEE_CloseObject(TEE_ObjectHandle object);
TEE_Result TEE_GetObjectInfo1(TEE_ObjectHandle object,
    TEE_ObjectInfo* objectInfo);
TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, intmax_t offset,
    int whence);
TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object, void* buffer,
    size_t size, size_t* count);
TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, const void* buffer,
    size_t size);
TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, size_t size);

TEE_Result TEE_OpenTASession(const TEE_UUID* destination,
    uint32_t cancellationRequestTimeout, uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS], TEE_TASessionHandle* session,
    uint32_t* returnOrigin);
void TEE_CloseTASession(TEE_TASessionHandle session);
TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session,
    uint32_t cancellationRequestTimeout, uint32_t commandID,
    uint32_t paramTypes, TEE_Param params[TEE_NUM_PARAMS],
    uint32_t* returnOrigin);

/* Trusted application entry points, which OP-TEE declares in tee_ta_api.h. */
TEE_Result TA_CreateEntryPoint(void);
void TA_DestroyEntryPoint(void);
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS], void** sessCtx);
void TA_CloseSessionEntryPoint(void* sessCtx);
TEE_Result TA_InvokeCommandEntryPoint(void* sessCtx, uint32_t cmdId,
    uint32_t paramTypes, TEE_Param params[TEE_NUM_PARAMS]);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* MOCK_TEE_INTERNAL_API_H */
