/* mock_tee.c
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

/* RAM-backed implementation of the TEE Internal Core API subset declared in
 * tee_internal_api.h. Secure storage keeps its contents across trusted
 * application create/destroy cycles, as a real TEE does across reboots. */

#include "mock_tee.h"
#include "pta_system.h"

#include <stdio.h>
#include <stdlib.h>

#define MOCK_TEE_MAX_OBJECTS   4
#define MOCK_TEE_MAX_ID        64
#define MOCK_TEE_MAX_DATA      (80 * 1024)

struct MockTeeObject {
    int exists;
    char id[MOCK_TEE_MAX_ID];
    size_t idLen;
    uint8_t data[MOCK_TEE_MAX_DATA];
    size_t size;
    size_t pos;
};

struct MockTeeSession {
    int open;
};

MockTeeFaults mockTeeFaults;

static struct MockTeeObject mockObjects[MOCK_TEE_MAX_OBJECTS];
static struct MockTeeSession mockPtaSession;
static uint8_t mockDerivedKey[32];

void MockTee_Reset(void)
{
    memset(mockObjects, 0, sizeof(mockObjects));
    memset(&mockTeeFaults, 0, sizeof(mockTeeFaults));
    memset(mockDerivedKey, 0x11, sizeof(mockDerivedKey));
}

void MockTee_SetDerivedKey(const uint8_t* key, size_t keySz)
{
    if (keySz != sizeof(mockDerivedKey)) {
        fprintf(stderr, "mock TEE: derived key must be %u bytes\n",
            (unsigned)sizeof(mockDerivedKey));
        abort();
    }
    memcpy(mockDerivedKey, key, keySz);
}

static struct MockTeeObject* MockTee_Find(const void* id, size_t idLen)
{
    int i;

    for (i = 0; i < MOCK_TEE_MAX_OBJECTS; i++) {
        if (mockObjects[i].exists && mockObjects[i].idLen == idLen &&
                memcmp(mockObjects[i].id, id, idLen) == 0) {
            return &mockObjects[i];
        }
    }
    return NULL;
}

uint8_t* MockTee_ObjectData(const char* id, size_t* size)
{
    struct MockTeeObject* obj = MockTee_Find(id, strlen(id));

    if (obj == NULL) {
        return NULL;
    }
    if (size != NULL) {
        *size = obj->size;
    }
    return obj->data;
}

void MockTee_DeleteObject(const char* id)
{
    struct MockTeeObject* obj = MockTee_Find(id, strlen(id));

    if (obj != NULL) {
        memset(obj, 0, sizeof(*obj));
    }
}

void* TEE_Malloc(size_t size, uint32_t hint)
{
    (void)hint;
    return calloc(1, size == 0 ? 1 : size);
}

void* TEE_Realloc(void* buffer, size_t newSize)
{
    return realloc(buffer, newSize);
}

void TEE_Free(void* buffer)
{
    free(buffer);
}

void TEE_GenerateRandom(void* randomBuffer, size_t randomBufferLen)
{
    FILE* f = fopen("/dev/urandom", "rb");
    size_t got = 0;

    if (f != NULL) {
        got = fread(randomBuffer, 1, randomBufferLen, f);
        fclose(f);
    }
    if (got != randomBufferLen) {
        /* A TEE cannot fail this call, so neither may the stand-in. */
        fprintf(stderr, "mock TEE: no /dev/urandom\n");
        abort();
    }
}

void TEE_GetSystemTime(TEE_Time* time)
{
    static uint32_t ticks;

    ticks += 10;
    time->seconds = ticks / 1000;
    time->millis = ticks % 1000;
}

void TEE_GetREETime(TEE_Time* time)
{
    TEE_GetSystemTime(time);
}

TEE_Result TEE_OpenPersistentObject(uint32_t storageID, const void* objectID,
    size_t objectIDLen, uint32_t flags, TEE_ObjectHandle* object)
{
    struct MockTeeObject* obj;

    (void)storageID;
    (void)flags;
    obj = MockTee_Find(objectID, objectIDLen);
    if (obj == NULL) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    if (mockTeeFaults.openFailId != NULL &&
            strlen(mockTeeFaults.openFailId) == objectIDLen &&
            memcmp(mockTeeFaults.openFailId, objectID, objectIDLen) == 0) {
        return mockTeeFaults.openFailResult;
    }
    obj->pos = 0;
    *object = obj;
    return TEE_SUCCESS;
}

TEE_Result TEE_CreatePersistentObject(uint32_t storageID,
    const void* objectID, size_t objectIDLen, uint32_t flags,
    TEE_ObjectHandle attributes, const void* initialData,
    size_t initialDataLen, TEE_ObjectHandle* object)
{
    int i;

    (void)storageID;
    (void)flags;
    (void)attributes;
    if (mockTeeFaults.createFail || objectIDLen > MOCK_TEE_MAX_ID ||
            initialDataLen > MOCK_TEE_MAX_DATA ||
            MockTee_Find(objectID, objectIDLen) != NULL) {
        return TEE_ERROR_GENERIC;
    }
    for (i = 0; i < MOCK_TEE_MAX_OBJECTS; i++) {
        if (!mockObjects[i].exists) {
            memset(&mockObjects[i], 0, sizeof(mockObjects[i]));
            mockObjects[i].exists = 1;
            memcpy(mockObjects[i].id, objectID, objectIDLen);
            mockObjects[i].idLen = objectIDLen;
            if (initialDataLen > 0) {
                memcpy(mockObjects[i].data, initialData, initialDataLen);
            }
            mockObjects[i].size = initialDataLen;
            *object = &mockObjects[i];
            return TEE_SUCCESS;
        }
    }
    return TEE_ERROR_OUT_OF_MEMORY;
}

void TEE_CloseObject(TEE_ObjectHandle object)
{
    (void)object;
}

TEE_Result TEE_GetObjectInfo1(TEE_ObjectHandle object,
    TEE_ObjectInfo* objectInfo)
{
    objectInfo->dataSize = object->size;
    return TEE_SUCCESS;
}

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, intmax_t offset,
    int whence)
{
    if (whence != TEE_DATA_SEEK_SET || offset < 0 ||
            offset > MOCK_TEE_MAX_DATA) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    object->pos = (size_t)offset;
    return TEE_SUCCESS;
}

TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object, void* buffer,
    size_t size, size_t* count)
{
    size_t n = 0;

    if (object->pos < object->size) {
        n = object->size - object->pos;
        if (n > size) {
            n = size;
        }
        memcpy(buffer, object->data + object->pos, n);
    }
    object->pos += n;
    *count = n;
    return TEE_SUCCESS;
}

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, const void* buffer,
    size_t size)
{
    if (size > MOCK_TEE_MAX_DATA - object->pos) {
        return TEE_ERROR_STORAGE_NO_SPACE;
    }
    /* A real TEE zero-fills a gap left by seeking past the end. */
    if (object->pos > object->size) {
        memset(object->data + object->size, 0, object->pos - object->size);
    }
    memcpy(object->data + object->pos, buffer, size);
    object->pos += size;
    if (object->pos > object->size) {
        object->size = object->pos;
    }
    return TEE_SUCCESS;
}

TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, size_t size)
{
    if (size > MOCK_TEE_MAX_DATA) {
        return TEE_ERROR_STORAGE_NO_SPACE;
    }
    if (size > object->size) {
        memset(object->data + object->size, 0, size - object->size);
    }
    object->size = size;
    return TEE_SUCCESS;
}

TEE_Result TEE_OpenTASession(const TEE_UUID* destination,
    uint32_t cancellationRequestTimeout, uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS], TEE_TASessionHandle* session,
    uint32_t* returnOrigin)
{
    static const TEE_UUID sysUuid = PTA_SYSTEM_UUID;

    (void)cancellationRequestTimeout;
    (void)paramTypes;
    (void)params;
    (void)returnOrigin;
    if (mockTeeFaults.deriveFail ||
            memcmp(destination, &sysUuid, sizeof(sysUuid)) != 0) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    mockPtaSession.open = 1;
    *session = &mockPtaSession;
    return TEE_SUCCESS;
}

void TEE_CloseTASession(TEE_TASessionHandle session)
{
    session->open = 0;
}

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session,
    uint32_t cancellationRequestTimeout, uint32_t commandID,
    uint32_t paramTypes, TEE_Param params[TEE_NUM_PARAMS],
    uint32_t* returnOrigin)
{
    size_t n;

    (void)cancellationRequestTimeout;
    (void)returnOrigin;
    if (!session->open || commandID != PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY ||
            paramTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    mockTeeFaults.ptaCalls++;
    n = params[1].memref.size;
    if (n > sizeof(mockDerivedKey)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    memcpy(params[1].memref.buffer, mockDerivedKey, n);
    return TEE_SUCCESS;
}
