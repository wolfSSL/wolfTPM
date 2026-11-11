/* mock_tee.h
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

/* Controls for the mock TEE in mock_tee.c: inspect secure storage and inject
 * the failures a real TEE can produce. */

#ifndef MOCK_TEE_H
#define MOCK_TEE_H

#include "tee_internal_api.h"

#ifdef __cplusplus
    extern "C" {
#endif

typedef struct MockTeeFaults {
    int        deriveFail;    /* system PTA unavailable */
    const char* openFailId;   /* existing object that fails to open... */
    TEE_Result openFailResult;/* ...with this result */
    int        createFail;    /* TEE_CreatePersistentObject fails */
    int        ptaCalls;      /* key derivations performed */
} MockTeeFaults;

extern MockTeeFaults mockTeeFaults;

/* Erase all secure storage and reset the faults. */
void MockTee_Reset(void);
/* Value the system PTA derives as this TA's unique key. */
void MockTee_SetDerivedKey(const uint8_t* key, size_t keySz);
/* Object contents, or NULL when the object does not exist. */
uint8_t* MockTee_ObjectData(const char* id, size_t* size);
/* Remove one object from secure storage. */
void MockTee_DeleteObject(const char* id);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* MOCK_TEE_H */
