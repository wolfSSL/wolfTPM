/* fwtpm_tis_sem.c
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

#if defined(WOLFTPM_FWTPM_TIS) || defined(WOLFTPM_FWTPM_HAL)

#include <wolftpm/fwtpm/fwtpm_tis.h>

static int TisMakeSemName(const char* base, UINT64 ownerId, char* name,
    size_t nameSz)
{
    int nameLen;

    if (base == NULL || name == NULL || nameSz == 0U) {
        return -1;
    }
    nameLen = XSNPRINTF(name, nameSz, "%s-%016llx", base,
        (unsigned long long)ownerId);
    if (nameLen <= 0 || (size_t)nameLen >= nameSz) {
        return -1;
    }
    return 0;
}

WOLFTPM_LOCAL int FWTPM_TIS_MakeSemNames(UINT64 ownerUid, char* semCmd,
    size_t semCmdSz, char* semRsp, size_t semRspSz)
{
    /* Namespacing only, not a cryptographic identity. The authenticated UID
     * remains stable when the shared-memory pathname is removed after a
     * crash, allowing the next server to collect both semaphore objects. */
    UINT64 ownerId = ownerUid * 0x9E3779B185EBCA87ULL;

    if (TisMakeSemName(FWTPM_TIS_SEM_CMD, ownerId, semCmd, semCmdSz) != 0 ||
            TisMakeSemName(FWTPM_TIS_SEM_RSP, ownerId, semRsp,
                semRspSz) != 0) {
        return -1;
    }
    return 0;
}

#endif /* WOLFTPM_FWTPM_TIS || WOLFTPM_FWTPM_HAL */
