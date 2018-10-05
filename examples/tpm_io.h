/* tpm_io.h
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _TPM_IO_H_
#define _TPM_IO_H_

#include <wolftpm/tpm2.h>

/* Configuration */
#define TPM2_DEMO_STORAGE_KEY_HANDLE    0x81000200  /* Persistent Storage Key Handle */

#define TPM2_DEMO_RSA_IDX               0x20        /* offset handle to unused index */
#define TPM2_DEMO_RSA_KEY_HANDLE        (0x81000000 + TPM2_DEMO_RSA_IDX) /* Persistent Key Handle */
#define TPM2_DEMO_RSA_CERT_HANDLE       (0x01800000 + TPM2_DEMO_RSA_IDX) /* NV Handle */

#define TPM2_DEMO_ECC_IDX               0x21        /* offset handle to unused index */
#define TPM2_DEMO_ECC_KEY_HANDLE        (0x81000000 + TPM2_DEMO_ECC_IDX) /* Persistent Key Handle */
#define TPM2_DEMO_ECC_CERT_HANDLE       (0x01800000 + TPM2_DEMO_ECC_IDX) /* NV Handle */

static const char gStorageKeyAuth[] = "ThisIsMyStorageKeyAuth";
static const char gKeyAuth[] =        "ThisIsMyKeyAuth";
static const char gUsageAuth[] =      "ThisIsASecretUsageAuth";

/* TPM2 IO Examples */
#ifdef WOLFTPM_ADV_IO
int TPM2_IoCb(TPM2_CTX*, int isRead, word32 addr, byte* buf, word16 size,
    void* userCtx);
#else
int   TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx);
#endif

#endif /* _TPM_IO_H_ */
