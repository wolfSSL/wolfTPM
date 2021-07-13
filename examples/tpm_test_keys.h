/* tpm_test_keys.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#ifndef _TPM_TEST_KEYS_H_
#define _TPM_TEST_KEYS_H_

#ifndef WOLFTPM2_NO_WRAPPER
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

WOLFTPM_LOCAL int readKeyBlob(const char* filename, WOLFTPM2_KEYBLOB* key);
WOLFTPM_LOCAL int writeKeyBlob(const char* filename, WOLFTPM2_KEYBLOB* key);
WOLFTPM_LOCAL int writeKeyPubPem(const char* filename, byte *buf, int bufSz);

WOLFTPM_LOCAL int readAndLoadKey(WOLFTPM2_DEV* pDev,
                          WOLFTPM2_KEY* key,
                          WOLFTPM2_HANDLE* parent,
                          const char* filename,
                          const byte* auth,
                          int authSz);

WOLFTPM_LOCAL int createAndLoadKey(WOLFTPM2_DEV* pDev,
                WOLFTPM2_KEY* key,
                WOLFTPM2_HANDLE* parent,
                const char* filename,
                const byte* auth,
                int authSz,
                TPMT_PUBLIC* publicTemplate);


WOLFTPM_LOCAL int getPrimaryStoragekey(WOLFTPM2_DEV* pDev,
                                       WOLFTPM2_KEY* pStorageKey,
                                       TPM_ALG_ID alg);

WOLFTPM_LOCAL int getRSAkey(WOLFTPM2_DEV* pDev,
                            WOLFTPM2_KEY* pStorageKey,
                            WOLFTPM2_KEY* key,
                            void* pWolfRsaKey,
                            int tpmDevId,
                            const byte* auth, int authSz,
                            TPMT_PUBLIC* publicTemplate);

WOLFTPM_LOCAL int getECCkey(WOLFTPM2_DEV* pDev,
                            WOLFTPM2_KEY* pStorageKey,
                            WOLFTPM2_KEY* key,
                            void* pWolfEccKey,
                            int tpmDevId,
                            const byte* auth, int authSz,
                            TPMT_PUBLIC* publicTemplate);

#endif /* !WOLFTPM2_NO_WRAPPER */

#endif /* _TPM_TEST_KEYS_H_ */
