/* tpm_test_keys.h
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

#ifndef _TPM_TEST_KEYS_H_
#define _TPM_TEST_KEYS_H_

#ifndef WOLFTPM2_NO_WRAPPER
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

WOLFTPM_LOCAL int readKeyBlob(const char* filename, WOLFTPM2_KEYBLOB* key);
WOLFTPM_LOCAL int writeKeyBlob(const char* filename, WOLFTPM2_KEYBLOB* key);

WOLFTPM_LOCAL int writeBin(const char* filename, const byte *buf, word32 bufSz);
WOLFTPM_LOCAL int readBin(const char* filename, byte *buf, word32* bufSz);

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

#if defined(WOLFTPM_MLDSA) || defined(WOLFTPM_MLKEM)
/* Create a transient PQC primary and start an HMAC param-enc session using it:
 * ML-KEM as the session salt key, ML-DSA as the bind key (with a transient SRK
 * salt, since sign-only ML-DSA cannot supply one). The session is started but
 * not assigned a slot; the caller calls wolfTPM2_SetAuthSession() and later
 * unloads pqcKey->handle and session->handle. */
WOLFTPM_LOCAL int getPrimaryParamEncKey(WOLFTPM2_DEV* pDev,
                                        WOLFTPM2_SESSION* session,
                                        WOLFTPM2_KEY* pqcKey,
                                        TPM_ALG_ID pqcAlg,
                                        int paramSet,
                                        int paramEncAlg);

/* Parse a PQC parameter-set value ("mlkem[=512|768|1024]" /
 * "mldsa[=44|65|87]"). Returns 1 on a valid value (sets the alg and paramSet
 * outputs), -1 if a PQC algorithm is named with an unsupported set (printed),
 * or 0 if not a PQC value. parsePqcParamEncArg() takes the "-" option form. */
WOLFTPM_LOCAL int parsePqcParamSet(const char* val, TPM_ALG_ID* alg,
                                   int* paramSet);
WOLFTPM_LOCAL int parsePqcParamEncArg(const char* arg, TPM_ALG_ID* alg,
                                      int* paramSet);
#endif

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


/* if *buf != NULL, it will use existing buffer and provided bufLen */
WOLFTPM_LOCAL int loadFile(const char* fname, byte** buf, size_t* bufLen);

WOLFTPM_LOCAL int hexToByte(const char *hex, unsigned char *output, unsigned long sz);
WOLFTPM_LOCAL void printHexString(const unsigned char* bin, unsigned long sz,
    unsigned long maxLine);

#endif /* !WOLFTPM2_NO_WRAPPER */

#endif /* _TPM_TEST_KEYS_H_ */
