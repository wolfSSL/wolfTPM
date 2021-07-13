/* tpm_test_keys.c
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

/* use ANSI stdio for support of format strings, must be set before
 * including stdio.h
 */
#if defined(__MINGW32__) || defined(__MINGW64__)
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include "tpm_test.h"
#include "tpm_test_keys.h"
#include <wolftpm/tpm2_wrap.h>

#define RSA_FILENAME  "rsa_test_blob.raw"
#define ECC_FILENAME  "ecc_test_blob.raw"

#ifndef WOLFTPM2_NO_WRAPPER

int writeKeyPubPem(const char* filename, byte *buf, int bufSz)
{
    int rc = TPM_RC_FAILURE;

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    XFILE fp = NULL;
    size_t fileSz = 0;

    if (filename == NULL || buf == NULL)
        return BAD_FUNC_ARG;

    fp = XFOPEN(filename, "wt");
    if (fp != XBADFILE) {
        fileSz = XFWRITE(buf, 1, bufSz, fp);
        /* sanity check */
        if (fileSz == (word32)bufSz) {
            rc = TPM_RC_SUCCESS;
        }
#ifdef DEBUG_WOLFTPM
        printf("Public PEM file size = %zu\n", fileSz);
        TPM2_PrintBin(buf, bufSz);
#endif
        XFCLOSE(fp);
    }
#endif
    return rc;
}


int writeKeyBlob(const char* filename,
                        WOLFTPM2_KEYBLOB* key)
{
    int rc = 0;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    XFILE  fp = NULL;
    size_t fileSz = 0;
    byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];
    int pubAreaSize;

    fp = XFOPEN(filename, "wb");
    if (fp != XBADFILE) {
        /* Make publicArea in encoded format to eliminate empty fields, save space */
        rc = TPM2_AppendPublic(pubAreaBuffer, (word32)sizeof(pubAreaBuffer),
            &pubAreaSize, &key->pub);
        if (rc != TPM_RC_SUCCESS)
            return rc;
        if (pubAreaSize != (key->pub.size + (int)sizeof(key->pub.size))) {
            printf("writeKeyBlob: Sanity check for publicArea size failed\n");
            return BUFFER_E;
        }
    #ifdef WOLFTPM_DEBUG_VERBOSE
        TPM2_PrintBin(pubAreaBuffer, pubAreaSize);
    #endif
        /* Write size marker for the public part */
        fileSz += XFWRITE(&key->pub.size, 1, sizeof(key->pub.size), fp);
        /* Write the public part with bytes aligned */
        fileSz += XFWRITE(pubAreaBuffer, 1, sizeof(UINT16) + key->pub.size, fp);
        /* Write the private part, size marker is included */
        fileSz += XFWRITE(&key->priv, 1, sizeof(UINT16) + key->priv.size, fp);
        XFCLOSE(fp);
    }
    printf("Wrote %d bytes to %s\n", (int)fileSz, filename);
#else
    (void)filename;
    (void)key;
#endif /* !NO_FILESYSTEM && !NO_WRITE_TEMP_FILES */
    return rc;
}

int readKeyBlob(const char* filename, WOLFTPM2_KEYBLOB* key)
{
    int rc = 0;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    XFILE  fp = NULL;
    size_t fileSz = 0;
    size_t bytes_read = 0;
    byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];
    int pubAreaSize;

    XMEMSET(key, 0, sizeof(WOLFTPM2_KEYBLOB));

    fp = XFOPEN(filename, "rb");
    if (fp != XBADFILE) {
        XFSEEK(fp, 0, XSEEK_END);
        fileSz = XFTELL(fp);
        XREWIND(fp);
        if (fileSz > sizeof(key->priv) + sizeof(key->pub)) {
            printf("File size check failed\n");
            rc = BUFFER_E; goto exit;
        }
        printf("Reading %d bytes from %s\n", (int)fileSz, filename);

        bytes_read = XFREAD(&key->pub.size, 1, sizeof(key->pub.size), fp);
        if (bytes_read != sizeof(key->pub.size)) {
            printf("Read %zu, expected size marker of %zu bytes\n",
                bytes_read, sizeof(key->pub.size));
            goto exit;
        }
        fileSz -= bytes_read;

        bytes_read = XFREAD(pubAreaBuffer, 1, sizeof(UINT16) + key->pub.size, fp);
        if (bytes_read != sizeof(UINT16) + key->pub.size) {
            printf("Read %zu, expected public blob %zu bytes\n",
                bytes_read, sizeof(UINT16) + key->pub.size);
            goto exit;
        }
        fileSz -= bytes_read; /* Reminder bytes for private key part */

        /* Decode the byte stream into a publicArea structure ready for use */
        rc = TPM2_ParsePublic(&key->pub, pubAreaBuffer,
            (word32)sizeof(pubAreaBuffer), &pubAreaSize);
        if (rc != TPM_RC_SUCCESS) return rc;
    #ifdef DEBUG_WOLFTPM
        TPM2_PrintPublicArea(&key->pub);
    #endif

        if (fileSz > 0) {
            printf("Reading the private part of the key\n");
            bytes_read = XFREAD(&key->priv, 1, fileSz, fp);
            if (bytes_read != fileSz) {
                printf("Read %zu, expected private blob %zu bytes\n",
                    bytes_read, fileSz);
                goto exit;
            }
            rc = 0; /* success */
        }

        /* sanity check the sizes */
        if (pubAreaSize != (key->pub.size + (int)sizeof(key->pub.size)) ||
             key->priv.size > sizeof(key->priv.buffer)) {
            printf("Struct size check failed (pub %d, priv %d)\n",
                   key->pub.size, key->priv.size);
            rc = BUFFER_E;
        }
    }
    else {
        rc = BUFFER_E;
        printf("File %s not found!\n", filename);
        printf("Keys can be generated by running:\n"
               "  ./examples/keygen/keygen rsa_test_blob.raw -rsa -t\n"
               "  ./examples/keygen/keygen ecc_test_blob.raw -ecc -t\n");
    }

exit:
    if (fp)
      XFCLOSE(fp);
#else
    (void)filename;
    (void)key;
#endif /* !NO_FILESYSTEM && !NO_WRITE_TEMP_FILES */
    return rc;
}

int createAndLoadKey(WOLFTPM2_DEV* pDev,
                WOLFTPM2_KEY* key,
                WOLFTPM2_HANDLE* parent,
                const char* filename,
                const byte* auth,
                int authSz,
                TPMT_PUBLIC* publicTemplate)
{
    int rc;
    WOLFTPM2_KEYBLOB keyblob;

    rc = readAndLoadKey(pDev, key, parent, filename, auth, authSz);
    if (rc == 0) {
        return rc;
    }
    /* read failed, so let's create a new key */
    
    /* if a public template was not provided we cannot create */
    if (publicTemplate == NULL) {
        return BUFFER_E;
    }


    XMEMSET(&keyblob, 0, sizeof(keyblob));
    rc = wolfTPM2_CreateKey(pDev, &keyblob, parent,
                            publicTemplate, auth, authSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateKey failed\n");
        return rc;
    }
    printf("Created new key (pub %d, priv %d bytes)\n",
        keyblob.pub.size, keyblob.priv.size);

    /* Save key as encrypted blob to the disk */
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_FILESYSTEM)
    rc = writeKeyBlob(filename, &keyblob);
    if (rc != 0) {
        return rc;
    }
#endif

    /* Load Key */
    rc = wolfTPM2_LoadKey(pDev, &keyblob, parent);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        return rc;
    }
    printf("Loaded key to 0x%x\n",
        (word32)keyblob.handle.hndl);

    key->handle = keyblob.handle;
    key->pub    = keyblob.pub;
    key->handle.auth.size = authSz;
    XMEMCPY(key->handle.auth.buffer, auth, authSz);

    return rc;
}

int readAndLoadKey(WOLFTPM2_DEV* pDev,
                          WOLFTPM2_KEY* key,
                          WOLFTPM2_HANDLE* parent,
                          const char* filename,
                          const byte* auth,
                          int authSz)
{
    int rc;
    WOLFTPM2_KEYBLOB keyblob;

    /* clear output key buffer */
    XMEMSET(key, 0, sizeof(WOLFTPM2_KEY));

    rc = readKeyBlob(filename, &keyblob);
    if (rc != 0) {
        /* if does not exist - create */

        return rc;
    }

    rc = wolfTPM2_LoadKey(pDev, &keyblob, parent);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        return rc;
    }
    printf("Loaded key to 0x%x\n",
        (word32)keyblob.handle.hndl);

    key->handle = keyblob.handle;
    key->pub    = keyblob.pub;
    key->handle.auth.size = authSz;
    XMEMCPY(key->handle.auth.buffer, auth, authSz);

    return rc;
}

int getPrimaryStoragekey(WOLFTPM2_DEV* pDev,
                                       WOLFTPM2_KEY* pStorageKey,
                                       TPM_ALG_ID alg)
{
    int rc;

    /* See if SRK already exists */
    rc = wolfTPM2_ReadPublicKey(pDev, pStorageKey, TPM2_DEMO_STORAGE_KEY_HANDLE);
    if (rc != 0) {
        /* Create primary storage key */
        rc = wolfTPM2_CreateSRK(pDev, pStorageKey, alg,
            (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
    #ifndef WOLFTPM_WINAPI
        if (rc == TPM_RC_SUCCESS) {
            /* Move storage key into persistent NV */
            rc = wolfTPM2_NVStoreKey(pDev, TPM_RH_OWNER, pStorageKey,
                TPM2_DEMO_STORAGE_KEY_HANDLE);
        }
    #endif
    }
    else {
        /* specify auth password for storage key */
        pStorageKey->handle.auth.size = sizeof(gStorageKeyAuth)-1;
        XMEMCPY(pStorageKey->handle.auth.buffer, gStorageKeyAuth,
                pStorageKey->handle.auth.size);
    }
    if (rc != 0) {
        printf("Loading SRK: Storage failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        return rc;
    }
    printf("Loading SRK: Storage 0x%x (%d bytes)\n",
        (word32)pStorageKey->handle.hndl, pStorageKey->pub.size);
    return rc;
}

int getRSAkey(WOLFTPM2_DEV* pDev,
                            WOLFTPM2_KEY* pStorageKey,
                            WOLFTPM2_KEY* key,
                            void* pWolfRsaKey,
                            int tpmDevId,
                            const byte* auth, int authSz,
                            TPMT_PUBLIC* publicTemplate)
{
    int rc = 0;

    /* Create/Load RSA key */
    rc = createAndLoadKey(pDev, key, &pStorageKey->handle,
                        RSA_FILENAME,
                        auth, authSz, publicTemplate);
    if (rc != 0) {
        return rc;
    }

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    if (pWolfRsaKey) {
        /* setup wolf RSA key with TPM deviceID, so crypto callbacks are used */
        rc = wc_InitRsaKey_ex((RsaKey*)pWolfRsaKey, NULL, tpmDevId);
        if (rc != 0) return rc;

        /* load public portion of key into wolf RSA Key */
        rc = wolfTPM2_RsaKey_TpmToWolf(pDev, key, (RsaKey*)pWolfRsaKey);
    }
#else
    (void)pWolfRsaKey;
    (void)tpmDevId;
#endif /* !WOLFTPM2_NO_WOLFCRYPT && !NO_RSA */

    return rc;
}

int getECCkey(WOLFTPM2_DEV* pDev,
                            WOLFTPM2_KEY* pStorageKey,
                            WOLFTPM2_KEY* key,
                            void* pWolfEccKey,
                            int tpmDevId,
                            const byte* auth, int authSz,
                            TPMT_PUBLIC* publicTemplate)
{
    int rc = 0;

    /* Create/Load ECC key */
    rc = createAndLoadKey(pDev, key, &pStorageKey->handle,
                        ECC_FILENAME,
                        auth, authSz, publicTemplate);
    if (rc != 0) {
        return rc;
    }
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC)
    if (pWolfEccKey) {
        /* setup wolf ECC key with TPM deviceID, so crypto callbacks are used */
        rc = wc_ecc_init_ex((ecc_key*)pWolfEccKey, NULL, tpmDevId);
        if (rc != 0) return rc;

        /* load public portion of key into wolf ECC Key */
        rc = wolfTPM2_EccKey_TpmToWolf(pDev, key, (ecc_key*)pWolfEccKey);
    }
#else
    (void)pWolfEccKey;
    (void)tpmDevId;
#endif /* !WOLFTPM2_NO_WRAPPER && HAVE_ECC */

    return rc;
}

#endif /* !WOLFTPM2_NO_WRAPPER */
