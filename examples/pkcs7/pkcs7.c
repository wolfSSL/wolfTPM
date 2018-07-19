/* pkcs7.c
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


#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(HAVE_PKCS7) && \
     defined(WOLF_CRYPTO_DEV)

#include <examples/tpm_io.h>
#include <examples/pkcs7/pkcs7.h>
#include <wolfssl/wolfcrypt/pkcs7.h>

/* Sign PKCS7 using TPM based key:
 * Must Run:
 * 1. `./examples/csr/csr`
 * 2. `./certs/certreq.sh`
 * 3. Results in `./certs/client-rsa-cert.der`
 */


/******************************************************************************/
/* --- BEGIN TPM2 PKCS7 Example -- */
/******************************************************************************/

int TPM2_PKCS7_Example(void* userCtx)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY rsaKey;
    TPMT_PUBLIC publicTemplate;
    TpmCryptoDevCtx tpmCtx;
    PKCS7 pkcs7;
    byte  data[] = "My encoded DER cert.";
    int tpmDevId;
    WOLFTPM2_BUFFER der;
    WOLFTPM2_BUFFER output;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));

    printf("TPM2 PKCS7 Example\n");

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

    /* Setup the wolf crypto device callback */
    tpmCtx.rsaKey = &rsaKey;
    rc = wolfTPM2_SetCryptoDevCb(&dev, wolfTPM2_CryptoDevCb, &tpmCtx, &tpmDevId);
    if (rc < 0) goto exit;

    /* See if primary storage key already exists */
    rc = wolfTPM2_ReadPublicKey(&dev, &storageKey,
        TPM2_DEMO_STORAGE_KEY_HANDLE);
    if (rc != 0) {
        /* Create primary storage key */
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
            TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);
        if (rc != 0) goto exit;
        rc = wolfTPM2_CreatePrimaryKey(&dev, &storageKey, TPM_RH_OWNER,
            &publicTemplate, (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
        if (rc != 0) goto exit;

        /* Move this key into persistent storage */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &storageKey,
            TPM2_DEMO_STORAGE_KEY_HANDLE);
        if (rc != 0) goto exit;
    }
    else {
        /* specify auth password for storage key */
        storageKey.handle.auth.size = sizeof(gStorageKeyAuth)-1;
        XMEMCPY(storageKey.handle.auth.buffer, gStorageKeyAuth,
            storageKey.handle.auth.size);
    }

    /* Create/Load RSA key for PKCS7 signing */
    rc = wolfTPM2_ReadPublicKey(&dev, &rsaKey, TPM2_DEMO_RSA_KEY_HANDLE);
    if (rc != 0) {
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
        if (rc != 0) goto exit;
        rc = wolfTPM2_CreateAndLoadKey(&dev, &rsaKey, &storageKey.handle,
            &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
        if (rc != 0) goto exit;

        /* Move this key into persistent storage */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &rsaKey,
            TPM2_DEMO_RSA_KEY_HANDLE);
        if (rc != 0) goto exit;
    }
    else {
        /* specify auth password for rsa key */
        rsaKey.handle.auth.size = sizeof(gKeyAuth)-1;
        XMEMCPY(rsaKey.handle.auth.buffer, gKeyAuth, rsaKey.handle.auth.size);
    }


    /* load DER certificate for TPM key (obtained by running
        `./examples/csr/csr` and `./certs/certreq.sh`) */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    {
        FILE* derFile = fopen("./certs/client-rsa-cert.der", "rb");
        if (derFile) {
            fseek(derFile, 0, SEEK_END);
            der.size = (int)ftell(derFile);
            rewind(derFile);
            rc = (int)fread(der.buffer, 1, der.size, derFile);
            fclose(derFile);
            if (rc != der.size) {
                rc = -1; goto exit;
            }
        }
    }
#endif

    /* Generate and verify PKCS#7 files containing data using TPM key */
    rc = wc_PKCS7_Init(&pkcs7, NULL, tpmDevId);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_InitWithCert(&pkcs7, der.buffer, der.size);
    if (rc != 0) goto exit;

    pkcs7.content = data;
    pkcs7.contentSz = (word32)sizeof(data);
    pkcs7.encryptOID = RSAk;
    pkcs7.hashOID = SHA256h;
    pkcs7.rng = wolfTPM2_GetRng(&dev);

    rc = wc_PKCS7_EncodeSignedData(&pkcs7, output.buffer, sizeof(output.buffer));
    if (rc <= 0) goto exit;
    wc_PKCS7_Free(&pkcs7);
    output.size = rc;

    printf("PKCS7 Signed Container %d\n", output.size);
    TPM2_PrintBin(output.buffer, output.size);

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    {
        FILE* pemFile = fopen("./examples/pkcs7/pkcs7tpmsigned.p7s", "wb");
        if (pemFile) {
            rc = (int)fwrite(output.buffer, 1, output.size, pemFile);
            fclose(pemFile);
            if (rc != output.size) {
                rc = -1; goto exit;
            }
        }
    }
#endif

    /* Test verify with TPM */
    rc = wc_PKCS7_Init(&pkcs7, NULL, tpmDevId);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_InitWithCert(&pkcs7, NULL, 0);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_VerifySignedData(&pkcs7, output.buffer, output.size);
    if (rc != 0) goto exit;
    wc_PKCS7_Free(&pkcs7);

    printf("PKCS7 Container Verified (using TPM)\n");

    /* Test verify with software */
    rc = wc_PKCS7_Init(&pkcs7, NULL, INVALID_DEVID);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_InitWithCert(&pkcs7, NULL, 0);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_VerifySignedData(&pkcs7, output.buffer, output.size);
    if (rc != 0) goto exit;
    wc_PKCS7_Free(&pkcs7);

    printf("PKCS7 Container Verified (using software)\n");

exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2 PKCS7 Example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER && HAVE_PKCS7 && WOLF_CRYPTO_DEV */

#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(HAVE_PKCS7) && \
     defined(WOLF_CRYPTO_DEV)
    rc = TPM2_PKCS7_Example(TPM2_IoGetUserCtx());
#else
    printf("Wrapper/PKCS7/CryptoDev code not compiled in\n");
    printf("Build wolfssl with ./configure --enable-pkcs7 --enable-cryptodev\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
