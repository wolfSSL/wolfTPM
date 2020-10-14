#include "tpm_test.h"
#include "tpm_test_keys.h"
#include <wolftpm/tpm2_wrap.h>

#define RSA_PUB_FILENAME  "rsa_example_pub.raw"
#define RSA_PRIV_FILENAME "rsa_example_priv.raw"
#define ECC_PUB_FILENAME  "ecc_example_pub.raw"
#define ECC_PRIV_FILENAME "ecc_example_priv.raw"

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
static inline int writeKeyPair(const char* pub_name,
                               const char* priv_name,
                               const TPM2B_PUBLIC* pub,
                               const TPM2B_PRIVATE* priv) {
    int rc;
    FILE*  fp = NULL;

    fp = fopen(pub_name, "wb");
    if (fp) {
        rc = (int)fwrite(&pub->publicArea, 1, sizeof(TPMT_PUBLIC), fp);
        fclose(fp);
        if (rc != sizeof(TPMT_PUBLIC)) {
            perror("Writing public key");
            return -1;
        }
    }

    fp = fopen(priv_name, "wb");
    if (fp) {
        rc = (int)fwrite(priv->buffer, 1, priv->size, fp);
        fclose(fp);
        if (rc != priv->size) {
            perror("Writing private key");
            return -1;
        }
    }

    return rc;
}

static inline int readRawKey(const char* filename,
                             byte* buffer,
                             UINT16* size)
{
    FILE*  file = NULL;
    int ret;

    file = fopen(filename, "rb");
    if (file == NULL)
        return WOLFSSL_BAD_FILE;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return WOLFSSL_BAD_FILE;
    }

    *size = ftell(file);
    rewind(file);

    if ( (ret = (int)fread(buffer, 1, *size, file)) != *size) {
        return WOLFSSL_BAD_FILE;
    }

    return 0;
}

static inline int readKeyPair(const char* pub_name,
             const char* priv_name,
             TPM2B_PUBLIC* pub,
             TPM2B_PRIVATE* priv) {
    int rc = 0;
    if (rc == 0) rc = readRawKey(pub_name, (byte*)&pub->publicArea, &pub->size);
    if (rc == 0) rc = readRawKey(priv_name, priv->buffer, &priv->size);
    return rc;
}

#endif /* !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) */

static inline int test_TryReadKey(WOLFTPM2_DEV* pDev,
                                  WOLFTPM2_KEY* key,
                                  WOLFTPM2_HANDLE* parent,
                                  const char* pub_name,
                                  const char* priv_name,
                                  const byte* auth,
                                  int authSz)
{
    int rc;
    Load_In  loadIn;
    Load_Out loadOut;

    pDev->session[0].auth = parent->auth;

    /* clear output key buffer */
    XMEMSET(key, 0, sizeof(WOLFTPM2_KEY));
    XMEMSET(&loadIn, 0, sizeof(loadIn));

    loadIn.parentHandle = parent->hndl;

    rc = readKeyPair(pub_name, priv_name, &loadIn.inPublic, &loadIn.inPrivate);
    if (rc != 0) return rc;

    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Load key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        XMEMSET(&pDev->session[0].auth, 0, sizeof(pDev->session[0].auth));
        return rc;
    }
    key->handle.dev  = pDev;
    key->handle.hndl = loadOut.objectHandle;

    key->pub = loadIn.inPublic;

    #ifdef DEBUG_WOLFTPM
    printf("test_TryReadKey Handle 0x%x\n", (word32)key->handle.hndl);
    #endif

    if (auth) {
        key->handle.auth.size = authSz;
        XMEMCPY(key->handle.auth.buffer, auth, authSz);
    } else {
        XMEMSET(&key->handle.auth, 0, sizeof(TPM2B_AUTH));
    }

    /* clear auth */
    XMEMSET(&pDev->session[0].auth, 0, sizeof(pDev->session[0].auth));

    return rc;
}

static inline int test_CreateAndLoadKey(WOLFTPM2_DEV* dev,
                                        WOLFTPM2_KEY* key,
                                        WOLFTPM2_HANDLE* parent,
                                        TPMT_PUBLIC* publicTemplate,
                                        const byte* auth, int authSz,
                                        const char* pub_filename,
                                        const char* priv_filename)
{
    int rc;
    Create_In  createIn;
    Create_Out createOut;
    Load_In  loadIn;
    Load_Out loadOut;

    if (dev == NULL || key == NULL || parent == NULL || publicTemplate == NULL)
        return BAD_FUNC_ARG;

    /* clear output key buffer */
    XMEMSET(key, 0, sizeof(WOLFTPM2_KEY));

    /* set session auth for key */
    dev->session[0].auth = parent->auth;

    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent->hndl;
    if (auth) {
        createIn.inSensitive.sensitive.userAuth.size = authSz;
        XMEMCPY(createIn.inSensitive.sensitive.userAuth.buffer, auth,
            createIn.inSensitive.sensitive.userAuth.size);
    }
    XMEMCPY(&createIn.inPublic.publicArea, publicTemplate, sizeof(TPMT_PUBLIC));

#if 0
    /* Optional creation nonce */
    createIn.outsideInfo.size = createNoneSz;
    XMEMCPY(createIn.outsideInfo.buffer, createNonce, createIn.outsideInfo.size);
#endif

    rc = TPM2_Create(&createIn, &createOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Create key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        XMEMSET(&dev->session[0].auth, 0, sizeof(dev->session[0].auth));
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Create key: pub %d, priv %d\n", createOut.outPublic.size,
           createOut.outPrivate.size);
    printf("save\n");
    TPM2_PrintBin((byte*)&createOut.outPublic.publicArea, createOut.outPublic.size);
    TPM2_PrintBin(createOut.outPrivate.buffer, createOut.outPrivate.size);
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    writeKeyPair(pub_filename, priv_filename, &createOut.outPublic, &createOut.outPrivate);
#endif
    key->pub = createOut.outPublic;

    /* Load new key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent->hndl;
    loadIn.inPrivate = createOut.outPrivate;
    loadIn.inPublic = key->pub;
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Load key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        XMEMSET(&dev->session[0].auth, 0, sizeof(dev->session[0].auth));
        return rc;
    }
    key->handle.dev  = dev;
    key->handle.hndl = loadOut.objectHandle;
    key->handle.auth = createIn.inSensitive.sensitive.userAuth;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Load Key Handle 0x%x\n", (word32)key->handle.hndl);
#endif

    /* clear auth */
    XMEMSET(&dev->session[0].auth, 0, sizeof(dev->session[0].auth));

    return rc;
}

int getPrimaryStoragekey(WOLFTPM2_DEV* pDev,
                         WOLFTPM2_KEY* pStorageKey,
                         TPMT_PUBLIC* pPublicTemplate,
                         int tryNV)
{
    int rc = 0;

    /* See if primary storage key already exists */
    if (tryNV) {
        rc = wolfTPM2_ReadPublicKey(pDev, pStorageKey,
                                    TPM2_DEMO_STORAGE_KEY_HANDLE);
    }

    if (!tryNV || rc != 0) {
        /* Create primary storage key */
        rc = wolfTPM2_GetKeyTemplate_RSA(pPublicTemplate,
            TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);
        if (rc != 0) return rc;
        rc = wolfTPM2_CreatePrimaryKey(pDev, pStorageKey, TPM_RH_OWNER,
            pPublicTemplate, (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
        if (rc != 0) return rc;

        /* Move this key into persistent storage */
        if (tryNV) {
            rc = wolfTPM2_NVStoreKey(pDev, TPM_RH_OWNER, pStorageKey,
                                     TPM2_DEMO_STORAGE_KEY_HANDLE);
            if (rc != 0) {
                printf("store failed\n");
                return rc;
            }
        }
    }
    else {
        /* specify auth password for storage key */
        pStorageKey->handle.auth.size = sizeof(gStorageKeyAuth)-1;
        XMEMCPY(pStorageKey->handle.auth.buffer, gStorageKeyAuth,
                pStorageKey->handle.auth.size);
    }

    return rc;
}

#ifndef NO_RSA
int getRSAPrimaryStoragekey(WOLFTPM2_DEV* pDev,
                            WOLFTPM2_KEY* pStorageKey,
                            TPMT_PUBLIC*  pPublicTemplate,
                            WOLFTPM2_KEY* pRsaKey,
                            RsaKey* pWolfRsaKey,
                            int tpmDevId,
                            int tryNV)
{
    int rc = 0;
    int generate_key = 0;

    /* Create/Load RSA key */
    if (tryNV) {
        rc = wolfTPM2_ReadPublicKey(pDev, pRsaKey, TPM2_DEMO_RSA_KEY_HANDLE);
        if (rc == TPM_RC_SUCCESS) {
            /* specify auth password for RSA key */
            pRsaKey->handle.auth.size = sizeof(gKeyAuth)-1;
            XMEMCPY(pRsaKey->handle.auth.buffer, gKeyAuth, pRsaKey->handle.auth.size);
        }
        else {
            generate_key = 1;
        }
      } else {
        rc = test_TryReadKey(pDev, pRsaKey, &pStorageKey->handle,
                             RSA_PUB_FILENAME, RSA_PRIV_FILENAME,
                             (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
        if (rc == WOLFSSL_BAD_FILE) {
            generate_key = 1;
        }
        else {
            return rc;
        }
    }

    if (generate_key) {
        rc = wolfTPM2_GetKeyTemplate_RSA(pPublicTemplate,
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
        if (rc != 0) return rc;

        rc = test_CreateAndLoadKey(pDev, pRsaKey, &pStorageKey->handle,
                                   pPublicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1,
                                   RSA_PUB_FILENAME, RSA_PRIV_FILENAME);
        if (rc != 0) return rc;

        /* Move this key into persistent storage */
        if (tryNV) {
            rc = wolfTPM2_NVStoreKey(pDev, TPM_RH_OWNER, pRsaKey,
                                     TPM2_DEMO_RSA_KEY_HANDLE);
            if (rc != 0) return rc;
        }
    }

    /* setup wolf RSA key with TPM deviceID, so crypto callbacks are used */
    rc = wc_InitRsaKey_ex(pWolfRsaKey, NULL, tpmDevId);
    if (rc != 0) return rc;

    /* load public portion of key into wolf RSA Key */
    rc = wolfTPM2_RsaKey_TpmToWolf(pDev, pRsaKey, pWolfRsaKey);

    return rc;
}
#endif /* !NO_RSA */


#ifdef HAVE_ECC
int getECCkey(WOLFTPM2_DEV* pDev,
              WOLFTPM2_KEY* pStorageKey,
              TPMT_PUBLIC*  pPublicTemplate,
              WOLFTPM2_KEY* pEccKey,
              ecc_key* pWolfEccKey,
              int tpmDevId,
              int tryNV)
{
    int rc = 0;
    int generate_key = 0;

    /* Create/Load ECC key */
    if (tryNV) {
        rc = wolfTPM2_ReadPublicKey(pDev, pEccKey, TPM2_DEMO_ECC_KEY_HANDLE);
        if (rc == TPM_RC_SUCCESS) {
            /* specify auth password for ECC key */
            pEccKey->handle.auth.size = sizeof(gKeyAuth)-1;
            XMEMCPY(pEccKey->handle.auth.buffer, gKeyAuth, pEccKey->handle.auth.size);
        }
        else {
            generate_key = 1;
        }
    }
    else {
        rc = test_TryReadKey(pDev, pEccKey, &pStorageKey->handle,
                             ECC_PUB_FILENAME, ECC_PRIV_FILENAME,
                             (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
        if (rc == WOLFSSL_BAD_FILE) {
            generate_key = 1;
        }
        else {
            return rc;
        }
    }

    if (generate_key) {
        rc = wolfTPM2_GetKeyTemplate_ECC(pPublicTemplate,
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
            TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
        if (rc != 0) return rc;

        rc = test_CreateAndLoadKey(pDev, pEccKey, &pStorageKey->handle,
                                   pPublicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1,
                                   ECC_PUB_FILENAME, ECC_PRIV_FILENAME);
        if (rc != 0) return rc;

        /* Move this key into persistent storage */
        if (tryNV) {
            rc = wolfTPM2_NVStoreKey(pDev, TPM_RH_OWNER, pEccKey,
                                     TPM2_DEMO_ECC_KEY_HANDLE);
            if (rc != 0) return rc;
        }
    }

    /* setup wolf ECC key with TPM deviceID, so crypto callbacks are used */
    rc = wc_ecc_init_ex(pWolfEccKey, NULL, tpmDevId);
    if (rc != 0) return rc;
    /* load public portion of key into wolf ECC Key */
    rc = wolfTPM2_EccKey_TpmToWolf(pDev, pEccKey, pWolfEccKey);

    return rc;
}
#endif /* HAVE_ECC */
