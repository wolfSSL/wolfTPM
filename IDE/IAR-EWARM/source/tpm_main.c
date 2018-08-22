/* Generic Example for using Wrappers */

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>


/* Configuration */
#define TPM2_PRIMARY_STORAGE_KEY_HANDLE     0x81000000
#define TPM2_RSA_KEY_HANDLE                 0x81000010
#define TPM2_RSA_PUBLIC_KEY_HANDLE          0x81000011
#define TPM2_NV_CERT_INDEX                  0x01800000
static const char gStorageKeyAuth[] =       "ThisIsMyStorageKeyAuth";
static const char gKeyAuth[] =              "ThisIsMyKeyAuth";



/* IO Callback */

static int TPM2_IoCb(TPM2_CTX* ctx, const BYTE* txBuf, BYTE* rxBuf, UINT16 xferSz,
    void* userCtx)
{
    int ret = TPM_RC_FAILURE;

    (void)ctx;
    (void)userCtx;

    /* TODO: Add your own SPI hardware interface call */
    //ret = XferSPI_TPM(txBuf, rxBuf, xferSz);
    if (ret == 0) {
        ret = TPM_RC_SUCCESS;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_IoCb: %d\n", xferSz);
    TPM2_PrintBin(txBuf, xferSz);
    TPM2_PrintBin(rxBuf, xferSz);
#endif

    return ret;
}

int TPM2_Cust_Example(void* userCtx)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY rsaKey;
    TPMT_PUBLIC publicTemplate;

    printf("TPM2 Example for Wrapper\n");

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

    /* See if primary storage key already exists */
    rc = wolfTPM2_ReadPublicKey(&dev, &storageKey,
        TPM2_PRIMARY_STORAGE_KEY_HANDLE);
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
            TPM2_PRIMARY_STORAGE_KEY_HANDLE);
        if (rc != 0) goto exit;
    }
    else {
        /* specify auth password for storage key */
        storageKey.handle.auth.size = sizeof(gStorageKeyAuth)-1;
        XMEMCPY(storageKey.handle.auth.buffer, gStorageKeyAuth,
            storageKey.handle.auth.size);
    }

    /* Create RSA key */
    rc = wolfTPM2_ReadPublicKey(&dev, &rsaKey, TPM2_RSA_KEY_HANDLE);
    if (rc != 0) {
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
        if (rc != 0) goto exit;
        rc = wolfTPM2_CreateAndLoadKey(&dev, &rsaKey, &storageKey.handle,
            &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
        if (rc != 0) goto exit;

        /* Store RSA PRIVATE KEY in TPM CHIP */
        /* Move this key into persistent storage */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &rsaKey,
            TPM2_RSA_KEY_HANDLE);
        if (rc != 0) goto exit;
    }
    else {
        /* specify auth password for rsa key */
        rsaKey.handle.auth.size = sizeof(gKeyAuth)-1;
        XMEMCPY(rsaKey.handle.auth.buffer, gKeyAuth, rsaKey.handle.auth.size);
    }


exit:

    if (rc != 0) {
        printf("Failure %d (0x%x): %s\n", rc, rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &storageKey.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}
