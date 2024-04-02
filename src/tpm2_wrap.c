/* tpm2_wrap.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_param_enc.h>

#ifndef WOLFTPM2_NO_WRAPPER

/* For some struct to buffer conversions */
#include <wolftpm/tpm2_packet.h>


/* Local Functions */
static int wolfTPM2_GetCapabilities_NoDev(WOLFTPM2_CAPS* cap);
static void wolfTPM2_CopySymmetric(TPMT_SYM_DEF* out, const TPMT_SYM_DEF* in);
static void wolfTPM2_CopyName(TPM2B_NAME* out, const TPM2B_NAME* in);
static void wolfTPM2_CopyAuth(TPM2B_AUTH* out, const TPM2B_AUTH* in);
static void wolfTPM2_CopyPubT(TPMT_PUBLIC* out, const TPMT_PUBLIC* in);
static void wolfTPM2_CopyPub(TPM2B_PUBLIC* out, const TPM2B_PUBLIC* in);
static void wolfTPM2_CopyPriv(TPM2B_PRIVATE* out, const TPM2B_PRIVATE* in);
static void wolfTPM2_CopyEccParam(TPM2B_ECC_PARAMETER* out, const TPM2B_ECC_PARAMETER* in);
static void wolfTPM2_CopyKeyFromBlob(WOLFTPM2_KEY* key, const WOLFTPM2_KEYBLOB* keyBlob);
static void wolfTPM2_CopyNvPublic(TPMS_NV_PUBLIC* out, const TPMS_NV_PUBLIC* in);

/******************************************************************************/
/* --- BEGIN Wrapper Device Functions -- */
/******************************************************************************/

static int wolfTPM2_Init_ex(TPM2_CTX* ctx, TPM2HalIoCb ioCb, void* userCtx,
    int timeoutTries)
{
    int rc;

#if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_WINAPI)
    Startup_In startupIn;
#if defined(WOLFTPM_MICROCHIP) || defined(WOLFTPM_PERFORM_SELFTEST)
    SelfTest_In selfTest;
#endif
#endif /* ! WOLFTPM_LINUX_DEV */

    if (ctx == NULL)
        return BAD_FUNC_ARG;

#if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || \
    defined(WOLFTPM_WINAPI)
    rc = TPM2_Init_minimal(ctx);
    /* Using standard file I/O for the Linux TPM device */
    (void)ioCb;
    (void)userCtx;
    (void)timeoutTries;
#else
    rc = TPM2_Init_ex(ctx, ioCb, userCtx, timeoutTries);
#endif
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Init failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
#ifdef DEBUG_WOLFTPM
    printf("TPM2: Caps 0x%08x, Did 0x%04x, Vid 0x%04x, Rid 0x%2x \n",
        ctx->caps,
        ctx->did_vid >> 16,
        ctx->did_vid & 0xFFFF,
        ctx->rid);
#endif

#if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_WINAPI)
    /* startup */
    XMEMSET(&startupIn, 0, sizeof(Startup_In));
    startupIn.startupType = TPM_SU_CLEAR;
    rc = TPM2_Startup(&startupIn);
    if (rc != TPM_RC_SUCCESS &&
        rc != TPM_RC_INITIALIZE /* TPM_RC_INITIALIZE = Already started */ ) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Startup failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
#ifdef DEBUG_WOLFTPM
    printf("TPM2_Startup pass\n");
#endif

#if defined(WOLFTPM_MICROCHIP) || defined(WOLFTPM_PERFORM_SELFTEST)
    /* Do full self-test (Chips such as ATTPM20 require this before some operations) */
    XMEMSET(&selfTest, 0, sizeof(selfTest));
    selfTest.fullTest = YES;
    rc = TPM2_SelfTest(&selfTest);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_SelfTest failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    #endif
        return rc;
    }
#ifdef DEBUG_WOLFTPM
    printf("TPM2_SelfTest pass\n");
#endif
#else
    rc = TPM_RC_SUCCESS;
#endif /* WOLFTPM_MICROCHIP || WOLFTPM_PERFORM_SELFTEST */
#endif /* !WOLFTPM_LINUX_DEV && !WOLFTPM_WINAPI */

    return rc;
}

/* Single-shot API for testing access to hardware and optionally return capabilities */
int wolfTPM2_Test(TPM2HalIoCb ioCb, void* userCtx, WOLFTPM2_CAPS* caps)
{
    int rc;
    TPM2_CTX* current_ctx;
    TPM2_CTX ctx;

    /* Backup active TPM context */
    current_ctx = TPM2_GetActiveCtx();

    /* Perform startup and test device */
    rc = wolfTPM2_Init_ex(&ctx, ioCb, userCtx, TPM_STARTUP_TEST_TRIES);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    /* Optionally get and return capabilities */
    if (caps) {
        rc = wolfTPM2_GetCapabilities_NoDev(caps);
    }

    /* Perform cleanup */
    TPM2_Cleanup(&ctx);

    /* Restore original context */
    TPM2_SetActiveCtx(current_ctx);

    return rc;
}

int wolfTPM2_Init(WOLFTPM2_DEV* dev, TPM2HalIoCb ioCb, void* userCtx)
{
    int rc;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(dev, 0, sizeof(WOLFTPM2_DEV));

    rc = wolfTPM2_Init_ex(&dev->ctx, ioCb, userCtx, TPM_TIMEOUT_TRIES);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    /* define the default session auth */
    XMEMSET(dev->session, 0, sizeof(dev->session));
    wolfTPM2_SetAuthPassword(dev, 0, NULL);

    return rc;
}

#ifndef WOLFTPM2_NO_HEAP
WOLFTPM2_DEV* wolfTPM2_New(void)
{
    WOLFTPM2_DEV *dev = (WOLFTPM2_DEV*)XMALLOC(
        sizeof(WOLFTPM2_DEV), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (dev != NULL) {
        if (wolfTPM2_Init(dev, NULL, NULL) != TPM_RC_SUCCESS) {
            XFREE(dev, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            dev = NULL;
        }
    }
    return dev;
}
int wolfTPM2_Free(WOLFTPM2_DEV *dev)
{
    if (dev != NULL) {
        wolfTPM2_Cleanup(dev);
        XFREE(dev, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return TPM_RC_SUCCESS;
}

WOLFTPM2_KEYBLOB* wolfTPM2_NewKeyBlob(void)
{
    WOLFTPM2_KEYBLOB* blob = (WOLFTPM2_KEYBLOB*)XMALLOC(
        sizeof(WOLFTPM2_KEYBLOB), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (blob != NULL) {
        XMEMSET(blob, 0, sizeof(WOLFTPM2_KEYBLOB));
    }
    return blob;
}
int wolfTPM2_FreeKeyBlob(WOLFTPM2_KEYBLOB* blob)
{
    if (blob != NULL) {
        XFREE(blob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return TPM_RC_SUCCESS;
}

TPMT_PUBLIC* wolfTPM2_NewPublicTemplate(void)
{
    TPMT_PUBLIC* PublicTemplate = (TPMT_PUBLIC*)XMALLOC(
        sizeof(TPMT_PUBLIC), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (PublicTemplate != NULL) {
        XMEMSET(PublicTemplate, 0, sizeof(TPMT_PUBLIC));
    }
    return PublicTemplate;
}
int wolfTPM2_FreePublicTemplate(TPMT_PUBLIC* PublicTemplate)
{
    if (PublicTemplate != NULL) {
        XFREE(PublicTemplate, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return TPM_RC_SUCCESS;
}

WOLFTPM2_KEY* wolfTPM2_NewKey(void)
{
    WOLFTPM2_KEY* key = (WOLFTPM2_KEY*)XMALLOC(
        sizeof(WOLFTPM2_KEY), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (key != NULL) {
        XMEMSET(key, 0, sizeof(WOLFTPM2_KEY));
    }
    return key;
}
int wolfTPM2_FreeKey(WOLFTPM2_KEY* key)
{
    if (key != NULL) {
        XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return TPM_RC_SUCCESS;
}

WOLFTPM2_SESSION* wolfTPM2_NewSession(void)
{
    WOLFTPM2_SESSION* session = (WOLFTPM2_SESSION*)XMALLOC(
        sizeof(WOLFTPM2_SESSION), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (session != NULL) {
        XMEMSET(session, 0, sizeof(WOLFTPM2_SESSION));
    }
    return session;
}
int wolfTPM2_FreeSession(WOLFTPM2_SESSION* session)
{
    if (session != NULL) {
        XFREE(session, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return TPM_RC_SUCCESS;
}

#ifdef WOLFTPM2_CERT_GEN
WOLFTPM2_CSR* wolfTPM2_NewCSR(void)
{
    WOLFTPM2_CSR* csr = (WOLFTPM2_CSR*)XMALLOC(
        sizeof(WOLFTPM2_CSR), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (csr != NULL) {
        XMEMSET(csr, 0, sizeof(WOLFTPM2_CSR));
        if (wc_InitCert(&csr->req) != 0) {
            XFREE(csr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            csr = NULL;
        }
    }
    return csr;
}
int wolfTPM2_FreeCSR(WOLFTPM2_CSR* csr)
{
    if (csr != NULL) {
        XFREE(csr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return TPM_RC_SUCCESS;
}
#endif /* WOLFTPM2_CERT_GEN */

#endif /* !WOLFTPM2_NO_HEAP */

WOLFTPM2_HANDLE* wolfTPM2_GetHandleRefFromKey(WOLFTPM2_KEY* key)
{
    return (key != NULL) ? &key->handle : NULL;
}
WOLFTPM2_HANDLE* wolfTPM2_GetHandleRefFromKeyBlob(WOLFTPM2_KEYBLOB* keyBlob)
{
    return (keyBlob != NULL) ? &keyBlob->handle : NULL;
}

WOLFTPM2_HANDLE* wolfTPM2_GetHandleRefFromSession(WOLFTPM2_SESSION* session)
{
    return (session != NULL) ? &session->handle : NULL;
}

TPM_HANDLE wolfTPM2_GetHandleValue(WOLFTPM2_HANDLE* handle)
{
    TPM_HANDLE hndl = 0;
    if (handle)
        hndl = handle->hndl;
    return hndl;
}

int wolfTPM2_GetKeyBlobAsBuffer(byte *buffer, word32 bufferSz,
    WOLFTPM2_KEYBLOB* key)
{
    int rc = 0;
    int sz = 0;
    byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];
    int pubAreaSize;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    /* publicArea is encoded format. Eliminates empty fields, saves space. */
    rc = TPM2_AppendPublic(pubAreaBuffer, (word32)sizeof(pubAreaBuffer),
        &pubAreaSize, &key->pub);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    if (pubAreaSize != (key->pub.size + (int)sizeof(key->pub.size))) {
#ifdef DEBUG_WOLFTPM
        printf("Sanity check for publicArea size failed\n");
#endif
        return BUFFER_E;
    }

    /* calculate actual size */
    sz = sizeof(key->pub.size) + sizeof(UINT16) + key->pub.size +
        sizeof(UINT16) + key->priv.size;

    /* return size only */
    if (buffer == NULL) {
        return sz;

    }
    if ((int)bufferSz < sz) {
        return BUFFER_E;
    }

    /* Write size marker for the public part */
    XMEMCPY(buffer, &key->pub.size, sizeof(key->pub.size));
    sz = sizeof(key->pub.size);

    /* Write the public part with bytes aligned */
    XMEMCPY(buffer + sz, pubAreaBuffer, sizeof(UINT16) + key->pub.size);
    sz += sizeof(UINT16) + key->pub.size;

    /* Write the private part, size marker is included */
    XMEMCPY(buffer + sz, &key->priv, sizeof(UINT16) + key->priv.size);
    sz += sizeof(UINT16) + key->priv.size;

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Get KeyBlob: %d bytes\n", (int)sz);
    TPM2_PrintBin(buffer, sz);
#endif

    return sz;
}

int wolfTPM2_GetKeyBlobAsSeparateBuffers(byte* pubBuffer, word32* pubBufferSz,
    byte* privBuffer, word32* privBufferSz, WOLFTPM2_KEYBLOB* key)
{
    int rc = 0;
    byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];
    int pubAreaSize;

    if (key == NULL || pubBufferSz == NULL || privBufferSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* publicArea is encoded format. Eliminates empty fields, saves space. */
    rc = TPM2_AppendPublic(pubAreaBuffer, (word32)sizeof(pubAreaBuffer),
        &pubAreaSize, &key->pub);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    if (pubAreaSize != (key->pub.size + (int)sizeof(key->pub.size))) {
#ifdef DEBUG_WOLFTPM
        printf("Sanity check for publicArea size failed\n");
#endif
        return BUFFER_E;
    }

    if (pubBuffer == NULL || privBuffer == NULL) {
        *privBufferSz = sizeof(UINT16) + key->priv.size;
        *pubBufferSz = sizeof(key->pub.size) + sizeof(UINT16) + key->pub.size;
        return LENGTH_ONLY_E;
    }

    if (*pubBufferSz < sizeof(key->pub.size) + sizeof(UINT16) + key->pub.size ||
        *privBufferSz < sizeof(UINT16) + key->priv.size) {
        return BUFFER_E;
    }

    *pubBufferSz = 0;
    *privBufferSz = 0;

    /* Write size marker for the public part */
    XMEMCPY(pubBuffer, &key->pub.size, sizeof(key->pub.size));
    *pubBufferSz += sizeof(key->pub.size);

    /* Write the public part with bytes aligned */
    XMEMCPY(pubBuffer + *pubBufferSz, pubAreaBuffer, sizeof(UINT16) +
        key->pub.size);
    *pubBufferSz += sizeof(UINT16) + key->pub.size;

    /* Write the private part, size marker is included */
    XMEMCPY(privBuffer, &key->priv, sizeof(UINT16) + key->priv.size);
    *privBufferSz += sizeof(UINT16) + key->priv.size;

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Get KeyBlob public: %d bytes\n", (int)*pubBufferSz);
    TPM2_PrintBin(pubBuffer, *pubBufferSz);

    printf("Get KeyBlob private: %d bytes\n", (int)*privBufferSz);
    TPM2_PrintBin(privBuffer, *privBufferSz);
#endif

    return TPM_RC_SUCCESS;
}

int wolfTPM2_SetKeyBlobFromBuffer(WOLFTPM2_KEYBLOB* key, byte *buffer,
                                  word32 bufferSz)
{
    int rc = 0;
    byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];
    int pubAreaSize;
    byte *runner = buffer;
    size_t done_reading = 0;

    if ((key == NULL) || (buffer == NULL) || (bufferSz <= 0)) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(key, 0, sizeof(WOLFTPM2_KEYBLOB));

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Set KeyBlob: %d bytes\n", (int)bufferSz);
    TPM2_PrintBin(buffer, bufferSz);
#endif

    if (bufferSz < done_reading + sizeof(key->pub.size)) {
#ifdef DEBUG_WOLFTPM
        printf("Buffer size check failed (%d)\n", bufferSz);
#endif
        return BUFFER_E;
    }

    XMEMCPY(&key->pub.size, runner, sizeof(key->pub.size));
    runner += sizeof(key->pub.size);
    done_reading += sizeof(key->pub.size);

    if (bufferSz < done_reading + sizeof(UINT16) + key->pub.size) {
#ifdef DEBUG_WOLFTPM
        printf("Buffer size check failed (%d)\n", bufferSz);
#endif
        return BUFFER_E;
    }

    XMEMCPY(pubAreaBuffer, runner, sizeof(UINT16) + key->pub.size);
    runner += sizeof(UINT16) + key->pub.size;
    done_reading += sizeof(UINT16) + key->pub.size;

    /* Decode the byte stream into a publicArea structure ready for use */
    rc = TPM2_ParsePublic(&key->pub, pubAreaBuffer,
        (word32)sizeof(pubAreaBuffer), &pubAreaSize);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    if (bufferSz < done_reading + sizeof(key->priv.size)) {
#ifdef DEBUG_WOLFTPM
        printf("Buffer size check failed (%d)\n", bufferSz);
#endif
        return BUFFER_E;
    }

    XMEMCPY(&key->priv.size, runner, sizeof(key->priv.size));
    runner += sizeof(key->priv.size);
    done_reading += sizeof(key->priv.size);

    if (bufferSz < done_reading + key->priv.size) {
#ifdef DEBUG_WOLFTPM
        printf("Buffer size check failed (%d)\n", bufferSz);
#endif
        return BUFFER_E;
    }

    XMEMCPY(key->priv.buffer, runner, key->priv.size);
    done_reading += key->priv.size;

    if (done_reading != bufferSz) {
#ifdef DEBUG_WOLFTPM
        printf("Extra data left in buffer (%d!=%d)\n",
            bufferSz, (word32)done_reading);
#endif
        return BUFFER_E;
    }

    return TPM_RC_SUCCESS;
}

int wolfTPM2_SetKeyAuthPassword(WOLFTPM2_KEY *key, const byte* auth,
                               int authSz)
{
    if ((key == NULL) || (authSz < 0)) {
        return BAD_FUNC_ARG;
    }

    if ( ((auth != NULL) && (authSz == 0))
         || ((auth == NULL) && (authSz != 0))
        ) {
        return BAD_FUNC_ARG;
    }

    /* specify auth password for storage key */
    key->handle.auth.size = authSz;
    if (auth != NULL) {
        XMEMCPY(key->handle.auth.buffer, auth, authSz);
    }

    return TPM_RC_SUCCESS;
}

/* Access already started TPM module */
int wolfTPM2_OpenExisting(WOLFTPM2_DEV* dev, TPM2HalIoCb ioCb, void* userCtx)
{
    int rc;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(dev, 0, sizeof(WOLFTPM2_DEV));

    /* The 0 startup indicates use existing locality */
    rc = wolfTPM2_Init_ex(&dev->ctx, ioCb, userCtx, 0);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Init failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* define the default session auth */
    XMEMSET(dev->session, 0, sizeof(dev->session));
    wolfTPM2_SetAuthPassword(dev, 0, NULL);

    return rc;
}

int wolfTPM2_GetTpmDevId(WOLFTPM2_DEV* dev)
{
    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    return (int)dev->ctx.did_vid; /* return something besides INVALID_DEVID */
}

int wolfTPM2_SelfTest(WOLFTPM2_DEV* dev)
{
    int rc;
    SelfTest_In selfTest;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    /* Full self test */
    XMEMSET(&selfTest, 0, sizeof(selfTest));
    selfTest.fullTest = YES;
    rc = TPM2_SelfTest(&selfTest);
#ifdef WOLFTPM_WINAPI
    if (rc == (int)TPM_E_COMMAND_BLOCKED) { /* 0x80280400 */
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_SelfTest not allowed on Windows TBS (err 0x%x)\n", rc);
    #endif
        rc = TPM_RC_SUCCESS; /* report success */
    }
#endif
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_SelfTest failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    #endif
        return rc;
    }
#ifdef DEBUG_WOLFTPM
    printf("TPM2_SelfTest pass\n");
#endif

    return rc;
}

/* Infineon SLB9670
 *  TPM_PT_MANUFACTURER     "IFX"
 *  TPM_PT_VENDOR_STRING_1  "SLB9"
 *  TPM_PT_VENDOR_STRING_2  "670 "
 *  TPM_PT_FIRMWARE_VERSION_1 0x00070055 = v7.85
 *  TPM_PT_FIRMWARE_VERSION_2 0x0011CB02
 *      Byte  1: reserved.
 *      Bytes 2-3: build num = 11CB,
 *      Byte  4: 0x00 (TPM CC), 0x02 (no CC)
 *  TPM_PT_MODES = Bit 0 = FIPS_140_2
 */

#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
    /* Infineon SLB9672 or SLB9673 Firmware Upgrade support */
    #define TPM_PT_VENDOR_FIX 0x80000000
    #define TPM_PT_VENDOR_FIX_FU_COUNTER        (TPM_PT_VENDOR_FIX + 3)
    #define TPM_PT_VENDOR_FIX_FU_COUNTER_SAME   (TPM_PT_VENDOR_FIX + 4)
    #define TPM_PT_VENDOR_FIX_FU_OPERATION_MODE (TPM_PT_VENDOR_FIX + 7)
    #define TPM_PT_VENDOR_FIX_FU_KEYGROUP_ID    (TPM_PT_VENDOR_FIX + 8)
#endif

/* ST33TP
 *  TPM_PT_MANUFACTURER 0x53544D20: "STM"
 *  TPM_PT_FIRMWARE_VERSION_1 TPM FW version: 0x00006400
 *  TPM_PT_VENDOR_TPM_TYPE 1: TPM 2.0
 *  TPM_PT_MODES: BIT 0 SET (1): indicates that the TPM is designed to
 *      comply with all of the FIPS 140-2 requirements at Level 1 or higher.
 *   TPM_PT_FIRMWARE_VERSION_2: ST Internal Additional Version
 */
static int wolfTPM2_ParseCapabilities(WOLFTPM2_CAPS* caps,
    TPML_TAGGED_TPM_PROPERTY* props)
{
    int rc = 0;
    word32 i, val, len;

    for (i=0; i<props->count && i<MAX_TPM_PROPERTIES; i++) {
        val = props->tpmProperty[i].value;
        switch (props->tpmProperty[i].property) {
            case TPM_PT_MANUFACTURER:
                val = TPM2_Packet_SwapU32(val); /* swap for little endian */
                XMEMCPY(&caps->mfgStr, &val, sizeof(UINT32));
                if (XMEMCMP(&caps->mfgStr, "IFX", 3) == 0) {
                    caps->mfg = TPM_MFG_INFINEON;
                }
                else if (XMEMCMP(&caps->mfgStr, "STM", 3) == 0) {
                    caps->mfg = TPM_MFG_STM;
                    caps->req_wait_state = 1;
                }
                else if (XMEMCMP(&caps->mfgStr, "MCHP", 4) == 0) {
                    caps->mfg = TPM_MFG_MCHP;
                    caps->req_wait_state = 1;
                }
                else if (XMEMCMP(&caps->mfgStr, "NTC", 4) == 0) {
                    caps->mfg = TPM_MFG_NUVOTON;
                    caps->req_wait_state = 1;
                }
                else if (XMEMCMP(&caps->mfgStr, "NTZ", 4) == 0) {
                    caps->mfg = TPM_MFG_NATIONTECH;
                    caps->req_wait_state = 1;
                }
                break;
            case TPM_PT_VENDOR_STRING_1:
            case TPM_PT_VENDOR_STRING_2:
            case TPM_PT_VENDOR_STRING_3:
            case TPM_PT_VENDOR_STRING_4:
                val = TPM2_Packet_SwapU32(val); /* swap for little endian */
                len = (word32)XSTRLEN(caps->vendorStr); /* add to existing string */
                if (len + sizeof(UINT32) < sizeof(caps->vendorStr)) {
                    XMEMCPY(&caps->vendorStr[len], &val, sizeof(UINT32));
                }
                if (val == 0x46495053) { /* FIPS */
                    caps->fips140_2 = 1;
                }
                break;
            case TPM_PT_VENDOR_TPM_TYPE:
                caps->tpmType = val;
                break;
            case TPM_PT_FIRMWARE_VERSION_1:
                caps->fwVerMajor = val >> 16;
                caps->fwVerMinor = val & 0xFFFF;
                break;
            case TPM_PT_FIRMWARE_VERSION_2:
                if (caps->mfg == TPM_MFG_INFINEON) {
                    caps->fwVerVendor = val >> 8;
                    caps->cc_eal4 = (val & 0x00000002) ? 0 : 1;
                }
                else {
                    caps->fwVerVendor = val;
                }
                break;
            case TPM_PT_MODES:
                caps->fips140_2 = (val & 0x00000001) ? 1: 0;
                break;
            default:
                break;
        }
    }
    return rc;
}

#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
static int tpm2_ifx_cap_vendor_get(WOLFTPM2_CAPS* cap, uint32_t property,
    uint8_t* val, size_t valSz)
{
    int rc;
    GetCapability_In  in;
    GetCapability_Out out;

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = TPM_CAP_VENDOR_PROPERTY;
    in.property = property;
    in.propertyCount = 1;
    rc = TPM2_GetCapability(&in, &out);
    if (rc == TPM_RC_SUCCESS) {
        TPM2B_MAX_BUFFER* buf = &out.capabilityData.data.vendor;
        /* 4 bytes=count + 2 bytes=len + vendor value */
        if (buf->buffer[3] == 1 && buf->buffer[5] == valSz) {
            XMEMCPY(val, &buf->buffer[6], valSz);
            if (valSz == 2) {
                *((uint16_t*)val) = be16_to_cpu(*((uint16_t*)val));
            }
            else if (valSz == 4) {
                *((uint32_t*)val) = be32_to_cpu(*((uint32_t*)val));
            }
        }
    }
    else {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_GetCapability vendor prop 0x%x failed 0x%x: %s\n",
            property, rc, TPM2_GetRCString(rc));
    #endif
    }
    (void)cap;
    return rc;
}
#endif

static int wolfTPM2_GetCapabilities_NoDev(WOLFTPM2_CAPS* cap)
{
    int rc;
    GetCapability_In  in;
    GetCapability_Out out;

    if (cap == NULL)
        return BAD_FUNC_ARG;

    /* clear caps */
    XMEMSET(cap, 0, sizeof(WOLFTPM2_CAPS));

    /* Get Capabilities TPM_PT_MANUFACTURER thru TPM_PT_FIRMWARE_VERSION_2 */
    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = TPM_CAP_TPM_PROPERTIES;
    in.property = TPM_PT_MANUFACTURER;
    in.propertyCount = 8;
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_GetCapability manufacture failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    #endif
        return rc;
    }
    rc = wolfTPM2_ParseCapabilities(cap, &out.capabilityData.data.tpmProperties);
    if (rc != 0)
        return rc;

    /* Get Capability TPM_PT_MODES */
    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = TPM_CAP_TPM_PROPERTIES;
    in.property = TPM_PT_MODES;
    in.propertyCount = 1;
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_GetCapability modes failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    #endif
        return rc;
    }
    rc = wolfTPM2_ParseCapabilities(cap, &out.capabilityData.data.tpmProperties);

#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
    /* Get vendor specific information */
    if (rc == 0) {
        rc = tpm2_ifx_cap_vendor_get(cap, TPM_PT_VENDOR_FIX_FU_OPERATION_MODE,
            &cap->opMode, sizeof(cap->opMode));
    }
    if (rc == 0) {
        rc = tpm2_ifx_cap_vendor_get(cap, TPM_PT_VENDOR_FIX_FU_KEYGROUP_ID,
            (uint8_t*)&cap->keyGroupId, sizeof(cap->keyGroupId));
    }
    if (rc == 0) {
        rc = tpm2_ifx_cap_vendor_get(cap, TPM_PT_VENDOR_FIX_FU_COUNTER,
            (uint8_t*)&cap->fwCounter, sizeof(cap->fwCounter));
    }
    if (rc == 0) {
        rc = tpm2_ifx_cap_vendor_get(cap, TPM_PT_VENDOR_FIX_FU_COUNTER_SAME,
            (uint8_t*)&cap->fwCounterSame, sizeof(cap->fwCounterSame));
    }
#endif

    return rc;
}

int wolfTPM2_GetCapabilities(WOLFTPM2_DEV* dev, WOLFTPM2_CAPS* cap)
{
    if (dev == NULL)
        return BAD_FUNC_ARG;

    return wolfTPM2_GetCapabilities_NoDev(cap);
}

int wolfTPM2_GetHandles(TPM_HANDLE handle, TPML_HANDLE* handles)
{
    int rc;
    GetCapability_In  in;
    GetCapability_Out out;
#ifdef DEBUG_WOLFTPM
    UINT32 i;
#endif

    /* Get Capability TPM_CAP_HANDLES - PCR */
    XMEMSET(&in, 0, sizeof(in));
    in.capability = TPM_CAP_HANDLES;
    in.property = handle;
    in.propertyCount = MAX_CAP_HANDLES;
    rc = TPM2_GetCapability(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_GetCapability handles failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }
    if (handles != NULL) {
        /* optionally return handles count/list */
        XMEMCPY(handles, &out.capabilityData.data.handles, sizeof(TPML_HANDLE));
    }
    handles = &out.capabilityData.data.handles;
#ifdef DEBUG_WOLFTPM
    printf("Handles Cap: Start 0x%x, Count %d\n", handle, handles->count);
    for (i=0; i<handles->count; i++) {
        printf("\tHandle 0x%x\n", handles->handle[i]);
    }
#endif
    return handles->count;
}

int wolfTPM2_UnsetAuth(WOLFTPM2_DEV* dev, int index)
{
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || index >= MAX_SESSION_NUM || index < 0) {
        return BAD_FUNC_ARG;
    }

    session = &dev->session[index];
    XMEMSET(session, 0, sizeof(TPM2_AUTH_SESSION));

    return TPM2_SetSessionAuth(dev->session);
}

int wolfTPM2_UnsetAuthSession(WOLFTPM2_DEV* dev, int index,
    WOLFTPM2_SESSION* tpmSession)
{
    TPM2_AUTH_SESSION* devSession;

    if (dev == NULL || tpmSession == NULL ||
            index >= MAX_SESSION_NUM || index < 0) {
        return BAD_FUNC_ARG;
    }

    devSession = &dev->session[index];

    /* save off nonce from TPM to support continued use of session */
    XMEMCPY(&tpmSession->nonceTPM, &devSession->nonceTPM, sizeof(TPM2B_NONCE));

    XMEMSET(devSession, 0, sizeof(TPM2_AUTH_SESSION));

    return TPM2_SetSessionAuth(dev->session);
}

int wolfTPM2_SetAuth(WOLFTPM2_DEV* dev, int index,
    TPM_HANDLE sessionHandle, const TPM2B_AUTH* auth,
    TPMA_SESSION sessionAttributes, const TPM2B_NAME* name)
{
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || index >= MAX_SESSION_NUM || index < 0) {
        return BAD_FUNC_ARG;
    }

    session = &dev->session[index];
    XMEMSET(session, 0, sizeof(TPM2_AUTH_SESSION));
    session->sessionHandle = sessionHandle;
    session->sessionAttributes = sessionAttributes;
    if (auth) {
        session->auth.size = auth->size;
        XMEMCPY(session->auth.buffer, auth->buffer, auth->size);
    }
    if (name) {
        session->name.size = name->size;
        XMEMCPY(session->name.name, name->name, name->size);
    }

    TPM2_SetSessionAuth(dev->session);

    return TPM_RC_SUCCESS;
}

int wolfTPM2_SetAuthPassword(WOLFTPM2_DEV* dev, int index,
    const TPM2B_AUTH* auth)
{
    return wolfTPM2_SetAuth(dev, index, TPM_RS_PW, auth, 0, NULL);
}

int wolfTPM2_SetAuthHandle(WOLFTPM2_DEV* dev, int index,
    const WOLFTPM2_HANDLE* handle)
{
    const TPM2B_AUTH* auth = NULL;
    const TPM2B_NAME* name = NULL;
    if (dev == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    if (handle) {
        /* don't set auth for policy session, just name */
        if (handle->policyAuth) {
            TPM2_AUTH_SESSION* session = &dev->session[index];
            session->name.size = handle->name.size;
            XMEMCPY(session->name.name, handle->name.name, handle->name.size);
            return TPM_RC_SUCCESS;
        }
        auth = &handle->auth;
        name = &handle->name;
    }
    return wolfTPM2_SetAuth(dev, index, TPM_RS_PW, auth, 0, name);
}

int wolfTPM2_SetAuthHandleName(WOLFTPM2_DEV* dev, int index,
    const WOLFTPM2_HANDLE* handle)
{
    const TPM2B_NAME* name = NULL;
    TPM2_AUTH_SESSION* session;

    if (dev == NULL || handle == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    name = &handle->name;
    session = &dev->session[index];

    if (session->auth.size == 0 && handle->auth.size > 0) {
        session->auth.size = handle->auth.size;
        XMEMCPY(session->auth.buffer, handle->auth.buffer, handle->auth.size);
    }
    session->name.size = name->size;
    XMEMCPY(session->name.name, name->name, session->name.size);

    return TPM_RC_SUCCESS;
}

int wolfTPM2_SetAuthSession(WOLFTPM2_DEV* dev, int index,
    WOLFTPM2_SESSION* tpmSession, TPMA_SESSION sessionAttributes)
{
    int rc;

    if (dev == NULL || index >= MAX_SESSION_NUM) {
        return BAD_FUNC_ARG;
    }

    if (tpmSession == NULL) {
        /* clearing auth session */
        XMEMSET(&dev->session[index], 0, sizeof(TPM2_AUTH_SESSION));
        return TPM_RC_SUCCESS;
    }

    rc = wolfTPM2_SetAuth(dev, index, tpmSession->handle.hndl,
        &tpmSession->handle.auth, sessionAttributes, NULL);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_AUTH_SESSION* session = &dev->session[index];

        /* save off session attributes */
        tpmSession->sessionAttributes = sessionAttributes;

        /* define the symmetric algorithm */
        session->authHash = tpmSession->authHash;
        XMEMCPY(&session->symmetric, &tpmSession->handle.symmetric,
            sizeof(TPMT_SYM_DEF));

        /* fresh nonce generated in TPM2_CommandProcess based on this size */
        session->nonceCaller.size = TPM2_GetHashDigestSize(WOLFTPM2_WRAP_DIGEST);

        /* Capture TPM provided nonce */
        session->nonceTPM.size = tpmSession->nonceTPM.size;
        XMEMCPY(session->nonceTPM.buffer, tpmSession->nonceTPM.buffer,
            session->nonceTPM.size);

        /* Parameter Encryption or Policy session will have an HMAC added later.
         * Reserve space, the same way it was done for nonceCaller above.
         */
        if ((session->sessionHandle != TPM_RS_PW &&
                ((session->sessionAttributes & TPMA_SESSION_encrypt) ||
                 (session->sessionAttributes & TPMA_SESSION_decrypt)))
             || TPM2_IS_POLICY_SESSION(session->sessionHandle))
        {
            session->auth.size = TPM2_GetHashDigestSize(session->authHash);
        }
    }
    return rc;
}

int wolfTPM2_CreateAuthSession_EkPolicy(WOLFTPM2_DEV* dev,
                                        WOLFTPM2_SESSION* tpmSession)
{
    int rc = TPM_RC_FAILURE;
    PolicySecret_In policySecretIn;
    PolicySecret_Out policySecretOut;

    /* Endorsement Key requires authorization with Policy */
    rc = wolfTPM2_StartSession(dev, tpmSession, NULL, NULL,
                               TPM_SE_POLICY, TPM_ALG_NULL);
    if (rc == TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
                (word32)tpmSession->handle.hndl);
        #endif
        /* Provide Endorsement Auth using PolicySecret */
        XMEMSET(&policySecretIn, 0, sizeof(policySecretIn));
        policySecretIn.authHandle = TPM_RH_ENDORSEMENT;
        policySecretIn.policySession = tpmSession->handle.hndl;
        rc = TPM2_PolicySecret(&policySecretIn, &policySecretOut);
        #ifdef DEBUG_WOLFTPM
        if (rc == TPM_RC_SUCCESS) {
            printf("policySecret applied on session\n");
        }
        #endif
    }
    return rc;
}

int wolfTPM2_Cleanup_ex(WOLFTPM2_DEV* dev, int doShutdown)
{
    int rc = 0;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFTPM_CRYPTOCB
    /* make sure crypto dev callback is unregistered */
    rc = wolfTPM2_ClearCryptoDevCb(dev, INVALID_DEVID);
    if (rc != 0)
        return rc;
#endif

    if (doShutdown)  {
        Shutdown_In shutdownIn;
        XMEMSET(&shutdownIn, 0, sizeof(shutdownIn));
        shutdownIn.shutdownType = TPM_SU_CLEAR;
        rc = TPM2_Shutdown(&shutdownIn);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_Shutdown failed %d: %s\n",
                rc, wolfTPM2_GetRCString(rc));
        #endif
            /* finish cleanup and return error */
        }
    }

    TPM2_Cleanup(&dev->ctx);

    return rc;
}

int wolfTPM2_Cleanup(WOLFTPM2_DEV* dev)
{
#if defined(WOLFTPM_WINAPI)
    return wolfTPM2_Cleanup_ex(dev, 0);
#else
    return wolfTPM2_Cleanup_ex(dev, 1);
#endif
}

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && defined(HAVE_ECC) && \
    !defined(WC_NO_RNG) && defined(WOLFSSL_PUBLIC_MP)
/* The KDF for producing a symmetric key.
 * See TPM 2.0 Part 1 specification (11.4.9.3)
 */
static int TPM2_KDFe(
    TPM_ALG_ID        hashAlg,    /* IN: hash algorithm used */
    const TPM2B_DATA *Z,          /* IN: x coordinate of shared secret */
    const char       *label,      /* IN: a 0-byte terminated label used in KDF */
    const TPM2B_DATA *partyUInfo, /* IN: x coordinate of our public key */
    const TPM2B_DATA *partyVInfo, /* IN: x coordinate of peer's public key */
    BYTE             *key,        /* OUT: key buffer */
    UINT32           keySz        /* IN: size of generated key in bytes */
)
{
    int ret;
    enum wc_HashType hashType;
    wc_HashAlg hash_ctx;
    word32 counter = 0;
    int hLen, copyLen, lLen = 0;
    byte uint32Buf[sizeof(UINT32)];
    UINT32 pos;
    BYTE* keyStream = key;
    byte hash[WC_MAX_DIGEST_SIZE];

    if (key == NULL || Z == NULL)
        return BAD_FUNC_ARG;

    ret = TPM2_GetHashType(hashAlg);
    if (ret == WC_HASH_TYPE_NONE)
        return NOT_COMPILED_IN;
    hashType = (enum wc_HashType)ret;

    hLen = TPM2_GetHashDigestSize(hashAlg);
    if ((hLen <= 0) || (hLen > WC_MAX_DIGEST_SIZE))
        return NOT_COMPILED_IN;

    /* get label length if provided, including null termination */
    if (label != NULL) {
        lLen = (int)XSTRLEN(label) + 1;
    }

    ret = wc_HashInit(&hash_ctx, hashType);
    if (ret != 0)
        return ret;

    /* generate required bytes - blocks sized digest */
    for (pos = 0; pos < keySz; pos += hLen) {
        /* KDFe counter starts at 1 */
        counter++;
        copyLen = hLen;

        /* add counter */
        TPM2_Packet_U32ToByteArray(counter, uint32Buf);
        ret = wc_HashUpdate(&hash_ctx, hashType, uint32Buf,
            (word32)sizeof(uint32Buf));
        /* add Z */
        if (ret == 0) {
            ret = wc_HashUpdate(&hash_ctx, hashType, Z->buffer, Z->size);
        }
        /* add label */
        if (ret == 0 && label != NULL) {
            ret = wc_HashUpdate(&hash_ctx, hashType, (byte*)label, lLen);
        }

        /* add partyUInfo */
        if (ret == 0 && partyUInfo != NULL && partyUInfo->size > 0) {
            ret = wc_HashUpdate(&hash_ctx, hashType, partyUInfo->buffer,
                partyUInfo->size);
        }

        /* add partyVInfo */
        if (ret == 0 && partyVInfo != NULL && partyVInfo->size > 0) {
            ret = wc_HashUpdate(&hash_ctx, hashType, partyVInfo->buffer,
                partyVInfo->size);
        }

        /* get result */
        if (ret == 0) {
            ret = wc_HashFinal(&hash_ctx, hashType, hash);
        }

        if (ret != 0) {
            goto exit;
        }

        if ((UINT32)hLen > keySz - pos) {
          copyLen = keySz - pos;
        }

        XMEMCPY(keyStream, hash, copyLen);
        keyStream += copyLen;
    }
    ret = keySz;

exit:
    wc_HashFree(&hash_ctx, hashType);

    /* return length rounded up to nearest 8 multiple */
    return ret;
}

#ifdef ALT_ECC_SIZE
#error use of ecc_point below does not support ALT_ECC_SIZE
#endif
/* returns both the plaintext and encrypted value */
/* ECC: data = derived symmetric key
 *      secret = exported public point */
static int wolfTPM2_EncryptSecret_ECC(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* tpmKey,
    TPM2B_DATA *data, TPM2B_ENCRYPTED_SECRET *secret,
    const char* label)
{
    int rc;
    WC_RNG rng;
    ecc_key eccKeyPriv, eccKeyPub;
    const TPMT_PUBLIC *publicArea;
    TPM2B_ECC_POINT pubPoint, secretPoint;
    ecc_point r[1];
    mp_int prime, a;
    word32 keySz = 0;

    publicArea = &tpmKey->pub.publicArea;
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&eccKeyPub, 0, sizeof(eccKeyPub));
    XMEMSET(&eccKeyPriv, 0, sizeof(eccKeyPriv));
    XMEMSET(&pubPoint, 0, sizeof(pubPoint));
    XMEMSET(&secretPoint, 0, sizeof(secretPoint));
    XMEMSET(r, 0, sizeof(r));
    XMEMSET(&prime, 0, sizeof(prime));
    XMEMSET(&a, 0, sizeof(a));

    rc = wc_InitRng_ex(&rng, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_ecc_init_ex(&eccKeyPub, NULL, INVALID_DEVID);
    }
    if (rc == 0) {
        rc = wc_ecc_init_ex(&eccKeyPriv, NULL, INVALID_DEVID);
    }
#ifdef ECC_TIMING_RESISTANT
    if (rc == 0) {
        wc_ecc_set_rng(&eccKeyPriv, &rng);
        wc_ecc_set_rng(&eccKeyPub, &rng);
    }
#endif
    if (rc == 0) {
        /* import peer public key */
        rc = wolfTPM2_EccKey_TpmToWolf(dev, (WOLFTPM2_KEY*)tpmKey, &eccKeyPub);
    }
    if (rc == 0) {
        /* create local private key */
        rc = wc_ecc_make_key_ex(&rng, 0, &eccKeyPriv,
            TPM2_GetWolfCurve(publicArea->parameters.eccDetail.curveID));
    }
    if (rc == 0) {
        keySz = wc_ecc_size(&eccKeyPriv);

        /* export private's public point as data */
        rc = wolfTPM2_EccKey_WolfToPubPoint(dev, &eccKeyPriv, &pubPoint);
    }
    if (rc == 0) {
        /* Export public point x/y into secret buffer for peer */
        TPM2_Packet packet;
        XMEMSET(&packet, 0, sizeof(packet));
        packet.buf = secret->secret;
        packet.size = sizeof(secret->secret);
        TPM2_Packet_AppendEccPoint(&packet, &pubPoint.point);
        secret->size = packet.pos;
    }
    if (rc == 0) {
        rc = mp_init_multi(&prime, &a, r->x, r->y, r->z, NULL);
    }
    if (rc == 0) {
        rc = mp_read_radix(&prime, eccKeyPriv.dp->prime, MP_RADIX_HEX);
    }
    if (rc == 0) {
        rc = mp_read_radix(&a, eccKeyPriv.dp->Af, MP_RADIX_HEX);
    }
    if (rc == 0) {
        /* perform point multiply */
        rc = wc_ecc_mulmod(wc_ecc_key_get_priv(&eccKeyPriv), &eccKeyPub.pubkey,
            r, &a, &prime, 1);
    }
    if (rc == 0) {
        /* export shared secret x - zero pad to key size */
        secretPoint.point.x.size = mp_unsigned_bin_size(r->x);
        rc = mp_to_unsigned_bin(r->x,
            &secretPoint.point.x.buffer[keySz-secretPoint.point.x.size]);
        secretPoint.point.x.size = keySz;
    }
    if (rc == 0) {
        /* set size encryption key */
        data->size = TPM2_GetHashDigestSize(publicArea->nameAlg);

        rc = TPM2_KDFe(
            publicArea->nameAlg,
            (const TPM2B_DATA*)&secretPoint.point.x,
            label,
            (const TPM2B_DATA*)&pubPoint.point.x,
            (const TPM2B_DATA*)&publicArea->unique.ecc.x,
            data->buffer,
            data->size
        );
    }

    mp_clear(r->x);
    mp_clear(r->y);
    mp_clear(r->z);
    mp_clear(&a);
    mp_clear(&prime);
    wc_ecc_free(&eccKeyPub);
    wc_ecc_free(&eccKeyPriv);
    wc_FreeRng(&rng);

    if (rc >= 0) {
        rc = (rc == data->size) ? 0 /* success */ : BUFFER_E /* fail */;
    }

    return rc;
}
#endif /* !WOLFTPM2_NO_WOLFCRYPT && HAVE_ECC && !WC_NO_RNG */

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA) && !defined(WC_NO_RNG)
/* returns both the plaintext and encrypted value */
/* RSA: data = input to encrypt or generated random value
 *      secret = RSA encrypted random */
static int wolfTPM2_EncryptSecret_RSA(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* tpmKey,
    TPM2B_DATA *data, TPM2B_ENCRYPTED_SECRET *secret, const char* label)
{
    int rc, mgf;
    enum wc_HashType hashType;
    WC_RNG rng;
    RsaKey rsaKey;
    const TPMT_PUBLIC *publicArea;

    publicArea = &tpmKey->pub.publicArea;
    if (publicArea->nameAlg == TPM_ALG_SHA1) {
        hashType = WC_HASH_TYPE_SHA;
        mgf = WC_MGF1SHA1;
    }
    else if (publicArea->nameAlg == TPM_ALG_SHA256) {
        hashType = WC_HASH_TYPE_SHA256;
        mgf = WC_MGF1SHA256;
    }
    else {
        return NOT_COMPILED_IN;
    }

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));

    rc = wc_InitRng_ex(&rng, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_InitRsaKey_ex(&rsaKey, NULL, INVALID_DEVID);
    }
#ifdef WC_RSA_BLINDING
    if (rc == 0) {
        wc_RsaSetRNG(&rsaKey, &rng);
    }
#endif
    if (rc == 0 && data->size == 0) {
        /* Generate random value to exchange for encryption */
        data->size = TPM2_GetHashDigestSize(publicArea->nameAlg);
        rc = wc_RNG_GenerateBlock(&rng, data->buffer, data->size);
    }
    if (rc == 0) {
        rc = wolfTPM2_RsaKey_TpmToWolf(dev, (WOLFTPM2_KEY*)tpmKey, &rsaKey);
    }
    if (rc == 0) {
        secret->size = publicArea->unique.rsa.size;
        rc = wc_RsaPublicEncrypt_ex(
            data->buffer,    /* in pointer to the buffer for encryption */
            data->size,      /* inLen length of in parameter */
            secret->secret, /* out encrypted msg created */
            secret->size,   /* outLen length of buffer available to hold encrypted msg */
            &rsaKey,         /* key initialized RSA key struct */
            &rng,            /* rng initialized WC_RNG struct */
            WC_RSA_OAEP_PAD, /* type type of padding to use (WC_RSA_OAEP_PAD or WC_RSA_PKCSV15_PAD) */
            hashType,        /* hash type of hash to use (choices can be found in hash.h) */
            mgf,             /* mgf type of mask generation function to use */
            (byte*)label,    /* label an optional label to associate with encrypted message */
            (word32)XSTRLEN(label)+1 /* labelSz size of the optional label used */
        );
    }

    wc_FreeRsaKey(&rsaKey);
    wc_FreeRng(&rng);

    if (rc > 0) {
        rc = (rc == secret->size) ? 0 /* success */ : BUFFER_E /* fail */;
    }

    return rc;
}
#endif /* !WOLFTPM2_NO_WOLFCRYPT && !NO_RSA && !WC_NO_RNG */

int wolfTPM2_EncryptSecret(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* tpmKey,
    TPM2B_DATA *data, TPM2B_ENCRYPTED_SECRET *secret,
    const char* label)
{
    int rc = NOT_COMPILED_IN;

    /* if a tpmKey is not present then we are using an unsalted session */
    if (dev == NULL || tpmKey == NULL || data == NULL || secret == NULL) {
        return TPM_RC_SUCCESS;
    }

#ifdef DEBUG_WOLFTPM
    printf("Encrypt secret: Alg %s, Label %s\n",
        TPM2_GetAlgName(tpmKey->pub.publicArea.type), label);
#endif

#ifndef WOLFTPM2_NO_WOLFCRYPT
    switch (tpmKey->pub.publicArea.type) {
    #if defined(HAVE_ECC) && !defined(WC_NO_RNG) && defined(WOLFSSL_PUBLIC_MP)
        case TPM_ALG_ECC:
            rc = wolfTPM2_EncryptSecret_ECC(dev, tpmKey, data, secret, label);
            break;
    #endif
    #if !defined(NO_RSA) && !defined(WC_NO_RNG)
        case TPM_ALG_RSA:
            rc = wolfTPM2_EncryptSecret_RSA(dev, tpmKey, data, secret, label);
            break;
    #endif
        default:
            rc = NOT_COMPILED_IN;
            break;
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Encrypt Secret %d: %d bytes\n", rc, data->size);
    TPM2_PrintBin(data->buffer, data->size);
#endif
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

    (void)label;

    return rc;
}

int wolfTPM2_StartSession(WOLFTPM2_DEV* dev, WOLFTPM2_SESSION* session,
    WOLFTPM2_KEY* tpmKey, WOLFTPM2_HANDLE* bind, TPM_SE sesType,
    int encDecAlg)
{
    int rc;
    StartAuthSession_In  authSesIn;
    StartAuthSession_Out authSesOut;
    TPM2B_AUTH* bindAuth = NULL;
    TPM2B_DATA keyIn;
    TPMI_ALG_HASH authHash = WOLFTPM2_WRAP_DIGEST;
    int hashDigestSz;

    if (dev == NULL || session == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(session, 0, sizeof(WOLFTPM2_SESSION));
    XMEMSET(&authSesIn, 0, sizeof(authSesIn));

    authSesIn.authHash = authHash;
    hashDigestSz = TPM2_GetHashDigestSize(authHash);
    if (hashDigestSz <= 0) {
        return NOT_COMPILED_IN;
    }

    /* set session auth for key */
    if (tpmKey) {
        TPMA_SESSION sessionAttributes = 0;
        if (encDecAlg == TPM_ALG_CFB || encDecAlg == TPM_ALG_XOR) {
            /* if parameter encryption is enabled and key bind set, enable
             * encrypt/decrypt by default */
            sessionAttributes |= (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt);
        }
        wolfTPM2_SetAuth(dev, 0, tpmKey->handle.hndl, &tpmKey->handle.auth,
            sessionAttributes, NULL);
        authSesIn.tpmKey = tpmKey->handle.hndl;
    }
    else {
        wolfTPM2_SetAuthPassword(dev, 0, NULL);
        authSesIn.tpmKey = (TPMI_DH_OBJECT)TPM_RH_NULL;
    }
    /* setup bind key */
    authSesIn.bind = (TPMI_DH_ENTITY)TPM_RH_NULL;
    if (bind) {
        authSesIn.bind = bind->hndl;
        bindAuth = &bind->auth;
    }

    authSesIn.sessionType = sesType;
    if (encDecAlg == TPM_ALG_CFB) {
        authSesIn.symmetric.algorithm = TPM_ALG_AES;
        authSesIn.symmetric.keyBits.aes = 128;
        authSesIn.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else if (encDecAlg == TPM_ALG_XOR) {
        authSesIn.symmetric.algorithm = TPM_ALG_XOR;
        authSesIn.symmetric.keyBits.xorr = TPM_ALG_SHA256;
        authSesIn.symmetric.mode.sym = TPM_ALG_NULL;
    }
    else {
        authSesIn.symmetric.algorithm = TPM_ALG_NULL;
    }
    authSesIn.nonceCaller.size = hashDigestSz;
    rc = TPM2_GetNonce(authSesIn.nonceCaller.buffer,
                       authSesIn.nonceCaller.size);
    if (rc < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_GetNonce failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    if (authSesIn.tpmKey != TPM_RH_NULL) {
        /* Generate random salt */
        session->salt.size = hashDigestSz;
        rc = TPM2_GetNonce(session->salt.buffer, session->salt.size);
        if (rc != 0) {
            return rc;
        }

        /* Encrypt salt using "SECRET" */
        rc = wolfTPM2_EncryptSecret(dev, tpmKey, (TPM2B_DATA*)&session->salt,
            &authSesIn.encryptedSalt, "SECRET");
        if (rc != 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Building encrypted salt failed %d: %s!\n", rc,
                wolfTPM2_GetRCString(rc));
        #endif
            return rc;
        }
    }

    rc = TPM2_StartAuthSession(&authSesIn, &authSesOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_StartAuthSession failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Calculate "key" and store into auth */
    /* key is bindAuthValue || salt */
    XMEMSET(&keyIn, 0, sizeof(keyIn));
    if (bindAuth && bindAuth->size > 0) {
        XMEMCPY(&keyIn.buffer[keyIn.size], bindAuth->buffer, bindAuth->size);
        keyIn.size += bindAuth->size;
    }
    if (session->salt.size > 0) {
        XMEMCPY(&keyIn.buffer[keyIn.size], session->salt.buffer,
            session->salt.size);
        keyIn.size += session->salt.size;
    }

    if (keyIn.size > 0) {
        session->handle.auth.size = hashDigestSz;
        rc = TPM2_KDFa(authSesIn.authHash, &keyIn, "ATH",
            &authSesOut.nonceTPM, &authSesIn.nonceCaller,
            session->handle.auth.buffer, session->handle.auth.size);
        if (rc != hashDigestSz) {
        #ifdef DEBUG_WOLFTPM
            printf("KDFa ATH Gen Error %d\n", rc);
        #endif
            return TPM_RC_FAILURE;
        }
        rc = TPM_RC_SUCCESS;
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Session Key %d\n", session->handle.auth.size);
    TPM2_PrintBin(session->handle.auth.buffer, session->handle.auth.size);
#endif

    /* return session */
    session->type = authSesIn.sessionType;
    session->authHash = authSesIn.authHash;
    session->handle.hndl = authSesOut.sessionHandle;
    wolfTPM2_CopySymmetric(&session->handle.symmetric, &authSesIn.symmetric);
    if (bind) {
        wolfTPM2_CopyName(&session->handle.name, &bind->name);
    }
    session->nonceCaller.size = authSesIn.nonceCaller.size;
    if (session->nonceCaller.size > (UINT16)sizeof(session->nonceCaller.buffer))
        session->nonceCaller.size = (UINT16)sizeof(session->nonceCaller.buffer);
    XMEMCPY(session->nonceCaller.buffer, authSesIn.nonceCaller.buffer,
        authSesIn.nonceCaller.size);
    session->nonceTPM.size = authSesOut.nonceTPM.size;
    if (session->nonceTPM.size > (UINT16)sizeof(session->nonceTPM.buffer))
        session->nonceTPM.size = (UINT16)sizeof(session->nonceTPM.buffer);
    XMEMCPY(session->nonceTPM.buffer, authSesOut.nonceTPM.buffer,
        session->nonceTPM.size);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_StartAuthSession: handle 0x%x, algorithm %s\n",
        (word32)session->handle.hndl,
        TPM2_GetAlgName(authSesIn.symmetric.algorithm));
#endif

    return rc;
}


int wolfTPM2_CreatePrimaryKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_HANDLE primaryHandle, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz)
{
    int rc;
    CreatePrimary_In  createPriIn;
    CreatePrimary_Out createPriOut;

    if (dev == NULL || key == NULL || publicTemplate == NULL)
        return BAD_FUNC_ARG;

    /* set session auth to blank */
    wolfTPM2_SetAuthPassword(dev, 0, NULL);

    /* clear output key buffer */
    XMEMSET(key, 0, sizeof(WOLFTPM2_KEY));

    /* setup create primary command */
    XMEMSET(&createPriIn, 0, sizeof(createPriIn));
    /* TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM or TPM_RH_NULL */
    createPriIn.primaryHandle = primaryHandle;
    if (auth && authSz > 0) {
        int nameAlgDigestSz = TPM2_GetHashDigestSize(publicTemplate->nameAlg);
        /* truncate if longer than name size */
        if (nameAlgDigestSz > 0 && authSz > nameAlgDigestSz)
            authSz = nameAlgDigestSz;
        XMEMCPY(createPriIn.inSensitive.sensitive.userAuth.buffer, auth, authSz);
        /* make sure auth is same size as nameAlg digest size */
        if (nameAlgDigestSz > 0 && authSz < nameAlgDigestSz)
            authSz = nameAlgDigestSz;
        createPriIn.inSensitive.sensitive.userAuth.size = authSz;
    }
    XMEMCPY(&createPriIn.inPublic.publicArea, publicTemplate,
        sizeof(TPMT_PUBLIC));
    rc = TPM2_CreatePrimary(&createPriIn, &createPriOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_CreatePrimary: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    key->handle.hndl = createPriOut.objectHandle;
    wolfTPM2_CopyAuth(&key->handle.auth,
        &createPriIn.inSensitive.sensitive.userAuth);
    wolfTPM2_CopyName(&key->handle.name, &createPriOut.name);
    wolfTPM2_CopySymmetric(&key->handle.symmetric,
        &createPriOut.outPublic.publicArea.parameters.asymDetail.symmetric);
    wolfTPM2_CopyPub(&key->pub, &createPriOut.outPublic);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_CreatePrimary: 0x%x (%d bytes)\n",
        (word32)key->handle.hndl, key->pub.size);
#endif

    return rc;
}

int wolfTPM2_ChangeAuthKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    WOLFTPM2_HANDLE* parent, const byte* auth, int authSz)
{
    int rc;
    ObjectChangeAuth_In changeIn;
    ObjectChangeAuth_Out changeOut;
    Load_In  loadIn;
    Load_Out loadOut;

    if (dev == NULL || key == NULL || parent == NULL)
        return BAD_FUNC_ARG;

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &key->handle);

    XMEMSET(&changeIn, 0, sizeof(changeIn));
    changeIn.objectHandle = key->handle.hndl;
    changeIn.parentHandle = parent->hndl;
    if (auth) {
        if (authSz > (int)sizeof(changeIn.newAuth.buffer))
            authSz = (int)sizeof(changeIn.newAuth.buffer);
        changeIn.newAuth.size = authSz;
        XMEMCPY(changeIn.newAuth.buffer, auth, changeIn.newAuth.size);
    }

    rc = TPM2_ObjectChangeAuth(&changeIn, &changeOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_ObjectChangeAuth failed %d: %s\n", rc,
                wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* unload old key */
    wolfTPM2_UnloadHandle(dev, &key->handle);

    /* set session auth for parent key */
    wolfTPM2_SetAuthHandle(dev, 0, parent);

    /* Load new key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent->hndl;
    wolfTPM2_CopyPriv(&loadIn.inPrivate, &changeOut.outPrivate);
    wolfTPM2_CopyPub(&loadIn.inPublic, &key->pub);
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Load key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    key->handle.hndl = loadOut.objectHandle;
    wolfTPM2_CopyAuth(&key->handle.auth, &changeIn.newAuth);
    wolfTPM2_CopyName(&key->handle.name, &loadOut.name);

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_ChangeAuthKey: Key Handle 0x%x\n",
        (word32)key->handle.hndl);
#endif

    return rc;
}

int wolfTPM2_CreateKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEYBLOB* keyBlob,
    WOLFTPM2_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz)
{
    int rc;
    Create_In  createIn;
    Create_Out createOut;

    if (dev == NULL || keyBlob == NULL || parent == NULL ||
            publicTemplate == NULL) {
        return BAD_FUNC_ARG;
    }

    /* clear output key buffer */
    XMEMSET(keyBlob, 0, sizeof(WOLFTPM2_KEYBLOB));
    XMEMSET(&createOut, 0, sizeof(createOut)); /* make sure pub struct is zero init */

    /* set session auth for parent key */
    wolfTPM2_SetAuthHandle(dev, 0, parent);

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
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Create key: pub %d, priv %d\n",
        createOut.outPublic.size, createOut.outPrivate.size);
    TPM2_PrintPublicArea(&createOut.outPublic);
#endif

    wolfTPM2_CopyAuth(&keyBlob->handle.auth,
        &createIn.inSensitive.sensitive.userAuth);
    wolfTPM2_CopySymmetric(&keyBlob->handle.symmetric,
            &createOut.outPublic.publicArea.parameters.asymDetail.symmetric);
    wolfTPM2_CopyPub(&keyBlob->pub, &createOut.outPublic);
    wolfTPM2_CopyPriv(&keyBlob->priv, &createOut.outPrivate);

    return rc;
}

int wolfTPM2_LoadKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEYBLOB* keyBlob,
    WOLFTPM2_HANDLE* parent)
{
    int rc;
    Load_In loadIn;
    Load_Out loadOut;

    if (dev == NULL || keyBlob == NULL || parent == NULL)
        return BAD_FUNC_ARG;

    /* set session auth for parent key */
    wolfTPM2_SetAuthHandle(dev, 0, parent);

    /* Load new key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent->hndl;
    wolfTPM2_CopyPriv(&loadIn.inPrivate, &keyBlob->priv);
    wolfTPM2_CopyPub(&loadIn.inPublic, &keyBlob->pub);
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Load key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    keyBlob->handle.hndl = loadOut.objectHandle;
    wolfTPM2_CopyName(&keyBlob->handle.name, &loadOut.name);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Load Key Handle 0x%x\n", (word32)keyBlob->handle.hndl);
#endif

    return rc;
}

int wolfTPM2_CreateAndLoadKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    WOLFTPM2_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz)
{
    int rc;
    WOLFTPM2_KEYBLOB keyBlob;

    if (dev == NULL || key == NULL)
        return BAD_FUNC_ARG;

    rc = wolfTPM2_CreateKey(dev, &keyBlob, parent, publicTemplate, auth, authSz);
    if (rc == TPM_RC_SUCCESS) {
        rc = wolfTPM2_LoadKey(dev, &keyBlob, parent);
    }

    /* return loaded key */
    XMEMCPY(key, &keyBlob, sizeof(WOLFTPM2_KEY));

    return rc;
}

int wolfTPM2_CreateLoadedKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEYBLOB* keyBlob,
    WOLFTPM2_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz)
{
    int rc;
    CreateLoaded_In  createLoadedIn;
    CreateLoaded_Out createLoadedOut;

    if (dev == NULL || keyBlob == NULL || parent == NULL || publicTemplate == NULL)
        return BAD_FUNC_ARG;

    /* clear output key buffer */
    XMEMSET(keyBlob, 0, sizeof(WOLFTPM2_KEYBLOB));
    XMEMSET(&createLoadedOut, 0, sizeof(createLoadedOut)); /* make sure pub struct is zero init */

    /* set session auth for parent key */
    wolfTPM2_SetAuthHandle(dev, 0, parent);

    XMEMSET(&createLoadedIn, 0, sizeof(createLoadedIn));
    createLoadedIn.parentHandle = parent->hndl;
    if (auth) {
        createLoadedIn.inSensitive.sensitive.userAuth.size = authSz;
        XMEMCPY(createLoadedIn.inSensitive.sensitive.userAuth.buffer, auth,
            createLoadedIn.inSensitive.sensitive.userAuth.size);
    }
    XMEMCPY(&createLoadedIn.inPublic.publicArea, publicTemplate, sizeof(TPMT_PUBLIC));

    rc = TPM2_CreateLoaded(&createLoadedIn, &createLoadedOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_CreateLoaded key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_CreateLoaded key: pub %d, priv %d\n",
        createLoadedOut.outPublic.size, createLoadedOut.outPrivate.size);
    TPM2_PrintPublicArea(&createLoadedOut.outPublic);
#endif

    keyBlob->handle.hndl = createLoadedOut.objectHandle;

    wolfTPM2_CopyAuth(&keyBlob->handle.auth,
        &createLoadedIn.inSensitive.sensitive.userAuth);
    wolfTPM2_CopySymmetric(&keyBlob->handle.symmetric,
      &createLoadedOut.outPublic.publicArea.parameters.asymDetail.symmetric);

    wolfTPM2_CopyPub(&keyBlob->pub, &createLoadedOut.outPublic);
    wolfTPM2_CopyPriv(&keyBlob->priv, &createLoadedOut.outPrivate);
    wolfTPM2_CopyName(&keyBlob->handle.name, &createLoadedOut.name);

    return rc;
}

int wolfTPM2_LoadPublicKey_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM2B_PUBLIC* pub, TPM_HANDLE hierarchy)
{
    int rc;
    LoadExternal_In  loadExtIn;
    LoadExternal_Out loadExtOut;

    if (dev == NULL || key == NULL || pub == NULL)
        return BAD_FUNC_ARG;

    /* Loading public key */
    XMEMSET(&loadExtIn, 0, sizeof(loadExtIn));
    wolfTPM2_CopyPub(&loadExtIn.inPublic, pub);
    loadExtIn.hierarchy = hierarchy;
    rc = TPM2_LoadExternal(&loadExtIn, &loadExtOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_LoadExternal: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    key->handle.hndl = loadExtOut.objectHandle;
    wolfTPM2_CopySymmetric(&key->handle.symmetric,
            &loadExtIn.inPublic.publicArea.parameters.asymDetail.symmetric);
    wolfTPM2_CopyName(&key->handle.name, &loadExtOut.name);
    wolfTPM2_CopyPub(&key->pub, &loadExtIn.inPublic);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_LoadExternal: 0x%x\n", (word32)loadExtOut.objectHandle);
#endif

    return rc;
}
int wolfTPM2_LoadPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM2B_PUBLIC* pub)
{
    return wolfTPM2_LoadPublicKey_ex(dev, key, pub, TPM_RH_OWNER);
}

int wolfTPM2_ComputeName(const TPM2B_PUBLIC* pub, TPM2B_NAME* out)
{
    int rc;
    TPMI_ALG_HASH nameAlg;
#ifndef WOLFTPM2_NO_WOLFCRYPT
    TPM2_Packet packet;
    TPM2B_TEMPLATE data;
    wc_HashAlg hash;
    enum wc_HashType hashType;
    int hashSz;
#endif

    if (pub == NULL || out == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(out, 0, sizeof(TPM2B_NAME));
    nameAlg = pub->publicArea.nameAlg;
    if (nameAlg == TPM_ALG_NULL)
        return TPM_RC_SUCCESS;

#ifndef WOLFTPM2_NO_WOLFCRYPT
    /* Encode public into buffer */
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = data.buffer;
    packet.size = sizeof(data.buffer);
    TPM2_Packet_AppendPublicArea(&packet, (TPMT_PUBLIC*)&pub->publicArea);
    data.size = packet.pos;

    /* Hash data - first two bytes are TPM_ALG_ID */
    rc = TPM2_GetHashType(nameAlg);
    hashType = (enum wc_HashType)rc;
    rc = wc_HashGetDigestSize(hashType);
    if (rc < 0)
        return rc;
    hashSz = rc;

    /* Encode hash algorithm in first 2 bytes */
    nameAlg = TPM2_Packet_SwapU16(nameAlg);
    XMEMCPY(&out->name[0], &nameAlg, sizeof(UINT16));

    /* Hash of data (name) goes into remainder */
    rc = wc_HashInit(&hash, hashType);
    if (rc == 0) {
        rc = wc_HashUpdate(&hash, hashType, data.buffer, data.size);
        if (rc == 0)
            rc = wc_HashFinal(&hash, hashType, &out->name[sizeof(UINT16)]);

        wc_HashFree(&hash, hashType);
    }

    /* compute final size */
    out->size = hashSz + (int)sizeof(UINT16);
#else
    (void)out;
    rc = NOT_COMPILED_IN;
#endif
    return rc;
}

/* Convert TPM2B_SENSITIVE to TPM2B_PRIVATE */
/* TPM2B_PRIVATE format:
 *   Integrity (UINT16) + Integrity (HMAC Digest) +
 *   IV (UINT16) + IV +
 *   Sensitive
 */
static int SensitiveToPrivate(TPM2B_SENSITIVE* sens, TPM2B_PRIVATE* priv,
    TPMI_ALG_HASH nameAlg, TPM2B_NAME* name, const WOLFTPM2_KEY* parentKey,
    TPMT_SYM_DEF_OBJECT* sym, TPM2B_DATA* symSeed, int useIv)
{
    int rc = 0;
#if !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    !defined(NO_AES) && defined(WOLFSSL_AES_CFB) && !defined(NO_HMAC)
    int outerWrap = 0, innerWrap = 0;
    int digestSz = 0;
    int integritySz = 0;
    int ivSz = 0;
    int sensSz = 0;
    BYTE* sensitiveData = NULL;
    TPM2B_IV ivField;
    TPM2_Packet packet;
    TPM2B_SYM_KEY symKey;
    TPM2B_DIGEST hmacKey;
    Aes enc;
    Hmac hmac_ctx;

    if (sens == NULL || priv == NULL) {
        return BAD_FUNC_ARG;
    }

    /* if using a parent then use it's integrity algorithm */
    if (parentKey != NULL) {
        nameAlg = parentKey->pub.publicArea.nameAlg;
        symKey.size = parentKey->handle.symmetric.keyBits.sym;
    }
    else {
        symKey.size = sym->keyBits.sym;
    }

    digestSz = TPM2_GetHashDigestSize(nameAlg);
    if (digestSz == 0) {
    #ifdef DEBUG_WOLFTPM
        printf("SensitiveToPrivate: Invalid name algorithm %d\n", nameAlg);
    #endif
        return TPM_RC_FAILURE;
    }

    /* Use outer wrap (Integrity then Encrypt) */
    if (symSeed && symSeed->size > 0) {
        outerWrap = 1;
        integritySz = sizeof(word16) + digestSz;
    }

    /* Use inner wrap (Encrypt then Integrity) */
    if (sym && sym->algorithm != TPM_ALG_NULL) {
        innerWrap = 1;
    }

    /* IV: Generate or use 0 */
    XMEMSET(&ivField, 0, sizeof(ivField));
    if (useIv) {
        /* Encode IV into private buffer */
        XMEMSET(&packet, 0, sizeof(packet));
        packet.buf = &priv->buffer[integritySz];
        packet.size = sizeof(priv->buffer) - integritySz;
        TPM2_Packet_AppendU16(&packet, ivField.size);
        TPM2_Packet_AppendBytes(&packet, ivField.buffer, ivField.size);
        ivSz = packet.pos;
    }

    /* Encode sensitive into private buffer */
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = &priv->buffer[integritySz + ivSz];
    packet.size = sizeof(priv->buffer) - (integritySz + ivSz);
    TPM2_Packet_AppendSensitive(&packet, sens);
    sensSz = packet.pos;
    priv->size = integritySz + ivSz + sensSz;

    sensitiveData = &priv->buffer[integritySz];
    sensSz = ivSz + sensSz;

    if (innerWrap) {
        /* TODO: Inner wrap support */
    }

    if (outerWrap) {
        /* Generate symmetric key for encryption of inner values */
        symKey.size = (symKey.size + 7) / 8; /* convert to byte and round up */
        rc = TPM2_KDFa(nameAlg, symSeed, "STORAGE", (TPM2B_NONCE*)name,
            NULL, symKey.buffer, symKey.size);
        if (rc != symKey.size) {
        #ifdef DEBUG_WOLFTPM
            printf("KDFa STORAGE Gen Error %d\n", rc);
        #endif
            return TPM_RC_FAILURE;
        }

        /* Encrypt the Sensitive Area using the generated symmetric key */
        rc = wc_AesInit(&enc, NULL, INVALID_DEVID);
        if (rc == 0) {
            rc = wc_AesSetKey(&enc, symKey.buffer, symKey.size,
                ivField.size == 0 ? NULL : ivField.buffer, AES_ENCRYPTION);
            if (rc == 0) {
                /* use inline encryption for both IV and sensitive */
                rc = wc_AesCfbEncrypt(&enc, sensitiveData, sensitiveData, sensSz);
            }
            wc_AesFree(&enc);
        }
        if (rc != 0) {
        #ifdef DEBUG_WOLFTPM
            printf("SensitiveToPrivate AES error %d!\n", rc);
        #endif
            return rc;
        }

        /* Generate HMAC key for generation of the integrity value */
        hmacKey.size = digestSz;
        rc = TPM2_KDFa(nameAlg, symSeed, "INTEGRITY", NULL, NULL,
                    hmacKey.buffer, hmacKey.size);
        if (rc != hmacKey.size) {
        #ifdef DEBUG_WOLFTPM
            printf("KDFa INTEGRITY Gen Error %d\n", rc);
        #endif
            return rc;
        }

        /* setup HMAC */
        rc = wc_HmacInit(&hmac_ctx, NULL, INVALID_DEVID);
        if (rc == 0) {
            /* start HMAC */
            rc = wc_HmacSetKey(&hmac_ctx, TPM2_GetHashType(nameAlg),
                hmacKey.buffer, hmacKey.size);

            /* consume IV and sensitive area */
            if (rc == 0)
                rc = wc_HmacUpdate(&hmac_ctx, sensitiveData, sensSz);

            /* consume name field */
            if (rc == 0)
                rc = wc_HmacUpdate(&hmac_ctx, name->name, name->size);

            if (rc == 0)
                rc = wc_HmacFinal(&hmac_ctx, &priv->buffer[sizeof(word16)]);

            wc_HmacFree(&hmac_ctx);
        }
        if (rc != 0) {
        #ifdef DEBUG_WOLFTPM
            printf("SensitiveToPrivate HMAC error %d!\n", rc);
        #endif
            return rc;
        }

        /* store the size of the integrity */
        digestSz = TPM2_Packet_SwapU16(digestSz);
        XMEMCPY(&priv->buffer[0], &digestSz, sizeof(word16));
    }

#else
    rc = NOT_COMPILED_IN;
    (void)sens;
    (void)priv;
    (void)nameAlg;
    (void)name;
    (void)parentKey;
    (void)sym;
    (void)symSeed;
    (void)useIv;
#endif
    return rc;
}

int wolfTPM2_SensitiveToPrivate(TPM2B_SENSITIVE* sens, TPM2B_PRIVATE* priv,
    TPMI_ALG_HASH nameAlg, TPM2B_NAME* name, const WOLFTPM2_KEY* parentKey,
    TPMT_SYM_DEF_OBJECT* sym, TPM2B_DATA* symSeed)
{
    return SensitiveToPrivate(sens, priv, nameAlg, name, parentKey, sym,
        symSeed, 0);
}

/* Import external private key */
int wolfTPM2_ImportPrivateKey(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEYBLOB* keyBlob, const TPM2B_PUBLIC* pub, TPM2B_SENSITIVE* sens)
{
    int rc;
    Import_In  importIn;
    Import_Out importOut;
    TPM2B_NAME name;
    TPM_HANDLE parentHandle;
    TPM2B_DATA symSeed;

    if (dev == NULL || keyBlob == NULL || pub == NULL ||
            sens == NULL) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    if (parentKey != NULL) {
        /* set session auth for parent key */
        wolfTPM2_SetAuthHandle(dev, 0, &parentKey->handle);
        parentHandle = parentKey->handle.hndl;
    }
    else {
        parentHandle = TPM_RH_OWNER;
    }

    /* Import private key */
    XMEMSET(&importIn, 0, sizeof(importIn));
    importIn.parentHandle = parentHandle;
    wolfTPM2_CopyPub(&importIn.objectPublic, pub);
    importIn.symmetricAlg.algorithm = TPM_ALG_NULL;
    rc = wolfTPM2_ComputeName(pub, &name);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("wolfTPM2_ComputeName: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Get symmetric seed for KDFa */
    XMEMSET(&symSeed, 0, sizeof(symSeed));
    rc = wolfTPM2_EncryptSecret(dev, parentKey, &symSeed, &importIn.inSymSeed,
        "DUPLICATE");
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("wolfTPM2_EncryptSecret: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Encrypt sensitive */
    rc = wolfTPM2_SensitiveToPrivate(sens, &importIn.duplicate,
        pub->publicArea.nameAlg, &name, parentKey, &importIn.symmetricAlg,
        &symSeed);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("wolfTPM2_SensitiveToPrivate: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    rc = TPM2_Import(&importIn, &importOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Import: failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    wolfTPM2_CopySymmetric(&keyBlob->handle.symmetric,
            &importIn.objectPublic.publicArea.parameters.asymDetail.symmetric);
    wolfTPM2_CopyPub(&keyBlob->pub, &importIn.objectPublic);
    wolfTPM2_CopyPriv(&keyBlob->priv, &importOut.outPrivate);

    return rc;
}

/* Import and Load external private key to TPM */
int wolfTPM2_LoadPrivateKey(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEY* key, const TPM2B_PUBLIC* pub, TPM2B_SENSITIVE* sens)
{
    int rc;
    WOLFTPM2_KEYBLOB keyBlob;

    if (dev == NULL || key == NULL || pub == NULL || sens == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(&keyBlob, key, sizeof(WOLFTPM2_KEY));
    rc = wolfTPM2_ImportPrivateKey(dev, parentKey, &keyBlob, pub, sens);
    if (rc == 0) {
        WOLFTPM2_HANDLE parentHandle_lcl, *parentHandle = &parentHandle_lcl;
        if (parentKey != NULL) {
            parentHandle = (WOLFTPM2_HANDLE*)&parentKey->handle;
        }
        else {
            XMEMSET(parentHandle, 0, sizeof(*parentHandle));
            parentHandle->hndl = TPM_RH_OWNER;
        }

        rc = wolfTPM2_LoadKey(dev, &keyBlob, parentHandle);
    }

    /* return loaded key */
    key->handle.hndl = keyBlob.handle.hndl;
    wolfTPM2_CopyName(&key->handle.name, &keyBlob.handle.name);
    wolfTPM2_CopySymmetric(&key->handle.symmetric, &keyBlob.handle.symmetric);
    wolfTPM2_CopyPub(&key->pub, &keyBlob.pub);
    wolfTPM2_CopyAuth(&key->handle.auth, &sens->sensitiveArea.authValue);

    return rc;
}

int wolfTPM2_LoadRsaPublicKey_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* rsaPub, word32 rsaPubSz, word32 exponent,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg)
{
    TPM2B_PUBLIC pub;

    if (dev == NULL || key == NULL || rsaPub == NULL)
        return BAD_FUNC_ARG;
    if (rsaPubSz > sizeof(pub.publicArea.unique.rsa.buffer))
        return BUFFER_E;

    /* To support TPM hardware and firmware versions that do not allow
        small exponents */
#ifndef WOLFTPM_NO_SOFTWARE_RSA
    /* The TPM reference implementation does not support an exponent size
       smaller than 7 nor does it allow keys to be created on the TPM with a
       public exponent less than 2^16 + 1. */
    if (exponent < 7) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM based RSA with exponent %u not allowed! Using soft RSA\n",
            exponent);
    #endif
        return TPM_RC_KEY;
    }
#endif

    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_RSA;
    /* make sure nameAlg is set for ticket */
    pub.publicArea.nameAlg = WOLFTPM2_WRAP_DIGEST;
    pub.publicArea.objectAttributes = (TPMA_OBJECT_sign | TPMA_OBJECT_decrypt |
        TPMA_OBJECT_userWithAuth | TPMA_OBJECT_noDA | TPMA_OBJECT_stClear);
    pub.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    pub.publicArea.parameters.rsaDetail.keyBits = rsaPubSz * 8;
    pub.publicArea.parameters.rsaDetail.exponent = exponent;
    pub.publicArea.parameters.rsaDetail.scheme.scheme = scheme;
    pub.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = hashAlg;
    pub.publicArea.unique.rsa.size = rsaPubSz;
    XMEMCPY(pub.publicArea.unique.rsa.buffer, rsaPub, rsaPubSz);

    return wolfTPM2_LoadPublicKey(dev, key, &pub);
}

int wolfTPM2_LoadRsaPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* rsaPub, word32 rsaPubSz, word32 exponent)
{
    return wolfTPM2_LoadRsaPublicKey_ex(dev, key, rsaPub, rsaPubSz, exponent,
        TPM_ALG_NULL, TPM_ALG_NULL);
}

int wolfTPM2_ImportRsaPrivateKeySeed(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEYBLOB* keyBlob, const byte* rsaPub,
    word32 rsaPubSz, word32 exponent, const byte* rsaPriv, word32 rsaPrivSz,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg, TPMA_OBJECT attributes,
    byte* seed, word32 seedSz)
{
    TPM2B_PUBLIC pub;
    TPM2B_SENSITIVE sens;
    word32 digestSz;

    if (dev == NULL || keyBlob == NULL || rsaPub == NULL || rsaPriv == NULL)
        return BAD_FUNC_ARG;
    if (rsaPubSz > sizeof(pub.publicArea.unique.rsa.buffer))
        return BUFFER_E;
    if (rsaPrivSz > sizeof(sens.sensitiveArea.sensitive.rsa.buffer))
        return BUFFER_E;

    /* Set up public key */
    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_RSA;
    pub.publicArea.nameAlg = WOLFTPM2_WRAP_DIGEST;
    pub.publicArea.objectAttributes = attributes;
    pub.publicArea.parameters.rsaDetail.keyBits = rsaPubSz * 8;
    pub.publicArea.parameters.rsaDetail.exponent = exponent;
    pub.publicArea.parameters.rsaDetail.scheme.scheme = scheme;
    pub.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = hashAlg;
    pub.publicArea.unique.rsa.size = rsaPubSz;
    XMEMCPY(pub.publicArea.unique.rsa.buffer, rsaPub, rsaPubSz);

    /* For fixedParent or (decrypt and restricted) enable symmetric */
    if ((attributes & TPMA_OBJECT_fixedParent) ||
           ((attributes & TPMA_OBJECT_decrypt) &&
            (attributes & TPMA_OBJECT_restricted))) {
        pub.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
        pub.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        pub.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else {
        pub.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    }

    /* Set up private key */
    XMEMSET(&sens, 0, sizeof(sens));
    sens.sensitiveArea.sensitiveType = TPM_ALG_RSA;
    if (keyBlob->handle.auth.size > 0) {
        sens.sensitiveArea.authValue.size = keyBlob->handle.auth.size;
        XMEMCPY(sens.sensitiveArea.authValue.buffer, keyBlob->handle.auth.buffer,
            keyBlob->handle.auth.size);
    }
    sens.sensitiveArea.sensitive.rsa.size = rsaPrivSz;
    XMEMCPY(sens.sensitiveArea.sensitive.rsa.buffer, rsaPriv, rsaPrivSz);

    /* Use Seed */
    digestSz = TPM2_GetHashDigestSize(pub.publicArea.nameAlg);
    if (seed != NULL) {
        /* use custom seed */
        if (seedSz != digestSz) {
        #ifdef DEBUG_WOLFTPM
            printf("Import RSA seed size invalid! %d != %d\n",
                seedSz, digestSz);
        #endif
            return BAD_FUNC_ARG;
        }
        sens.sensitiveArea.seedValue.size = seedSz;
        XMEMCPY(sens.sensitiveArea.seedValue.buffer, seed, seedSz);
    }
    else {
        /* assign random seed */
        sens.sensitiveArea.seedValue.size = digestSz;
        TPM2_GetNonce(sens.sensitiveArea.seedValue.buffer,
            sens.sensitiveArea.seedValue.size);
    }

    return wolfTPM2_ImportPrivateKey(dev, parentKey, keyBlob, &pub, &sens);
}
int wolfTPM2_ImportRsaPrivateKey(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEYBLOB* keyBlob, const byte* rsaPub,
    word32 rsaPubSz, word32 exponent, const byte* rsaPriv, word32 rsaPrivSz,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg)
{
    TPMA_OBJECT attributes = (TPMA_OBJECT_sign | TPMA_OBJECT_decrypt |
        TPMA_OBJECT_userWithAuth | TPMA_OBJECT_noDA);
    return wolfTPM2_ImportRsaPrivateKeySeed(dev, parentKey, keyBlob,
        rsaPub, rsaPubSz, exponent, rsaPriv, rsaPrivSz, scheme, hashAlg,
        attributes, NULL, 0);
}

int wolfTPM2_LoadRsaPrivateKey_ex(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEY* key, const byte* rsaPub,
    word32 rsaPubSz, word32 exponent, const byte* rsaPriv, word32 rsaPrivSz,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg)
{
    int rc;
    WOLFTPM2_KEYBLOB keyBlob;

    if (dev == NULL || key == NULL || rsaPub == NULL || rsaPriv == NULL)
        return BAD_FUNC_ARG;

    XMEMCPY(&keyBlob, key, sizeof(WOLFTPM2_KEY));
    rc = wolfTPM2_ImportRsaPrivateKey(dev, parentKey, &keyBlob, rsaPub, rsaPubSz,
        exponent, rsaPriv, rsaPrivSz, scheme, hashAlg);
    if (rc == 0) {
        rc = wolfTPM2_LoadKey(dev, &keyBlob,
            (WOLFTPM2_HANDLE*)&parentKey->handle);
    }

    /* return loaded key */
    wolfTPM2_CopyKeyFromBlob(key, &keyBlob);

    return rc;
}

int wolfTPM2_LoadRsaPrivateKey(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEY* key, const byte* rsaPub, word32 rsaPubSz, word32 exponent,
    const byte* rsaPriv, word32 rsaPrivSz)
{
    return wolfTPM2_LoadRsaPrivateKey_ex(dev, parentKey, key, rsaPub, rsaPubSz,
        exponent, rsaPriv, rsaPrivSz, TPM_ALG_NULL, TPM_ALG_NULL);
}

int wolfTPM2_LoadEccPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key, int curveId,
    const byte* eccPubX, word32 eccPubXSz, const byte* eccPubY, word32 eccPubYSz)
{
    TPM2B_PUBLIC pub;

    if (dev == NULL || key == NULL || eccPubX == NULL || eccPubY == NULL)
        return BAD_FUNC_ARG;
    if (eccPubXSz > sizeof(pub.publicArea.unique.ecc.x.buffer))
        return BUFFER_E;
    if (eccPubYSz > sizeof(pub.publicArea.unique.ecc.y.buffer))
        return BUFFER_E;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_ECC;
    /* make sure nameAlg is set for ticket */
    pub.publicArea.nameAlg = WOLFTPM2_WRAP_DIGEST;
    pub.publicArea.objectAttributes = TPMA_OBJECT_sign | TPMA_OBJECT_noDA;
    pub.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    pub.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    pub.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
        WOLFTPM2_WRAP_DIGEST;
    pub.publicArea.parameters.eccDetail.curveID = curveId;
    pub.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    pub.publicArea.unique.ecc.x.size = eccPubXSz;
    XMEMCPY(pub.publicArea.unique.ecc.x.buffer, eccPubX, eccPubXSz);
    pub.publicArea.unique.ecc.y.size = eccPubYSz;
    XMEMCPY(pub.publicArea.unique.ecc.y.buffer, eccPubY, eccPubYSz);

    return wolfTPM2_LoadPublicKey(dev, key, &pub);
}

int wolfTPM2_ImportEccPrivateKeySeed(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEYBLOB* keyBlob, int curveId,
    const byte* eccPubX, word32 eccPubXSz,
    const byte* eccPubY, word32 eccPubYSz,
    const byte* eccPriv, word32 eccPrivSz,
    TPMA_OBJECT attributes, byte* seed, word32 seedSz)
{
    TPM2B_PUBLIC pub;
    TPM2B_SENSITIVE sens;
    word32 digestSz;

    if (dev == NULL || keyBlob == NULL || eccPubX == NULL || eccPubY == NULL ||
        eccPriv == NULL) {
        return BAD_FUNC_ARG;
    }
    if (eccPubXSz > sizeof(pub.publicArea.unique.ecc.x.buffer))
        return BUFFER_E;
    if (eccPubYSz > sizeof(pub.publicArea.unique.ecc.y.buffer))
        return BUFFER_E;
    if (eccPrivSz > sizeof(sens.sensitiveArea.sensitive.ecc.buffer))
        return BUFFER_E;

    /* Set up public key */
    XMEMSET(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM_ALG_ECC;
    pub.publicArea.nameAlg = WOLFTPM2_WRAP_DIGEST;
    pub.publicArea.objectAttributes = attributes;
    pub.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    /* if both sign and decrypt are set then must use NULL algorithm */
    pub.publicArea.parameters.eccDetail.scheme.scheme =
        ((attributes & TPMA_OBJECT_sign) &&
         (attributes & TPMA_OBJECT_decrypt)) ?
            TPM_ALG_NULL : TPM_ALG_ECDSA;
    pub.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
        WOLFTPM2_WRAP_DIGEST;
    pub.publicArea.parameters.eccDetail.curveID = curveId;
    pub.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    pub.publicArea.unique.ecc.x.size = eccPubXSz;
    XMEMCPY(pub.publicArea.unique.ecc.x.buffer, eccPubX, eccPubXSz);
    pub.publicArea.unique.ecc.y.size = eccPubYSz;
    XMEMCPY(pub.publicArea.unique.ecc.y.buffer, eccPubY, eccPubYSz);

    /* Set up private key */
    XMEMSET(&sens, 0, sizeof(sens));
    sens.sensitiveArea.sensitiveType = TPM_ALG_ECC;
    if (keyBlob->handle.auth.size > 0) {
        sens.sensitiveArea.authValue.size = keyBlob->handle.auth.size;
        XMEMCPY(sens.sensitiveArea.authValue.buffer, keyBlob->handle.auth.buffer,
            keyBlob->handle.auth.size);
    }
    sens.sensitiveArea.sensitive.ecc.size = eccPrivSz;
    XMEMCPY(sens.sensitiveArea.sensitive.ecc.buffer, eccPriv, eccPrivSz);

    /* Use Seed */
    digestSz = TPM2_GetHashDigestSize(pub.publicArea.nameAlg);
    if (seed != NULL) {
        /* use custom seed */
        if (seedSz != digestSz) {
        #ifdef DEBUG_WOLFTPM
            printf("Import ECC seed size invalid! %d != %d\n",
                seedSz, digestSz);
        #endif
            return BAD_FUNC_ARG;
        }
        sens.sensitiveArea.seedValue.size = seedSz;
        XMEMCPY(sens.sensitiveArea.seedValue.buffer, seed, seedSz);
    }
    else {
        /* assign random seed */
        sens.sensitiveArea.seedValue.size = digestSz;
        TPM2_GetNonce(sens.sensitiveArea.seedValue.buffer,
            sens.sensitiveArea.seedValue.size);
    }

    return wolfTPM2_ImportPrivateKey(dev, parentKey, keyBlob, &pub, &sens);
}

int wolfTPM2_ImportEccPrivateKey(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEYBLOB* keyBlob, int curveId,
    const byte* eccPubX, word32 eccPubXSz,
    const byte* eccPubY, word32 eccPubYSz,
    const byte* eccPriv, word32 eccPrivSz)
{
    TPMA_OBJECT attributes = (TPMA_OBJECT_sign | TPMA_OBJECT_decrypt |
        TPMA_OBJECT_userWithAuth | TPMA_OBJECT_noDA);
    return wolfTPM2_ImportEccPrivateKeySeed(dev, parentKey, keyBlob, curveId,
        eccPubX, eccPubXSz, eccPubY, eccPubYSz, eccPriv, eccPrivSz, attributes,
        NULL, 0);
}

int wolfTPM2_LoadEccPrivateKey(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEY* key, int curveId,
    const byte* eccPubX, word32 eccPubXSz,
    const byte* eccPubY, word32 eccPubYSz,
    const byte* eccPriv, word32 eccPrivSz)
{
    int rc;
    WOLFTPM2_KEYBLOB keyBlob;

    if (dev == NULL || key == NULL || eccPubX == NULL || eccPubY == NULL ||
        eccPriv == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(&keyBlob, key, sizeof(WOLFTPM2_KEY));
    rc = wolfTPM2_ImportEccPrivateKey(dev, parentKey, &keyBlob, curveId,
        eccPubX, eccPubXSz, eccPubY, eccPubYSz, eccPriv, eccPrivSz);
    if (rc == 0) {
        rc = wolfTPM2_LoadKey(dev, &keyBlob,
            (WOLFTPM2_HANDLE*)&parentKey->handle);
    }

    /* return loaded key */
    wolfTPM2_CopyKeyFromBlob(key, &keyBlob);

    return rc;
}

int wolfTPM2_ReadPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM_HANDLE handle)
{
    int rc;
    ReadPublic_In  readPubIn;
    ReadPublic_Out readPubOut;

    if (dev == NULL || key == NULL)
        return BAD_FUNC_ARG;

    /* Read public key */
    XMEMSET(&readPubIn, 0, sizeof(readPubIn));
    readPubIn.objectHandle = handle;
    rc = TPM2_ReadPublic(&readPubIn, &readPubOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_ReadPublic failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    key->handle.hndl = readPubIn.objectHandle;
    wolfTPM2_CopySymmetric(&key->handle.symmetric,
            &readPubOut.outPublic.publicArea.parameters.asymDetail.symmetric);
    wolfTPM2_CopyName(&key->handle.name, &readPubOut.name);
    wolfTPM2_CopyPub(&key->pub, &readPubOut.outPublic);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_ReadPublic Handle 0x%x: pub %d, name %d, qualifiedName %d\n",
        (word32)readPubIn.objectHandle,
        readPubOut.outPublic.size, readPubOut.name.size,
        readPubOut.qualifiedName.size);
#endif

    return rc;
}

#ifndef WOLFTPM2_NO_WOLFCRYPT

#ifndef NO_ASN
#ifndef NO_RSA
int wolfTPM2_DecodeRsaDer(const byte* der, word32 derSz,
    TPM2B_PUBLIC* pub, TPM2B_SENSITIVE* sens, TPMA_OBJECT attributes)
{
    int rc = 0;
    RsaKey key[1];
    word32 idx = 0;
    word32 e = 0;
    byte n[RSA_MAX_SIZE / 8];
    byte d[RSA_MAX_SIZE / 8];
    byte p[RSA_MAX_SIZE / 8];
    byte q[RSA_MAX_SIZE / 8];
    word32  eSz = (word32)sizeof(e);
    word32  nSz = (word32)sizeof(n);
    word32  dSz = (word32)sizeof(d);
    word32  pSz = (word32)sizeof(p);
    word32  qSz = (word32)sizeof(q);
    int isPrivateKey = 0;

    XMEMSET(n, 0, sizeof(n));
    XMEMSET(d, 0, sizeof(d));
    XMEMSET(p, 0, sizeof(p));
    XMEMSET(q, 0, sizeof(q));

    if (attributes == 0) {
        attributes = (TPMA_OBJECT_restricted |
                      TPMA_OBJECT_sensitiveDataOrigin |
                      TPMA_OBJECT_sign |
                      TPMA_OBJECT_userWithAuth |
                      TPMA_OBJECT_noDA);
        if (sens != NULL) {
            attributes |= TPMA_OBJECT_decrypt;
        }
    }

    rc = wc_InitRsaKey(key, NULL);
    if (rc == 0) {
        idx = 0;
        rc = wc_RsaPrivateKeyDecode(der, &idx, key, derSz);
        if (rc == 0) {
            isPrivateKey = 1;
        }
        else {
            idx = 0;
            rc = wc_RsaPublicKeyDecode(der, &idx, key, derSz);
        }
        if (rc == 0) {
            if (isPrivateKey)
                rc = wc_RsaExportKey(key, (byte*)&e, &eSz, n, &nSz, d, &dSz,
                    p, &pSz, q, &qSz);
            else
                rc = wc_RsaFlattenPublicKey(key, (byte*)&e, &eSz, n, &nSz);
        }
        if (rc == 0 && nSz > sizeof(pub->publicArea.unique.rsa.buffer))
            rc = BUFFER_E;
        if (rc == 0 && sens != NULL && isPrivateKey &&
                qSz > sizeof(sens->sensitiveArea.sensitive.rsa.buffer))
            rc = BUFFER_E;
        if (rc == 0) {
            /* Set up public key */
            pub->publicArea.type = TPM_ALG_RSA;
            pub->publicArea.nameAlg = WOLFTPM2_WRAP_DIGEST;
            pub->publicArea.objectAttributes = attributes;
            pub->publicArea.parameters.rsaDetail.keyBits = nSz * 8;
            pub->publicArea.parameters.rsaDetail.exponent = e;
            pub->publicArea.parameters.rsaDetail.scheme.scheme =
                (attributes & TPMA_OBJECT_sign) ? TPM_ALG_RSASSA : TPM_ALG_NULL;
            pub->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg =
                WOLFTPM2_WRAP_DIGEST;
            pub->publicArea.unique.rsa.size = nSz;
            XMEMCPY(pub->publicArea.unique.rsa.buffer, n, nSz);

            /* For fixedParent or (decrypt and restricted) enable symmetric */
            if ((attributes & TPMA_OBJECT_fixedParent) ||
                ((attributes & TPMA_OBJECT_decrypt) &&
                    (attributes & TPMA_OBJECT_restricted))) {
                pub->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
                pub->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
                pub->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
            }
            else {
                pub->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
            }

            /* Set up private key */
            if (sens != NULL && isPrivateKey) {
                sens->sensitiveArea.sensitiveType = TPM_ALG_RSA;
                sens->sensitiveArea.sensitive.rsa.size = qSz;
                XMEMCPY(sens->sensitiveArea.sensitive.rsa.buffer, q, qSz);
            }
        }
        wc_FreeRsaKey(key);
    }

    return rc;
}
#endif
#ifdef HAVE_ECC
int wolfTPM2_DecodeEccDer(const byte* der, word32 derSz, TPM2B_PUBLIC* pub,
    TPM2B_SENSITIVE* sens, TPMA_OBJECT attributes)
{
    int rc;
    int curveId = 0;
    word32 idx;
    ecc_key key[1];
    byte    d[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
    byte    qx[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
    byte    qy[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
    word32  dSz = sizeof(d);
    word32  qxSz = sizeof(qx);
    word32  qySz = sizeof(qy);
    int isPrivateKey = 0;

    XMEMSET(d, 0, sizeof(d));
    XMEMSET(qx, 0, sizeof(qx));
    XMEMSET(qy, 0, sizeof(qy));

    if (attributes == 0) {
        attributes = (TPMA_OBJECT_restricted |
                      TPMA_OBJECT_sensitiveDataOrigin |
                      TPMA_OBJECT_sign |
                      TPMA_OBJECT_userWithAuth |
                      TPMA_OBJECT_noDA);
        if (sens != NULL) {
            attributes |= TPMA_OBJECT_decrypt;
        }
    }

    rc = wc_ecc_init(key);
    if (rc == 0) {
        idx = 0;
        rc = wc_EccPrivateKeyDecode(der, &idx, key, derSz);
        if (rc == 0) {
            isPrivateKey = 1;
        }
        else {
            idx = 0;
            rc = wc_EccPublicKeyDecode(der, &idx, key, derSz);
        }
        if (rc == 0) {
            curveId = TPM2_GetTpmCurve(key->dp->id);

            if (isPrivateKey)
                rc = wc_ecc_export_private_raw(key, qx, &qxSz, qy, &qySz, d, &dSz);
            else
                rc = wc_ecc_export_public_raw(key, qx, &qxSz, qy, &qySz);
        }
        if (rc == 0 && qxSz > sizeof(pub->publicArea.unique.ecc.x.buffer))
            rc = BUFFER_E;
        if (rc == 0 && qySz > sizeof(pub->publicArea.unique.ecc.y.buffer))
            rc = BUFFER_E;
        if (rc == 0 && sens != NULL && isPrivateKey &&
                dSz > sizeof(sens->sensitiveArea.sensitive.ecc.buffer))
            rc = BUFFER_E;
        if (rc == 0) {
            /* Set up public key */
            pub->publicArea.type = TPM_ALG_ECC;
            pub->publicArea.nameAlg = WOLFTPM2_WRAP_DIGEST;
            pub->publicArea.objectAttributes = attributes;
            pub->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
            pub->publicArea.parameters.eccDetail.scheme.scheme =
                (attributes & TPMA_OBJECT_sign) ? TPM_ALG_ECDSA : TPM_ALG_NULL;
            pub->publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
                WOLFTPM2_WRAP_DIGEST;
            pub->publicArea.parameters.eccDetail.curveID = curveId;
            pub->publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
            pub->publicArea.unique.ecc.x.size = qxSz;
            XMEMCPY(pub->publicArea.unique.ecc.x.buffer, qx, qxSz);
            pub->publicArea.unique.ecc.y.size = qySz;
            XMEMCPY(pub->publicArea.unique.ecc.y.buffer, qy, qySz);

            /* For fixedParent or (decrypt and restricted) enable symmetric */
            if ((attributes & TPMA_OBJECT_fixedParent) ||
                ((attributes & TPMA_OBJECT_decrypt) &&
                    (attributes & TPMA_OBJECT_restricted))) {
                pub->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
                pub->publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
                pub->publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
            }
            else {
                pub->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
            }

            /* Set up private key */
            if (sens != NULL && isPrivateKey) {
                sens->sensitiveArea.sensitiveType = TPM_ALG_ECC;
                sens->sensitiveArea.sensitive.ecc.size = dSz;
                XMEMCPY(sens->sensitiveArea.sensitive.ecc.buffer, d, dSz);
            }
        }

        wc_ecc_free(key);
    }

    return rc;
}
#endif /* HAVE_ECC */

int wolfTPM2_ExportPublicKeyBuffer(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    int encodingType, byte* out, word32* outSz)
{
    int rc;
    word32 derSz = 0;
    union keyUnion {
    #ifndef NO_RSA
        RsaKey rsa;
    #endif
    #ifdef HAVE_ECC
        ecc_key ecc;
    #endif
    } key;

    if (dev == NULL || tpmKey == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&key, 0, sizeof(key));

    /* determine the type of key in WOLFTPM2_KEY */
    if (tpmKey->pub.publicArea.type == TPM_ALG_ECC) {
    #if defined(HAVE_ECC) && \
        defined(HAVE_ECC_KEY_IMPORT) && defined(HAVE_ECC_KEY_EXPORT)
        rc = wc_ecc_init(&key.ecc);
        if (rc == 0) {
            /* load public portion of key into wolf ECC Key */
            rc = wolfTPM2_EccKey_TpmToWolf(dev, tpmKey, &key.ecc);
            if (rc == 0) {
                rc = wc_EccPublicKeyToDer(&key.ecc, out, *outSz, 1);
                if (rc > 0) {
                    derSz = rc;
                    rc = 0;
                }
                else {
                    rc = BUFFER_E;
                }
            }
        }
    #else
        rc = NOT_COMPILED_IN;
    #endif
    }
    else if (tpmKey->pub.publicArea.type == TPM_ALG_RSA) {
        /* RSA public key export only enabled with:
         * cert gen, key gen or openssl extra */
    #if !defined(NO_RSA) && \
        (defined(WOLFSSL_CERT_GEN) || defined(OPENSSL_EXTRA) || \
         defined(WOLFSSL_KEY_GEN))
        rc = wc_InitRsaKey(&key.rsa, NULL);
        if (rc == 0) {
            /* load public portion of key into wolf RSA Key */
            rc = wolfTPM2_RsaKey_TpmToWolf(dev, tpmKey, &key.rsa);
            if (rc == 0) {
                rc = wc_RsaKeyToPublicDer_ex(&key.rsa, out, *outSz, 1);
                if (rc > 0) {
                    derSz = rc;
                    rc = 0;
                }
                else {
                    rc = BUFFER_E;
                }
            }
        }
    #else
        rc = NOT_COMPILED_IN;
    #endif
    }
    else {
    #ifdef DEBUG_WOLFTPM
        printf("Invalid tpmKey type!\n");
    #endif
        rc = BAD_FUNC_ARG;
    }

    /* Optionally convert to PEM */
    if (rc == 0 && encodingType == ENCODING_TYPE_PEM) {
    #ifdef WOLFSSL_DER_TO_PEM
        WOLFTPM2_BUFFER tmp;
        if (derSz > (word32)sizeof(tmp.buffer)) {
            rc = BUFFER_E;
        }
        else {
            /* move DER to temp variable */
            tmp.size = derSz;
            XMEMCPY(tmp.buffer, out, derSz);
            XMEMSET(out, 0, *outSz);
            rc = wc_DerToPem(tmp.buffer, tmp.size, out, *outSz, PUBLICKEY_TYPE);
            if (rc > 0) {
                *outSz = rc;
                rc = 0;
            }
            else {
                rc = BUFFER_E;
            }
        }
    #else
        rc = NOT_COMPILED_IN;
    #endif
    }
    else if (rc == 0) {
        *outSz = derSz;
    }
    return rc;
}

int wolfTPM2_ImportPublicKeyBuffer(WOLFTPM2_DEV* dev, int keyType,
    WOLFTPM2_KEY* key, int encodingType, const char* input, word32 inSz,
    TPMA_OBJECT objectAttributes)
{
    int rc = 0;
    byte* derBuf;
    word32 derSz;

    if (dev == NULL || key == NULL || input == NULL || inSz == 0) {
        return BAD_FUNC_ARG;
    }

    if (encodingType == ENCODING_TYPE_PEM) {
    #ifdef WOLFTPM2_PEM_DECODE
        /* der size is base 64 decode length */
        derSz = inSz * 3 / 4 + 1;
        derBuf = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derBuf == NULL)
            return MEMORY_E;
        rc = wc_PubKeyPemToDer((byte*)input, inSz, derBuf, derSz);
        if (rc >= 0) {
            derSz = rc;
            rc = 0;
        }
    #else
        return NOT_COMPILED_IN;
    #endif
    }
    else { /* ASN.1 (DER) */
        derBuf = (byte*)input;
        derSz = inSz;
    }

    /* Handle DER Import */
    if (keyType == TPM_ALG_RSA) {
    #ifndef NO_RSA
        rc = wolfTPM2_DecodeRsaDer(derBuf, derSz, &key->pub, NULL, objectAttributes);
    #else
        rc = NOT_COMPILED_IN;
    #endif
    }
    else if (keyType == TPM_ALG_ECC) {
    #ifdef HAVE_ECC
        rc = wolfTPM2_DecodeEccDer(derBuf, derSz, &key->pub, NULL, objectAttributes);
    #else
        rc = NOT_COMPILED_IN;
    #endif
    }

#ifdef WOLFTPM2_PEM_DECODE
    if (derBuf != (byte*)input) {
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return rc;
}

int wolfTPM2_ImportPrivateKeyBuffer(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, int keyType, WOLFTPM2_KEYBLOB* keyBlob,
    int encodingType, const char* input, word32 inSz, const char* pass,
    TPMA_OBJECT objectAttributes, byte* seed, word32 seedSz)
{
    int rc = 0;
    byte* derBuf;
    word32 derSz;
    TPM2B_PUBLIC* pub;
    TPM2B_SENSITIVE sens;
    word32 digestSz;

    if (dev == NULL || keyBlob == NULL || input == NULL || inSz == 0) {
        return BAD_FUNC_ARG;
    }

    pub = &keyBlob->pub;
    XMEMSET(pub, 0, sizeof(*pub));
    XMEMSET(&sens, 0, sizeof(sens));

    if (encodingType == ENCODING_TYPE_PEM) {
    #ifdef WOLFTPM2_PEM_DECODE
        /* der size is base 64 decode length */
        derSz = inSz * 3 / 4 + 1;
        derBuf = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derBuf == NULL)
            return MEMORY_E;
        rc = wc_KeyPemToDer((byte*)input, inSz, derBuf, derSz, pass);
        if (rc >= 0) {
            derSz = rc;
            rc = 0;
        }
    #else
        (void)pass;
        return NOT_COMPILED_IN;
    #endif
    }
    else { /* ASN.1 (DER) */
        derBuf = (byte*)input;
        derSz = inSz;
    }

    /* Handle DER Import */
    if (keyType == TPM_ALG_RSA) {
    #ifndef NO_RSA
        rc = wolfTPM2_DecodeRsaDer(derBuf, derSz, pub, &sens, objectAttributes);
    #else
        rc = NOT_COMPILED_IN;
    #endif
    }
    else if (keyType == TPM_ALG_ECC) {
    #ifdef HAVE_ECC
        rc = wolfTPM2_DecodeEccDer(derBuf, derSz, pub, &sens, objectAttributes);
    #else
        rc = NOT_COMPILED_IN;
    #endif
    }

    if (rc == 0 && parentKey != NULL) {
        /* Setup private key */
        if (keyBlob->handle.auth.size > 0) {
            sens.sensitiveArea.authValue.size = keyBlob->handle.auth.size;
            XMEMCPY(sens.sensitiveArea.authValue.buffer,
                keyBlob->handle.auth.buffer, keyBlob->handle.auth.size);
        }

        /* Use Seed */
        digestSz = TPM2_GetHashDigestSize(pub->publicArea.nameAlg);
        if (seed != NULL) {
            /* use custom seed */
            if (seedSz != digestSz) {
            #ifdef DEBUG_WOLFTPM
                printf("Import %s seed size invalid! %d != %d\n",
                    TPM2_GetAlgName(keyType), seedSz, digestSz);
            #endif
                return BAD_FUNC_ARG;
            }
            sens.sensitiveArea.seedValue.size = seedSz;
            XMEMCPY(sens.sensitiveArea.seedValue.buffer, seed, seedSz);
        }
        else {
            /* assign random seed */
            sens.sensitiveArea.seedValue.size = digestSz;
            TPM2_GetNonce(sens.sensitiveArea.seedValue.buffer,
                sens.sensitiveArea.seedValue.size);
        }


        /* Import Private Key */
        rc = wolfTPM2_ImportPrivateKey(dev, parentKey, keyBlob, pub, &sens);
    }

#ifdef WOLFTPM2_PEM_DECODE
    if (derBuf != (byte*)input) {
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return rc;
}
#endif /* !NO_ASN */

#ifndef NO_RSA
#ifndef NO_ASN
int wolfTPM2_RsaPrivateKeyImportDer(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEYBLOB* keyBlob, const byte* input,
    word32 inSz, TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg)
{
    int rc = 0;
    int initRc = -1;
    RsaKey key[1];
    word32 idx = 0;
    word32  e;
    byte n[RSA_MAX_SIZE / 8];
    byte d[RSA_MAX_SIZE / 8];
    byte p[RSA_MAX_SIZE / 8];
    byte q[RSA_MAX_SIZE / 8];
    word32  eSz = (word32)sizeof(e);
    word32  nSz = (word32)sizeof(n);
    word32  dSz = (word32)sizeof(d);
    word32  pSz = (word32)sizeof(p);
    word32  qSz = (word32)sizeof(q);

    if (dev == NULL || parentKey == NULL || keyBlob == NULL || input == NULL ||
        inSz == 0) {
        rc = BAD_FUNC_ARG;
    }

    if (rc == 0)
        rc = initRc = wc_InitRsaKey(key, NULL);

    if (rc == 0)
        rc = wc_RsaPrivateKeyDecode(input, &idx, key, inSz);

    if (rc == 0) {
        rc = wc_RsaExportKey(key, (byte*)&e, &eSz, n, &nSz, d, &dSz, p, &pSz, q,
            &qSz);
    }

    if (rc == 0) {
        rc = wolfTPM2_ImportRsaPrivateKey(dev, parentKey, keyBlob, n, nSz, e, q,
            qSz, scheme, hashAlg);
    }

    if (initRc == 0)
        wc_FreeRsaKey(key);

    return rc;
}
#endif /* !NO_ASN */

#ifdef WOLFTPM2_PEM_DECODE
int wolfTPM2_RsaPrivateKeyImportPem(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEYBLOB* keyBlob,
    const char* input, word32 inSz, char* pass,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg)
{
    (void)scheme;
    (void)hashAlg;
    return wolfTPM2_ImportPrivateKeyBuffer(dev, parentKey, TPM_ALG_RSA, keyBlob,
        ENCODING_TYPE_PEM, input, inSz, pass, 0, NULL, 0);
}
#endif /* WOLFTPM2_PEM_DECODE */


int wolfTPM2_RsaKey_TpmToWolf(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    RsaKey* wolfKey)
{
    int rc;
    word32  exponent;
    byte    e[sizeof(exponent)];
    byte    n[WOLFTPM2_WRAP_RSA_KEY_BITS / 8];
    word32  eSz = sizeof(e);
    word32  nSz = sizeof(n);

    if (dev == NULL || tpmKey == NULL || wolfKey == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(e, 0, sizeof(e));
    XMEMSET(n, 0, sizeof(n));

    /* load exponent */
    exponent = tpmKey->pub.publicArea.parameters.rsaDetail.exponent;
    if (exponent == 0)
        exponent = RSA_DEFAULT_PUBLIC_EXPONENT;
    e[3] = (exponent >> 24) & 0xFF;
    e[2] = (exponent >> 16) & 0xFF;
    e[1] = (exponent >> 8)  & 0xFF;
    e[0] =  exponent        & 0xFF;
    eSz = e[3] ? 4 : e[2] ? 3 : e[1] ? 2 : e[0] ? 1 : 0; /* calc size */

    /* load public key */
    nSz = tpmKey->pub.publicArea.unique.rsa.size;
    XMEMCPY(n, tpmKey->pub.publicArea.unique.rsa.buffer, nSz);

    /* load public key portion into wolf RsaKey */
    rc = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz, wolfKey);

    return rc;
}

int wolfTPM2_RsaKey_TpmToPemPub(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    byte* pem, word32* pemSz)
{
    return wolfTPM2_ExportPublicKeyBuffer(dev, tpmKey,
        ENCODING_TYPE_PEM, pem, pemSz);
}

static word32 wolfTPM2_RsaKey_Exponent(byte* e, word32 eSz)
{
    word32 exponent = 0, i;
    for (i=0; i<eSz && i<sizeof(word32); i++) {
        exponent |= ((word32)e[i]) << (i*8);
    }
    return exponent;
}

int wolfTPM2_RsaKey_WolfToTpm_ex(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* parentKey,
    RsaKey* wolfKey, WOLFTPM2_KEY* tpmKey)
{
    int rc;
    word32  exponent;
    byte    e[sizeof(exponent)];
    byte    n[WOLFTPM2_WRAP_RSA_KEY_BITS / 8];
    word32  eSz = sizeof(e);
    word32  nSz = sizeof(n);

    if (dev == NULL || tpmKey == NULL || wolfKey == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(e, 0, sizeof(e));
    XMEMSET(n, 0, sizeof(n));

    if (parentKey && wolfKey->type == RSA_PRIVATE) {
        byte    d[WOLFTPM2_WRAP_RSA_KEY_BITS / 8];
        byte    p[WOLFTPM2_WRAP_RSA_KEY_BITS / 8];
        byte    q[WOLFTPM2_WRAP_RSA_KEY_BITS / 8];
        word32  dSz = sizeof(d);
        word32  pSz = sizeof(p);
        word32  qSz = sizeof(q);

        XMEMSET(d, 0, sizeof(d));
        XMEMSET(p, 0, sizeof(p));
        XMEMSET(q, 0, sizeof(q));

        /* export the raw private and public RSA as unsigned binary */
        PRIVATE_KEY_UNLOCK();
        rc = wc_RsaExportKey(wolfKey, e, &eSz, n, &nSz,
            d, &dSz, p, &pSz, q, &qSz);
        PRIVATE_KEY_LOCK();
        if (rc == 0) {
            exponent = wolfTPM2_RsaKey_Exponent(e, eSz);
            rc = wolfTPM2_LoadRsaPrivateKey(dev, parentKey, tpmKey, n, nSz,
                exponent, q, qSz);
        }

        /* not used */
        (void)p;
    }
    else {
        /* export the raw public RSA portion */
        rc = wc_RsaFlattenPublicKey(wolfKey, e, &eSz, n, &nSz);
        if (rc == 0) {
            exponent = wolfTPM2_RsaKey_Exponent(e, eSz);
            rc = wolfTPM2_LoadRsaPublicKey(dev, tpmKey, n, nSz, exponent);
        }
    }

    return rc;
}
int wolfTPM2_RsaKey_WolfToTpm(WOLFTPM2_DEV* dev, RsaKey* wolfKey,
    WOLFTPM2_KEY* tpmKey)
{
    return wolfTPM2_RsaKey_WolfToTpm_ex(dev, NULL, wolfKey, tpmKey);
}

int wolfTPM2_RsaKey_PubPemToTpm(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    const byte* pem, word32 pemSz)
{
    int rc = TPM_RC_FAILURE;
#ifdef WOLFTPM2_PEM_DECODE
    RsaKey rsaKey;
#endif

    if (dev == NULL || tpmKey == NULL || pem == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFTPM2_PEM_DECODE
    /* Prepare wolfCrypt key structure */
    rc = wc_InitRsaKey(&rsaKey, NULL);
    if (rc == 0) {
        /* allocate buffer for DER */
        word32 derSz = pemSz; /* DER is always smaller */
        byte* derBuf = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derBuf == NULL) {
            rc = MEMORY_E;
        }
        if (rc == 0) {
            /* Convert PEM format key from file to DER - inline okay */
            rc = wc_PubKeyPemToDer(pem, pemSz, derBuf, derSz);
        }
        if (rc >= 0) {
            /* Convert DER to wolfCrypt file */
            word32 idx = 0;
            derSz = (word32)rc;
            rc = wc_RsaPublicKeyDecode(derBuf, &idx, &rsaKey, derSz);
        }
        if (rc == 0) {
            /* Load into the TPM */
            rc = wolfTPM2_RsaKey_WolfToTpm(dev, &rsaKey, tpmKey);
        }
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRsaKey(&rsaKey);
    }
#else
    (void)pemSz;
#endif

    return rc;
}
#endif /* !NO_RSA */

#ifdef HAVE_ECC
#ifdef HAVE_ECC_KEY_IMPORT
int wolfTPM2_EccKey_TpmToWolf(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    ecc_key* wolfKey)
{
    int rc, curve_id;
    byte    qx[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
    byte    qy[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
    word32  qxSz = sizeof(qx);
    word32  qySz = sizeof(qy);

    if (dev == NULL || tpmKey == NULL || wolfKey == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(qx, 0, sizeof(qx));
    XMEMSET(qy, 0, sizeof(qy));

    /* load curve type */
    curve_id = tpmKey->pub.publicArea.parameters.eccDetail.curveID;
    rc = TPM2_GetWolfCurve(curve_id);
    if (rc < 0)
        return rc;
    curve_id = rc;

    /* load public key */
    qxSz = tpmKey->pub.publicArea.unique.ecc.x.size;
    XMEMCPY(qx, tpmKey->pub.publicArea.unique.ecc.x.buffer, qxSz);
    qySz = tpmKey->pub.publicArea.unique.ecc.y.size;
    XMEMCPY(qy, tpmKey->pub.publicArea.unique.ecc.y.buffer, qySz);

    /* load public key portion into wolf ecc_key */
    rc = wc_ecc_import_unsigned(wolfKey, qx, qy, NULL, curve_id);

    return rc;
}
#endif /* HAVE_ECC_KEY_IMPORT */
#ifdef HAVE_ECC_KEY_EXPORT
int wolfTPM2_EccKey_WolfToTpm_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* parentKey,
    ecc_key* wolfKey, WOLFTPM2_KEY* tpmKey)
{
    int rc, curve_id = 0;
    byte    qx[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
    byte    qy[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
    word32  qxSz = sizeof(qx);
    word32  qySz = sizeof(qy);

    if (dev == NULL || tpmKey == NULL || wolfKey == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(tpmKey, 0, sizeof(*tpmKey));
    XMEMSET(qx, 0, sizeof(qx));
    XMEMSET(qy, 0, sizeof(qy));

    if (wolfKey->dp)
        curve_id = wolfKey->dp->id;

    rc = TPM2_GetTpmCurve(curve_id);
    if (rc < 0)
        return rc;
    curve_id = rc;
    rc = 0;

    if (parentKey && wolfKey->type != ECC_PUBLICKEY) {
        byte    d[WOLFTPM2_WRAP_ECC_KEY_BITS / 8];
        word32  dSz = sizeof(d);

        XMEMSET(d, 0, sizeof(d));

        if (wolfKey->type == ECC_PRIVATEKEY_ONLY) {
            /* compute public point without modifying incoming wolf key */
            int keySz = wc_ecc_size(wolfKey);
            ecc_point* point = wc_ecc_new_point();
            if (point == NULL) {
                rc = MEMORY_E;
            }
            if (rc == 0) {
            #ifdef ECC_TIMING_RESISTANT
                rc = wc_ecc_make_pub_ex(wolfKey, point, wolfKey->rng);
            #else
                rc = wc_ecc_make_pub(wolfKey, point);
            #endif
                if (rc == 0)
                    rc = wc_export_int(point->x, qx, &qxSz, keySz,
                        WC_TYPE_UNSIGNED_BIN);
                if (rc == 0)
                    rc = wc_export_int(point->y, qy, &qySz, keySz,
                        WC_TYPE_UNSIGNED_BIN);
                if (rc == 0)
                    rc = wc_ecc_export_private_only(wolfKey, d, &dSz);
                wc_ecc_del_point(point);
            }
        }
        else {
            /* export the raw private/public ECC portions */
            rc = wc_ecc_export_private_raw(wolfKey,
                qx, &qxSz,
                qy, &qySz,
                d, &dSz);
        }

        if (rc == 0) {
            rc = wolfTPM2_LoadEccPrivateKey(dev, parentKey, tpmKey, curve_id,
                qx, qxSz, qy, qySz, d, dSz);
        }
    }
    else {
        /* export the raw public ECC portion */
        rc = wc_ecc_export_public_raw(wolfKey, qx, &qxSz, qy, &qySz);
        if (rc == 0) {
            rc = wolfTPM2_LoadEccPublicKey(dev, tpmKey, curve_id, qx, qxSz,
                qy, qySz);
        }
    }

    return rc;
}
int wolfTPM2_EccKey_WolfToTpm(WOLFTPM2_DEV* dev, ecc_key* wolfKey,
    WOLFTPM2_KEY* tpmKey)
{
    return wolfTPM2_EccKey_WolfToTpm_ex(dev, NULL, wolfKey, tpmKey);
}

int wolfTPM2_EccKey_WolfToPubPoint(WOLFTPM2_DEV* dev, ecc_key* wolfKey,
    TPM2B_ECC_POINT* pubPoint)
{
    int rc;
    word32 xSz, ySz;

    if (dev == NULL || wolfKey == NULL || pubPoint == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(pubPoint, 0, sizeof(TPM2B_ECC_POINT));
    xSz = sizeof(pubPoint->point.x.buffer);;
    ySz = sizeof(pubPoint->point.y.buffer);;

    /* load wolf ECC public key into TPM2B_ECC_POINT */
    rc = wc_ecc_export_public_raw(wolfKey,
        pubPoint->point.x.buffer, &xSz,
        pubPoint->point.y.buffer, &ySz);
    if (rc == 0) {
        pubPoint->point.x.size = xSz;
        pubPoint->point.y.size = ySz;
    }

    return rc;
}
#endif /* HAVE_ECC_KEY_EXPORT */
#endif /* HAVE_ECC */
#endif /* !WOLFTPM2_NO_WOLFCRYPT */


/* primaryHandle must be owner or platform hierarchy */
/* Owner    Persistent Handle Range: 0x81000000 to 0x817FFFFF */
/* Platform Persistent Handle Range: 0x81800000 to 0x81FFFFFF */
int wolfTPM2_NVStoreKey(WOLFTPM2_DEV* dev, TPM_HANDLE primaryHandle,
    WOLFTPM2_KEY* key, TPM_HANDLE persistentHandle)
{
    int rc;
    EvictControl_In in;

    if (dev == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }
    if (primaryHandle == TPM_RH_OWNER &&
        (persistentHandle < PERSISTENT_FIRST ||
         persistentHandle > PERSISTENT_LAST)) {
        return BAD_FUNC_ARG;
    }
    if (primaryHandle == TPM_RH_PLATFORM &&
        (persistentHandle < PLATFORM_PERSISTENT ||
         persistentHandle > PERSISTENT_LAST)) {
        return BAD_FUNC_ARG;
    }

    /* if key is already persistent then just return success */
    if (key->handle.hndl == persistentHandle)
        return TPM_RC_SUCCESS;

    /* set session auth to blank */
    wolfTPM2_SetAuthPassword(dev, 0, NULL);

    /* Move key into NV to persist */
    XMEMSET(&in, 0, sizeof(in));
    in.auth = primaryHandle;
    in.objectHandle = key->handle.hndl;
    in.persistentHandle = persistentHandle;

    rc = TPM2_EvictControl(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef WOLFTPM_WINAPI
        if (rc == (int)TPM_E_COMMAND_BLOCKED) { /* 0x80280400 */
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_EvictControl (storing key to NV) not allowed on "
                   "Windows TBS (err 0x%x)\n", rc);
        #endif
            rc = TPM_RC_COMMAND_CODE;
        }
    #endif

    #ifdef DEBUG_WOLFTPM
        printf("TPM2_EvictControl failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_EvictControl Auth 0x%x, Key 0x%x, Persistent 0x%x\n",
        (word32)in.auth, (word32)in.objectHandle, (word32)in.persistentHandle);
#endif

    /* unload transient handle */
    wolfTPM2_UnloadHandle(dev, &key->handle);

    /* replace handle with persistent one */
    key->handle.hndl = persistentHandle;

    return rc;
}

int wolfTPM2_NVDeleteKey(WOLFTPM2_DEV* dev, TPM_HANDLE primaryHandle,
    WOLFTPM2_KEY* key)
{
    int rc;
    EvictControl_In in;

    if (dev == NULL || key == NULL || primaryHandle == 0) {
        return BAD_FUNC_ARG;
    }

    /* if key is not persistent then just return success */
    if (key->handle.hndl < PERSISTENT_FIRST ||
            key->handle.hndl > PERSISTENT_LAST)
        return TPM_RC_SUCCESS;

    /* remove key from NV */
    XMEMSET(&in, 0, sizeof(in));
    in.auth = primaryHandle;
    in.objectHandle = key->handle.hndl;
    in.persistentHandle = key->handle.hndl;

    rc = TPM2_EvictControl(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_EvictControl failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_EvictControl Auth 0x%x, Key 0x%x, Persistent 0x%x\n",
        (word32)in.auth, (word32)in.objectHandle, (word32)in.persistentHandle);
#endif

    /* indicate no handle */
    key->handle.hndl = TPM_RH_NULL;

    return rc;
}

/* sigAlg: TPM_ALG_RSASSA, TPM_ALG_RSAPSS, TPM_ALG_ECDSA or TPM_ALG_ECDAA */
/* hashAlg: TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384 or TPM_ALG_SHA512 */
int wolfTPM2_SignHashScheme(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* digest, int digestSz, byte* sig, int* sigSz,
    TPMI_ALG_SIG_SCHEME sigAlg, TPMI_ALG_HASH hashAlg)
{
    int rc;
    Sign_In  signIn;
    Sign_Out signOut;
    int curveSize = 0;
    int sigOutSz = 0;

    if (dev == NULL || key == NULL || digest == NULL || sig == NULL ||
                                                            sigSz == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        /* get curve size */
        curveSize = wolfTPM2_GetCurveSize(
            key->pub.publicArea.parameters.eccDetail.curveID);
        if (curveSize <= 0) {
            return BAD_FUNC_ARG;
        }
    }

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &key->handle);

    XMEMSET(&signIn, 0, sizeof(signIn));
    signIn.keyHandle = key->handle.hndl;
    signIn.digest.size = digestSz;
    XMEMCPY(signIn.digest.buffer, digest, signIn.digest.size);
    signIn.inScheme.scheme = sigAlg;
    signIn.inScheme.details.any.hashAlg = hashAlg;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    rc = TPM2_Sign(&signIn, &signOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Sign failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        /* Assemble R and S into signature (R then S) */
        sigOutSz = signOut.signature.signature.ecdsa.signatureR.size +
                   signOut.signature.signature.ecdsa.signatureS.size;
        if (sigOutSz > *sigSz) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_Sign: ECC result truncated %d -> %d\n",
                sigOutSz, *sigSz);
        #endif
            sigOutSz = *sigSz;
        }
        XMEMCPY(sig,
                signOut.signature.signature.ecdsa.signatureR.buffer,
                signOut.signature.signature.ecdsa.signatureR.size);
        XMEMCPY(sig + signOut.signature.signature.ecdsa.signatureR.size,
                signOut.signature.signature.ecdsa.signatureS.buffer,
                signOut.signature.signature.ecdsa.signatureS.size);
    }
    else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        /* RSA signature size and buffer (with padding depending on scheme) */
        sigOutSz = signOut.signature.signature.rsassa.sig.size;
        if (sigOutSz > *sigSz) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_Sign: RSA result truncated %d -> %d\n",
                sigOutSz, *sigSz);
        #endif
            sigOutSz = *sigSz;
        }
        XMEMCPY(sig, signOut.signature.signature.rsassa.sig.buffer, sigOutSz);
    }
    *sigSz = sigOutSz;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Sign: %s %d\n",
        TPM2_GetAlgName(signIn.inScheme.scheme), *sigSz);
#endif

    return rc;
}

int wolfTPM2_SignHash(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* digest, int digestSz, byte* sig, int* sigSz)
{
    TPM_ALG_ID sigAlg = TPM_ALG_NULL;
    TPMI_ALG_HASH hashAlg = WOLFTPM2_WRAP_DIGEST;

    if (dev == NULL || key == NULL || digest == NULL || sig == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        /* Keys that are created with sign and decrypt require scheme to be NULL,
         * but we must supply ECDSA and Hash Algorithm for signing */
        sigAlg = key->pub.publicArea.parameters.eccDetail.scheme.scheme;
        hashAlg = key->pub.publicArea.parameters.eccDetail.scheme.details.any.hashAlg;
        if (sigAlg == 0 || sigAlg == TPM_ALG_NULL) {
            sigAlg = TPM_ALG_ECDSA;
        }
        if (hashAlg == 0 || hashAlg == TPM_ALG_NULL) {
            if (digestSz == 64)
                hashAlg = TPM_ALG_SHA512;
            else if (digestSz == 48)
                hashAlg = TPM_ALG_SHA384;
            else if (digestSz == 32)
                hashAlg = TPM_ALG_SHA256;
        }
    }
    else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        sigAlg = key->pub.publicArea.parameters.rsaDetail.scheme.scheme;
        hashAlg = key->pub.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg;
    }

    return wolfTPM2_SignHashScheme(dev, key, digest, digestSz, sig, sigSz,
        sigAlg, hashAlg);

}

/* sigAlg: TPM_ALG_RSASSA, TPM_ALG_RSAPSS, TPM_ALG_ECDSA or TPM_ALG_ECDAA */
/* hashAlg: TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384 or TPM_ALG_SHA512 */
int wolfTPM2_VerifyHashTicket(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz,
    TPMI_ALG_SIG_SCHEME sigAlg, TPMI_ALG_HASH hashAlg,
    TPMT_TK_VERIFIED* checkTicket)
{
    int rc;
    VerifySignature_In  verifySigIn;
    VerifySignature_Out verifySigOut;
    int curveSize = 0;

    if (dev == NULL || key == NULL || digest == NULL || sig == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        if (sigAlg == TPM_ALG_NULL)
            sigAlg = key->pub.publicArea.parameters.eccDetail.scheme.scheme;

        /* get curve size */
        curveSize = wolfTPM2_GetCurveSize(
            key->pub.publicArea.parameters.eccDetail.curveID);
        if (curveSize <= 0 || sigSz < (curveSize * 2)) {
            return BAD_FUNC_ARG;
        }
        /* verify curve size cannot exceed buffer */
        if (curveSize > (int)sizeof(verifySigIn.signature.signature.ecdsa.signatureR.buffer))
            return BAD_FUNC_ARG;

        /* hash cannot be larger than key size for TPM */
        if (digestSz > curveSize)
            digestSz = curveSize;
    }
    else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        if (sigAlg == TPM_ALG_NULL)
            sigAlg = key->pub.publicArea.parameters.rsaDetail.scheme.scheme;
        if (sigSz > (int)sizeof(verifySigIn.signature.signature.rsassa.sig.buffer))
            return BAD_FUNC_ARG;
    }
    else {
        return BAD_FUNC_ARG;
    }

    /* verify input cannot exceed buffer */
    if (digestSz > (int)sizeof(verifySigIn.digest.buffer))
        digestSz = (int)sizeof(verifySigIn.digest.buffer);

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &key->handle);

    XMEMSET(&verifySigIn, 0, sizeof(verifySigIn));
    verifySigIn.keyHandle = key->handle.hndl;
    verifySigIn.digest.size = digestSz;
    XMEMCPY(verifySigIn.digest.buffer, digest, digestSz);
    verifySigIn.signature.sigAlg = sigAlg;
    verifySigIn.signature.signature.any.hashAlg = hashAlg;
    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        /* Signature is R then S */
        verifySigIn.signature.signature.ecdsa.signatureR.size = curveSize;
        XMEMCPY(verifySigIn.signature.signature.ecdsa.signatureR.buffer,
            sig, curveSize);
        verifySigIn.signature.signature.ecdsa.signatureS.size = curveSize;
        XMEMCPY(verifySigIn.signature.signature.ecdsa.signatureS.buffer,
            sig + curveSize, curveSize);
    }
    else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        verifySigIn.signature.signature.rsassa.sig.size = sigSz;
        XMEMCPY(verifySigIn.signature.signature.rsassa.sig.buffer, sig, sigSz);
    }

    XMEMSET(&verifySigOut, 0, sizeof(verifySigOut));
    rc = TPM2_VerifySignature(&verifySigIn, &verifySigOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_VerifySignature failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
    }
    else {
        /* optionally return ticket */
        if (checkTicket) {
            XMEMCPY(checkTicket, &verifySigOut.validation,
                sizeof(TPMT_TK_VERIFIED));
        }
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_VerifySignature: Tag %d\n", verifySigOut.validation.tag);
    #endif
    }
    return rc;
}

int wolfTPM2_VerifyHashScheme(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz,
    TPMI_ALG_SIG_SCHEME sigAlg, TPMI_ALG_HASH hashAlg)
{
    return wolfTPM2_VerifyHashTicket(dev, key, sig, sigSz, digest,
        digestSz, sigAlg, hashAlg, NULL);
}

int wolfTPM2_VerifyHash_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz,
    int hashAlg)
{
    return wolfTPM2_VerifyHashTicket(dev, key, sig, sigSz, digest,
        digestSz, TPM_ALG_NULL, hashAlg, NULL);
}

int wolfTPM2_VerifyHash(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz)
{
    return wolfTPM2_VerifyHashTicket(dev, key, sig, sigSz, digest, digestSz,
        TPM_ALG_NULL, WOLFTPM2_WRAP_DIGEST, NULL);
}

/* Generate ECC key-pair with NULL hierarchy and load (populates handle) */
int wolfTPM2_ECDHGenKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* ecdhKey, int curve_id,
    const byte* auth, int authSz)
{
    int rc;
    TPMT_PUBLIC publicTemplate;
    WOLFTPM2_HANDLE nullParent;

    if (dev == NULL || ecdhKey == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&nullParent, 0, sizeof(nullParent));
    nullParent.hndl = TPM_RH_NULL;

    /* Create and load ECC key for DH */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA,
        curve_id, TPM_ALG_ECDH);
    if (rc == 0) {
        rc = wolfTPM2_CreatePrimaryKey(dev, ecdhKey, TPM_RH_NULL,
            &publicTemplate, auth, authSz);
    }

    return rc;
}

/* Generate ephemeral key and compute Z (shared secret) */
/* One shot API using private key handle to generate key-pair and return
    pub-point and shared secret */
int wolfTPM2_ECDHGen(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* privKey,
    TPM2B_ECC_POINT* pubPoint, byte* out, int* outSz)
{
    int rc;
    ECDH_KeyGen_In  ecdhIn;
    ECDH_KeyGen_Out ecdhOut;
    int curveSize;

    if (dev == NULL || privKey == NULL || pubPoint == NULL || out == NULL ||
                                                                outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get curve size to verify output is large enough */
    curveSize = wolfTPM2_GetCurveSize(
        privKey->pub.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || *outSz < curveSize) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &privKey->handle);

    XMEMSET(&ecdhIn, 0, sizeof(ecdhIn));
    ecdhIn.keyHandle = privKey->handle.hndl;
    rc = TPM2_ECDH_KeyGen(&ecdhIn, &ecdhOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_ECDH_KeyGen failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    pubPoint->size = ecdhOut.pubPoint.size;
    wolfTPM2_CopyEccParam(&pubPoint->point.x, &ecdhOut.pubPoint.point.x);
    wolfTPM2_CopyEccParam(&pubPoint->point.y, &ecdhOut.pubPoint.point.y);
    *outSz = ecdhOut.zPoint.point.x.size;
    XMEMCPY(out, ecdhOut.zPoint.point.x.buffer, ecdhOut.zPoint.point.x.size);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_ECDH_KeyGen: zPt %d, pubPt %d\n",
        ecdhOut.zPoint.size,
        ecdhOut.pubPoint.size);
#endif

    return rc;
}

/* Compute Z (shared secret) using pubPoint and loaded private ECC key */
int wolfTPM2_ECDHGenZ(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* privKey,
    const TPM2B_ECC_POINT* pubPoint, byte* out, int* outSz)
{
    int rc;
    ECDH_ZGen_In  ecdhZIn;
    ECDH_ZGen_Out ecdhZOut;
    int curveSize;

    if (dev == NULL || privKey == NULL || pubPoint == NULL || out == NULL ||
                                                                outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get curve size to verify output is large enough */
    curveSize = wolfTPM2_GetCurveSize(
        privKey->pub.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || *outSz < curveSize) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &privKey->handle);

    XMEMSET(&ecdhZIn, 0, sizeof(ecdhZIn));
    ecdhZIn.keyHandle = privKey->handle.hndl;
    XMEMCPY(&ecdhZIn.inPoint.point, &pubPoint->point, sizeof(TPMS_ECC_POINT));
    rc = TPM2_ECDH_ZGen(&ecdhZIn, &ecdhZOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_ECDH_ZGen failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    *outSz = ecdhZOut.outPoint.point.x.size;
    XMEMCPY(out, ecdhZOut.outPoint.point.x.buffer,
        ecdhZOut.outPoint.point.x.size);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_ECDH_ZGen: zPt %d\n", ecdhZOut.outPoint.size);
#endif

    return rc;
}


/* Generate ephemeral ECC key and return array index (2 phase method) */
/* One time use key */
int wolfTPM2_ECDHEGenKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* ecdhKey, int curve_id)
{
    int rc;
    EC_Ephemeral_In in;
    EC_Ephemeral_Out out;

    if (dev == NULL || ecdhKey == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&in, 0, sizeof(in));
    in.curveID = curve_id;
    rc = TPM2_EC_Ephemeral(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_EC_Ephemeral failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Save the point and counter (commit ID) into ecdhKey */
    wolfTPM2_CopyEccParam(&ecdhKey->pub.publicArea.unique.ecc.x, &out.Q.point.x);
    wolfTPM2_CopyEccParam(&ecdhKey->pub.publicArea.unique.ecc.y, &out.Q.point.y);
    ecdhKey->handle.hndl = (UINT32)out.counter;

    return rc;
}

/* Compute Z (shared secret) using pubPoint and counter (2 phase method) */
/* The counter / array ID can only be used one time */
int wolfTPM2_ECDHEGenZ(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEY* ecdhKey, const TPM2B_ECC_POINT* pubPoint,
    byte* out, int* outSz)
{
    int rc;
    ZGen_2Phase_In  inZGen2Ph;
    ZGen_2Phase_Out outZGen2Ph;
    int curveSize;

    if (dev == NULL || parentKey == NULL || ecdhKey == NULL ||
        pubPoint == NULL || out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get curve size to verify output is large enough */
    curveSize = wolfTPM2_GetCurveSize(
        parentKey->pub.publicArea.parameters.eccDetail.curveID);
    if (curveSize <= 0 || *outSz < curveSize) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &parentKey->handle);

    XMEMSET(&inZGen2Ph, 0, sizeof(inZGen2Ph));
    inZGen2Ph.keyA = ecdhKey->handle.hndl;
    ecdhKey->handle.hndl = TPM_RH_NULL;
    XMEMCPY(&inZGen2Ph.inQsB.point, &pubPoint->point, sizeof(TPMS_ECC_POINT));
    XMEMCPY(&inZGen2Ph.inQeB.point, &pubPoint->point, sizeof(TPMS_ECC_POINT));
    inZGen2Ph.inScheme = TPM_ALG_ECDH;
    inZGen2Ph.counter = (UINT16)ecdhKey->handle.hndl;

    rc = TPM2_ZGen_2Phase(&inZGen2Ph, &outZGen2Ph);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_ZGen_2Phase failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    *outSz = outZGen2Ph.outZ2.point.x.size;
    XMEMCPY(out, outZGen2Ph.outZ2.point.x.buffer,
        outZGen2Ph.outZ2.point.x.size);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_ZGen_2Phase: zPt %d\n", outZGen2Ph.outZ2.size);
#endif

    return rc;
}


int wolfTPM2_RsaEncrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_ALG_ID padScheme, const byte* msg, int msgSz, byte* out, int* outSz)
{
    int rc;
    RSA_Encrypt_In  rsaEncIn;
    RSA_Encrypt_Out rsaEncOut;

    if (dev == NULL || key == NULL || msg == NULL || out == NULL ||
                                                                outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &key->handle);

    /* RSA Encrypt */
    XMEMSET(&rsaEncIn, 0, sizeof(rsaEncIn));
    rsaEncIn.keyHandle = key->handle.hndl;
    rsaEncIn.message.size = msgSz;
    XMEMCPY(rsaEncIn.message.buffer, msg, msgSz);
    /* TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSASSA or TPM_ALG_RSAPSS */
    rsaEncIn.inScheme.scheme = padScheme;
    rsaEncIn.inScheme.details.anySig.hashAlg = WOLFTPM2_WRAP_DIGEST;

#if 0
    /* Optional label */
    rsaEncIn.label.size = sizeof(label); /* Null term required */
    XMEMCPY(rsaEncIn.label.buffer, label, rsaEncIn.label.size);
#endif

    rc = TPM2_RSA_Encrypt(&rsaEncIn, &rsaEncOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_RSA_Encrypt failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    *outSz = rsaEncOut.outData.size;
    XMEMCPY(out, rsaEncOut.outData.buffer, *outSz);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_RSA_Encrypt: %d\n", rsaEncOut.outData.size);
#endif

    return rc;
}

int wolfTPM2_RsaDecrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_ALG_ID padScheme, const byte* in, int inSz, byte* msg, int* msgSz)
{
    int rc;
    RSA_Decrypt_In  rsaDecIn;
    RSA_Decrypt_Out rsaDecOut;

    if (dev == NULL || key == NULL || in == NULL || msg == NULL ||
                                                                msgSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* set session auth and name for key */
    wolfTPM2_SetAuthHandle(dev, 0, &key->handle);

    /* RSA Decrypt */
    XMEMSET(&rsaDecIn, 0, sizeof(rsaDecIn));
    rsaDecIn.keyHandle = key->handle.hndl;
    rsaDecIn.cipherText.size = inSz;
    XMEMCPY(rsaDecIn.cipherText.buffer, in, inSz);
    /* TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSASSA or TPM_ALG_RSAPSS */
    rsaDecIn.inScheme.scheme = padScheme;
    rsaDecIn.inScheme.details.anySig.hashAlg = WOLFTPM2_WRAP_DIGEST;

#if 0
    /* Optional label */
    rsaDecIn.label.size = sizeof(label); /* Null term required */
    XMEMCPY(rsaDecIn.label.buffer, label, rsaEncIn.label.size);
#endif

    rc = TPM2_RSA_Decrypt(&rsaDecIn, &rsaDecOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_RSA_Decrypt failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    *msgSz = rsaDecOut.message.size;
    XMEMCPY(msg, rsaDecOut.message.buffer, *msgSz);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_RSA_Decrypt: %d\n", rsaDecOut.message.size);
#endif

    return rc;
}

int wolfTPM2_ResetPCR(WOLFTPM2_DEV* dev, int pcrIndex)
{
    int rc;
    PCR_Reset_In pcrReset;
    XMEMSET(&pcrReset, 0, sizeof(pcrReset));
    pcrReset.pcrHandle = pcrIndex;
    rc = TPM2_PCR_Reset(&pcrReset);
    (void)dev;
    return rc;
}

/* TODO: Version that can read up to 8 PCR's at a time */
int wolfTPM2_ReadPCR(WOLFTPM2_DEV* dev, int pcrIndex, int hashAlg, byte* digest,
    int* pDigestLen)
{
    int rc;
    PCR_Read_In  pcrReadIn;
    PCR_Read_Out pcrReadOut;
    int digestLen = 0;

    if (dev == NULL || pcrIndex < (int)PCR_FIRST || pcrIndex > (int)PCR_LAST)
        return BAD_FUNC_ARG;

    /* set session auth to blank */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthPassword(dev, 0, NULL);
    }

    XMEMSET(&pcrReadIn, 0, sizeof(pcrReadIn));
    wolfTPM2_SetupPCRSel(&pcrReadIn.pcrSelectionIn, hashAlg, pcrIndex);
    rc = TPM2_PCR_Read(&pcrReadIn, &pcrReadOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_PCR_Read failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    digestLen = (int)pcrReadOut.pcrValues.digests[0].size;
    if (digest)
        XMEMCPY(digest, pcrReadOut.pcrValues.digests[0].buffer, digestLen);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
        pcrIndex, digestLen, (int)pcrReadOut.pcrUpdateCounter);
    TPM2_PrintBin(digest, digestLen);
#endif

    if (pDigestLen)
        *pDigestLen = digestLen;

    return rc;
}

int wolfTPM2_ExtendPCR(WOLFTPM2_DEV* dev, int pcrIndex, int hashAlg,
    const byte* digest, int digestLen)
{
    int rc;
    PCR_Extend_In pcrExtend;

    if (dev == NULL || digestLen > TPM_MAX_DIGEST_SIZE) {
        return BAD_FUNC_ARG;
    }

    /* set session auth to blank */
    if (dev->ctx.session) {
        wolfTPM2_SetAuthPassword(dev, 0, NULL);
    }

    XMEMSET(&pcrExtend, 0, sizeof(pcrExtend));
    pcrExtend.pcrHandle = pcrIndex;
    pcrExtend.digests.count = 1;
    pcrExtend.digests.digests[0].hashAlg = hashAlg;
    XMEMCPY(pcrExtend.digests.digests[0].digest.H, digest, digestLen);
    rc = TPM2_PCR_Extend(&pcrExtend);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_PCR_Extend failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    #endif
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_PCR_Extend: Index %d, Digest Sz %d\n", pcrIndex, digestLen);
#endif

    return rc;
}

int wolfTPM2_UnloadHandle(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* handle)
{
    int rc;
    FlushContext_In in;

    if (dev == NULL || handle == NULL)
        return BAD_FUNC_ARG;

    /* don't try and unload null or persistent handles */
    if (handle->hndl == 0 || handle->hndl == TPM_RH_NULL ||
        (handle->hndl >= PERSISTENT_FIRST && handle->hndl <= PERSISTENT_LAST)) {
        return TPM_RC_SUCCESS;
    }

    XMEMSET(&in, 0, sizeof(in));
    in.flushHandle = handle->hndl;
    rc = TPM2_FlushContext(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_FlushContext failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_FlushContext: Closed handle 0x%x\n", (word32)handle->hndl);
#endif

    handle->hndl = TPM_RH_NULL;

    return TPM_RC_SUCCESS;
}

/* nv is the populated handle and auth */
/* auth and authSz are optional NV authentication */
int wolfTPM2_NVCreateAuth(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* parent,
    WOLFTPM2_NV* nv, word32 nvIndex, word32 nvAttributes, word32 maxSize,
    const byte* auth, int authSz)
{
    int rc, rctmp, alreadyExists = 0;
    NV_DefineSpace_In in;

    if (dev == NULL || nv == NULL) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    rc = wolfTPM2_SetAuthHandle(dev, 0, parent);
    if (rc != TPM_RC_SUCCESS) { return rc; }

    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = parent->hndl;
    if (auth && authSz > 0) {
        if (authSz > (int)sizeof(in.auth.buffer))
            authSz = (int)sizeof(in.auth.buffer);
        in.auth.size = authSz;
        XMEMCPY(in.auth.buffer, auth, in.auth.size);
    }
    in.publicInfo.nvPublic.nvIndex = nvIndex;
    in.publicInfo.nvPublic.nameAlg = WOLFTPM2_WRAP_DIGEST;
    in.publicInfo.nvPublic.attributes = nvAttributes;
    in.publicInfo.nvPublic.dataSize = (UINT16)maxSize;

    rc = TPM2_NV_DefineSpace(&in);
    if (rc == TPM_RC_NV_DEFINED) {
        alreadyExists = 1;
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_DefineSpace: handle already exists\n");
    #endif
    }
    else if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_DefineSpace failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    if (rc == TPM_RC_SUCCESS && alreadyExists)
        rc = TPM_RC_NV_DEFINED;

    /* compute NV object with name */
    XMEMSET(nv, 0, sizeof(*nv));
    rctmp = wolfTPM2_NVOpen(dev, nv, nvIndex, auth, authSz);
    if (rctmp != TPM_RC_SUCCESS)
        rc = rctmp;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_NV_DefineSpace: Auth 0x%x, Idx 0x%x, Attribs 0x%d, Size %d\n",
        (word32)in.authHandle,
        (word32)in.publicInfo.nvPublic.nvIndex,
        (word32)in.publicInfo.nvPublic.attributes,
        in.publicInfo.nvPublic.dataSize);
#endif

    /* if handle already existed then return `TPM_RC_NV_DEFINED` */
    return (rc == TPM_RC_SUCCESS && alreadyExists) ? TPM_RC_NV_DEFINED : rc;
}

/* older API kept for compatibility, recommend using wolfTPM2_NVCreateAuth */
int wolfTPM2_NVCreate(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, word32 nvAttributes, word32 maxSize,
    const byte* auth, int authSz)
{
    WOLFTPM2_NV nv;
    WOLFTPM2_HANDLE parent;

    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&parent, 0, sizeof(parent));
    parent.hndl = authHandle;
    return wolfTPM2_NVCreateAuth(dev, &parent, &nv, nvIndex, nvAttributes,
        maxSize, auth, authSz);
}

int wolfTPM2_NVWriteAuth(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    word32 nvIndex, byte* dataBuf, word32 dataSz, word32 offset)
{
    int rc = TPM_RC_SUCCESS;
    word32 pos = 0, towrite;
    NV_Write_In in;

    if (dev == NULL || nv == NULL) {
        return BAD_FUNC_ARG;
    }

    /* make sure the name is computed for the handle */
    if (!nv->handle.nameLoaded) {
        rc = wolfTPM2_NVOpen(dev, nv, nvIndex, NULL, 0);
        if (rc != 0) {
            return rc;
        }
    }

    /* Necessary, because NVWrite has two handles, second is NV Index */
    rc  = wolfTPM2_SetAuthHandleName(dev, 0, &nv->handle);
    rc |= wolfTPM2_SetAuthHandleName(dev, 1, &nv->handle);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("Setting NV index name failed\n");
    #endif
        return TPM_RC_FAILURE;
    }

    while (dataSz > 0) {
        towrite = dataSz;
        if (towrite > MAX_NV_BUFFER_SIZE)
            towrite = MAX_NV_BUFFER_SIZE;

        XMEMSET(&in, 0, sizeof(in));
        in.authHandle = nv->handle.hndl;
        in.nvIndex = nvIndex;
        in.offset = offset+pos;
        in.data.size = towrite;
        if (dataBuf)
            XMEMCPY(in.data.buffer, &dataBuf[pos], towrite);

        rc = TPM2_NV_Write(&in);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_NV_Write failed %d: %s\n", rc,
                wolfTPM2_GetRCString(rc));
        #endif
            return rc;
        }

        /* if this is the first write to NV then the NV_WRITTEN bit will get set
         * and name needs re-computed */
        if (pos == 0) {
            /* read public and re-compute name */
            rc = wolfTPM2_NVOpen(dev, nv, nv->handle.hndl, NULL, 0);
            if (rc != 0) break;
        }

    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_Write: Auth 0x%x, Idx 0x%x, Offset %d, Size %d\n",
            (word32)in.authHandle, (word32)in.nvIndex,
            in.offset, in.data.size);
    #endif

        pos += towrite;
        dataSz -= towrite;
    }

    return rc;
}

/* older API kept for compatibility, recommend using wolfTPM2_NVWriteAuth */
int wolfTPM2_NVWrite(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, byte* dataBuf, word32 dataSz, word32 offset)
{
    WOLFTPM2_NV nv;
    XMEMSET(&nv, 0, sizeof(nv));
    nv.handle.hndl = (TPM_HANDLE)nvIndex;
    (void)authHandle;
    return wolfTPM2_NVWriteAuth(dev, &nv, nvIndex, dataBuf, dataSz, offset);
}

int wolfTPM2_NVReadAuth(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    word32 nvIndex, byte* dataBuf, word32* pDataSz, word32 offset)
{
    int rc = TPM_RC_SUCCESS;
    word32 pos = 0, toread, dataSz;
    NV_Read_In in;
    NV_Read_Out out;

    if (dev == NULL || nv == NULL || pDataSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* make sure the name is computed for the handle */
    if (!nv->handle.nameLoaded) {
        rc = wolfTPM2_NVOpen(dev, nv, nvIndex, NULL, 0);
        if (rc != TPM_RC_SUCCESS) { return rc; }
    }

    /* Necessary, because NVRead has two handles, second is NV Index */
    rc  = wolfTPM2_SetAuthHandleName(dev, 0, &nv->handle);
    rc |= wolfTPM2_SetAuthHandleName(dev, 1, &nv->handle);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("Setting NV index name failed\n");
    #endif
        return TPM_RC_FAILURE;
    }

    dataSz = *pDataSz;
    while (dataSz > 0) {
        toread = dataSz;
        if (toread > MAX_NV_BUFFER_SIZE)
            toread = MAX_NV_BUFFER_SIZE;

        XMEMSET(&in, 0, sizeof(in));
        in.authHandle = nv->handle.hndl;
        in.nvIndex = nvIndex;
        in.offset = offset+pos;
        in.size = toread;

        rc = TPM2_NV_Read(&in, &out);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_NV_Read failed %d: %s\n", rc,
                wolfTPM2_GetRCString(rc));
        #endif
            return rc;
        }

        toread = out.data.size;
        if (dataBuf) {
            XMEMCPY(&dataBuf[pos], out.data.buffer, toread);
        }

    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_Read: Auth 0x%x, Idx 0x%x, Offset %d, Size %d\n",
            (word32)in.authHandle, (word32)in.nvIndex, in.offset, out.data.size);
    #endif

        /* if we are done reading, exit loop */
        if (toread == 0)
            break;

        pos += toread;
        dataSz -= toread;
    }
    *pDataSz = pos;

    return rc;
}

int wolfTPM2_NVReadCert(WOLFTPM2_DEV* dev, TPM_HANDLE handle,
    uint8_t* buffer, uint32_t* len)
{
    int rc;
    WOLFTPM2_NV nv;
    TPMS_NV_PUBLIC nvPublic;

    XMEMSET(&nvPublic, 0, sizeof(nvPublic));
    XMEMSET(&nv, 0, sizeof(nv));

    /* Get or check size of NV */
    rc = wolfTPM2_NVReadPublic(dev, handle, &nvPublic);
    if (rc == 0) {
        if (buffer == NULL) {
            /* just set size and return success */
            *len = nvPublic.dataSize;
            return 0;
        }
        if (nvPublic.dataSize > *len) {
            return BUFFER_E;
        }
        *len = nvPublic.dataSize;
    }
    else {
    #ifdef DEBUG_WOLFTPM
        printf("NV public read of handle 0x%x failed %d: %s\n",
            handle, rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Perform read of NV without auth password */
    nv.handle.hndl = handle;
    rc = wolfTPM2_NVReadAuth(dev, &nv, handle, buffer, (word32*)len, 0);
    return rc;
}

/* older API kept for compatibility, recommend using wolfTPM2_NVReadAuth */
int wolfTPM2_NVRead(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, byte* dataBuf, word32* pDataSz, word32 offset)
{
    WOLFTPM2_NV nv;
    XMEMSET(&nv, 0, sizeof(nv));
    nv.handle.hndl = (TPM_HANDLE)nvIndex;
    (void)authHandle;
    return wolfTPM2_NVReadAuth(dev, &nv, nvIndex, dataBuf, pDataSz, offset);
}

int wolfTPM2_NVOpen(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv, word32 nvIndex,
    const byte* auth, word32 authSz)
{
    int rc = TPM_RC_SUCCESS;
    TPMS_NV_PUBLIC nvPublic;

    if (dev == NULL || nv == NULL || authSz > sizeof(nv->handle.auth.buffer)) {
        return BAD_FUNC_ARG;
    }

    /* build the "handle" */
    nv->handle.hndl = nvIndex;
    /* auth can also be set already via nv->handle */
    if (auth != NULL && authSz > 0) {
        nv->handle.auth.size = authSz;
        XMEMCPY(nv->handle.auth.buffer, auth, authSz);
    }

    /* Read the NV Index publicArea to have up to date NV Index Name */
    rc = wolfTPM2_NVReadPublic(dev, nv->handle.hndl, &nvPublic);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("Failed to open (read) NV\n");
    #endif
        return rc;
    }

    /* Compute NV Index name in case of parameter encryption */
#ifndef WOLFTPM2_NO_WOLFCRYPT
    rc = TPM2_HashNvPublic(&nvPublic, (byte*)&nv->handle.name.name,
                           &nv->handle.name.size);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
#endif

    /* flag that the NV was "opened" and name was loaded */
    nv->handle.nameLoaded = 1;

    return rc;
}

int wolfTPM2_NVReadPublic(WOLFTPM2_DEV* dev, word32 nvIndex,
    TPMS_NV_PUBLIC* nvPublic)
{
    int rc;
    NV_ReadPublic_In  in;
    NV_ReadPublic_Out out;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&in, 0, sizeof(in));
    in.nvIndex = nvIndex;
    rc = TPM2_NV_ReadPublic(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_ReadPublic failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_NV_ReadPublic: Sz %d, Idx 0x%x, nameAlg %d, Attr 0x%x, "
            "authPol %d, dataSz %d, name %d\n",
        out.nvPublic.size,
        (word32)out.nvPublic.nvPublic.nvIndex,
        out.nvPublic.nvPublic.nameAlg,
        (word32)out.nvPublic.nvPublic.attributes,
        out.nvPublic.nvPublic.authPolicy.size,
        out.nvPublic.nvPublic.dataSize,
        out.nvName.size);
#endif

    if (nvPublic) {
        wolfTPM2_CopyNvPublic(nvPublic, &out.nvPublic.nvPublic);
    }

    return rc;
}

int wolfTPM2_NVIncrement(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv)
{
    int rc = TPM_RC_SUCCESS;
    NV_Increment_In in;

    if (dev == NULL || nv == NULL) {
        return BAD_FUNC_ARG;
    }

    /* make sure the name is computed for the handle */
    if (!nv->handle.nameLoaded) {
        rc = wolfTPM2_NVOpen(dev, nv, nv->handle.hndl, NULL, 0);
        if (rc != TPM_RC_SUCCESS) { return rc; }
    }

    /* Necessary, because NVRead has two handles, second is NV Index */
    rc  = wolfTPM2_SetAuthHandleName(dev, 0, &nv->handle);
    rc |= wolfTPM2_SetAuthHandleName(dev, 1, &nv->handle);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("Setting NV index name failed\n");
    #endif
        return rc;
    }

    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = nv->handle.hndl;
    in.nvIndex = nv->handle.hndl;

#ifdef DEBUG_WOLFTPM
    printf("TPM2_NV_Increment: Auth 0x%x, Idx 0x%x\n",
        (word32)in.authHandle, (word32)in.nvIndex);
#endif

    rc = TPM2_NV_Increment(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_Increment failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    return rc;
}

int wolfTPM2_NVWriteLock(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv)
{
    int rc;
    NV_WriteLock_In in;

    if (dev == NULL || nv == NULL) {
        return BAD_FUNC_ARG;
    }

    /* make sure the name is computed for the handle */
    if (!nv->handle.nameLoaded) {
        rc = wolfTPM2_NVOpen(dev, nv, nv->handle.hndl, NULL, 0);
        if (rc != 0) {
            return rc;
        }
    }

    /* Necessary, because NVRead has two handles, second is NV Index */
    rc  = wolfTPM2_SetAuthHandleName(dev, 0, &nv->handle);
    rc |= wolfTPM2_SetAuthHandleName(dev, 1, &nv->handle);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("Setting NV index name failed\n");
    #endif
        return TPM_RC_FAILURE;
    }

    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = nv->handle.hndl;
    in.nvIndex = nv->handle.hndl;
    return TPM2_NV_WriteLock(&in);
}

int wolfTPM2_NVDeleteAuth(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* parent,
    word32 nvIndex)
{
    int rc;
    NV_UndefineSpace_In in;

    if (dev == NULL || parent == NULL) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    if (dev->ctx.session) {
        rc = wolfTPM2_SetAuthHandle(dev, 0, parent);
        if (rc != TPM_RC_SUCCESS) { return rc; }
    }

    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = parent->hndl;
    in.nvIndex = nvIndex;

    rc = TPM2_NV_UndefineSpace(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_NV_UndefineSpace failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_NV_UndefineSpace: Auth 0x%x, Idx 0x%x\n",
        (word32)in.authHandle, (word32)in.nvIndex);
#endif

    return rc;
}

/* older API kept for compatibility, recommend using wolfTPM2_NVDeleteAuth */
int wolfTPM2_NVDelete(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex)
{
    WOLFTPM2_HANDLE parent;
    XMEMSET(&parent, 0, sizeof(parent));
    parent.hndl = authHandle;
    return wolfTPM2_NVDeleteAuth(dev, &parent, nvIndex);
}

#ifndef WOLFTPM2_NO_WOLFCRYPT
struct WC_RNG* wolfTPM2_GetRng(WOLFTPM2_DEV* dev)
{
    WC_RNG* rng = NULL;
    if (dev) {
    #ifdef WOLFTPM2_USE_WOLF_RNG
        (void)TPM2_GetWolfRng(&rng);
    #endif
    }
    return rng;
}
#endif

int wolfTPM2_GetRandom(WOLFTPM2_DEV* dev, byte* buf, word32 len)
{
    int rc = TPM_RC_SUCCESS;
    GetRandom_In in;
    GetRandom_Out out;
    word32 sz, pos = 0;

    if (dev == NULL || buf == NULL)
        return BAD_FUNC_ARG;

    while (pos < len) {
        /* calculate size to get */
        sz = len - pos;
        if (sz > MAX_RNG_REQ_SIZE)
            sz = MAX_RNG_REQ_SIZE;

        XMEMSET(&in, 0, sizeof(in));
        in.bytesRequested = sz;
        rc = TPM2_GetRandom(&in, &out);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_GetRandom failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
        #endif
            break;
        }

        sz = out.randomBytes.size; /* use actual returned size */
        if (sz > MAX_RNG_REQ_SIZE) {
        #ifdef DEBUG_WOLFTPM
            printf("wolfTPM2_GetRandom out size error\n");
        #endif
            rc = BAD_FUNC_ARG;
            break;
        }

        XMEMCPY(&buf[pos], out.randomBytes.buffer, sz);
        pos += sz;
    }
    return rc;
}

int wolfTPM2_Clear(WOLFTPM2_DEV* dev)
{
    int rc;
    Clear_In in;

    if (dev == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = TPM_RH_LOCKOUT;

    rc = TPM2_Clear(&in);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Clear failed %d: %s\n", rc,
            wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Clear Auth 0x%x\n", (word32)in.authHandle);
#endif

    return rc;
}

/* Hashing */
/* usageAuth: Optional auth for handle */
int wolfTPM2_HashStart(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    TPMI_ALG_HASH hashAlg, const byte* usageAuth, word32 usageAuthSz)
{
    int rc;
    HashSequenceStart_In in;
    HashSequenceStart_Out out;

    if (dev == NULL || hash == NULL || hashAlg == TPM_ALG_NULL ||
        (usageAuthSz > 0 && usageAuth == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* Capture usage auth */
    if (usageAuthSz > sizeof(hash->handle.auth.buffer))
        usageAuthSz = sizeof(hash->handle.auth.buffer);
    XMEMSET(hash, 0, sizeof(WOLFTPM2_HASH));
    hash->handle.auth.size = usageAuthSz;
    if (usageAuth != NULL)
        XMEMCPY(hash->handle.auth.buffer, usageAuth, usageAuthSz);

    XMEMSET(&in, 0, sizeof(in));
    wolfTPM2_CopyAuth(&in.auth, &hash->handle.auth);
    in.hashAlg = hashAlg;
    rc = TPM2_HashSequenceStart(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_HashSequenceStart failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Capture hash sequence handle */
    hash->handle.hndl = out.sequenceHandle;

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_HashStart: Handle 0x%x\n",
        (word32)out.sequenceHandle);
#endif

    return rc;
}

int wolfTPM2_HashUpdate(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    const byte* data, word32 dataSz)
{
    int rc = TPM_RC_SUCCESS;
    SequenceUpdate_In in;
    word32 pos = 0, hashSz;

    if (dev == NULL || hash == NULL || (data == NULL && dataSz > 0) ||
            hash->handle.hndl == 0) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for hash handle */
    wolfTPM2_SetAuthHandle(dev, 0, &hash->handle);

    XMEMSET(&in, 0, sizeof(in));
    in.sequenceHandle = hash->handle.hndl;

    while (pos < dataSz) {
        hashSz = dataSz - pos;
        if (hashSz > sizeof(in.buffer.buffer))
            hashSz = sizeof(in.buffer.buffer);

        in.buffer.size = hashSz;
        XMEMCPY(in.buffer.buffer, &data[pos], hashSz);
        rc = TPM2_SequenceUpdate(&in);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_SequenceUpdate failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
        #endif
            return rc;
        }
        pos += hashSz;
    }

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_HashUpdate: Handle 0x%x, DataSz %d\n",
        (word32)in.sequenceHandle, dataSz);
#endif

    return rc;
}

int wolfTPM2_HashFinish(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    byte* digest, word32* digestSz)
{
    int rc;
    SequenceComplete_In in;
    SequenceComplete_Out out;

    if (dev == NULL || hash == NULL || digest == NULL || digestSz == NULL ||
            hash->handle.hndl == 0) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for hash handle */
    wolfTPM2_SetAuthHandle(dev, 0, &hash->handle);

    XMEMSET(&in, 0, sizeof(in));
    in.sequenceHandle = hash->handle.hndl;
    in.hierarchy = TPM_RH_NULL;
    rc = TPM2_SequenceComplete(&in, &out);

    /* mark hash handle as done */
    hash->handle.hndl = TPM_RH_NULL;

    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_SequenceComplete failed 0x%x: %s: Handle 0x%x\n", rc,
            TPM2_GetRCString(rc), (word32)in.sequenceHandle);
    #endif
        return rc;
    }

    if (out.result.size > *digestSz)
        out.result.size = *digestSz;
    *digestSz = out.result.size;
    XMEMCPY(digest, out.result.buffer, *digestSz);

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_HashFinish: Handle 0x%x, DigestSz %d\n",
        (word32)in.sequenceHandle, *digestSz);
#endif

    return rc;
}


static int wolfTPM2_ComputeSymmetricUnique(WOLFTPM2_DEV* dev, int hashAlg,
    const TPMT_SENSITIVE* sensitive, TPM2B_DIGEST* unique)
{
    int rc;

#ifdef WOLFTPM_USE_SYMMETRIC
    WOLFTPM2_HASH hash;
#elif !defined(WOLFTPM2_NO_WOLFCRYPT)
    wc_HashAlg hash;
    enum wc_HashType hashType;
    int hashSz;
#endif

    if (dev == NULL || sensitive == NULL || unique == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFTPM_USE_SYMMETRIC
    rc = wolfTPM2_HashStart(dev, &hash, hashAlg, NULL, 0);
    if (rc == 0) {
        /* sensitive seed */
        rc = wolfTPM2_HashUpdate(dev, &hash, sensitive->seedValue.buffer,
            sensitive->seedValue.size);
        if (rc == 0) {
            /* sensitive value */
            rc = wolfTPM2_HashUpdate(dev, &hash, sensitive->sensitive.any.buffer,
                sensitive->sensitive.any.size);
        }
        if (rc == 0) {
            word32 uniqueSz = TPM2_GetHashDigestSize(hashAlg);
            rc = wolfTPM2_HashFinish(dev, &hash, unique->buffer, &uniqueSz);
            unique->size = uniqueSz;
        }
        else {
            /* Make sure hash if free'd on failure */
            wolfTPM2_UnloadHandle(dev, &hash.handle);
        }
    }
#elif !defined(WOLFTPM2_NO_WOLFCRYPT)
    rc = TPM2_GetHashType(hashAlg);
    hashType = (enum wc_HashType)rc;
    rc = wc_HashGetDigestSize(hashType);
    if (rc < 0)
        return rc;
    hashSz = rc;

    /* Hash of data (name) goes into remainder */
    rc = wc_HashInit(&hash, hashType);
    if (rc == 0) {
        /* sensitive seed */
        rc = wc_HashUpdate(&hash, hashType, sensitive->seedValue.buffer,
            sensitive->seedValue.size);
        if (rc == 0) {
            /* sensitive value */
            rc = wc_HashUpdate(&hash, hashType, sensitive->sensitive.any.buffer,
                sensitive->sensitive.any.size);
        }
        if (rc == 0) {
            rc = wc_HashFinal(&hash, hashType, unique->buffer);
            if (rc == 0)
                unique->size = hashSz;
        }
        wc_HashFree(&hash, hashType);
    }
#else
    (void)hashAlg;
    rc = NOT_COMPILED_IN;
#endif

    return rc;
}

int wolfTPM2_LoadSymmetricKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key, int alg,
    const byte* keyBuf, word32 keySz)
{
    int rc;
    LoadExternal_In  loadExtIn;
    LoadExternal_Out loadExtOut;
    int hashAlg, hashAlgDigSz;

    if (dev == NULL || key == NULL || keyBuf == NULL ||
            (keySz != 16 && keySz != 32)) {
        return BAD_FUNC_ARG;
    }
    if (keySz > sizeof(loadExtIn.inPrivate.sensitiveArea.sensitive.sym.buffer)) {
        return BUFFER_E;
    }

    hashAlg = (keySz == 32) ? TPM_ALG_SHA256 : TPM_ALG_SHA1;
    hashAlgDigSz = TPM2_GetHashDigestSize(hashAlg);

    /* Setup load command */
    XMEMSET(&loadExtIn, 0, sizeof(loadExtIn));
    loadExtIn.hierarchy = TPM_RH_NULL;

    /* Setup private key */
    loadExtIn.inPrivate.sensitiveArea.sensitiveType = TPM_ALG_SYMCIPHER;
    if (key->handle.auth.size > 0) {
        loadExtIn.inPrivate.sensitiveArea.authValue.size = key->handle.auth.size;
        XMEMCPY(loadExtIn.inPrivate.sensitiveArea.authValue.buffer,
            key->handle.auth.buffer, key->handle.auth.size);
    }
    loadExtIn.inPrivate.sensitiveArea.seedValue.size = hashAlgDigSz;
    rc = wolfTPM2_GetRandom(dev,
        loadExtIn.inPrivate.sensitiveArea.seedValue.buffer,
        loadExtIn.inPrivate.sensitiveArea.seedValue.size);
    if (rc != 0)
        goto exit;

    loadExtIn.inPrivate.sensitiveArea.sensitive.sym.size = keySz;
    XMEMCPY(loadExtIn.inPrivate.sensitiveArea.sensitive.sym.buffer,
        keyBuf, keySz);

    /* Setup public key */
    rc = wolfTPM2_GetKeyTemplate_Symmetric(&loadExtIn.inPublic.publicArea,
        keySz * 8, alg, YES, YES);
    if (rc != 0)
        goto exit;
    loadExtIn.inPublic.publicArea.nameAlg = hashAlg;
    loadExtIn.inPublic.publicArea.unique.sym.size = hashAlgDigSz;
    rc = wolfTPM2_ComputeSymmetricUnique(dev, hashAlg,
        &loadExtIn.inPrivate.sensitiveArea,
        &loadExtIn.inPublic.publicArea.unique.sym);
    if (rc != 0)
        goto exit;

    /* Load private key */
    rc = TPM2_LoadExternal(&loadExtIn, &loadExtOut);
    if (rc == TPM_RC_SUCCESS) {
        key->handle.hndl = loadExtOut.objectHandle;
        wolfTPM2_CopySymmetric(&key->handle.symmetric,
                &loadExtIn.inPublic.publicArea.parameters.asymDetail.symmetric);
        wolfTPM2_CopyPub(&key->pub, &loadExtIn.inPublic);

    #ifdef DEBUG_WOLFTPM
        printf("wolfTPM2_LoadSymmetricKey: 0x%x\n",
            (word32)loadExtOut.objectHandle);
    #endif
        return rc;
    }

exit:

    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_LoadExternal: failed %d: %s\n",
            rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    return rc;
}

/* EncryptDecrypt */
int wolfTPM2_EncryptDecryptBlock(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* in, byte* out, word32 inOutSz, byte* iv, word32 ivSz,
    int isDecrypt)
{
    int rc;
    EncryptDecrypt2_In encDecIn;
    EncryptDecrypt2_Out encDecOut;

    if (dev == NULL || key == NULL || in == NULL || out == NULL ||
            inOutSz == 0) {
        return BAD_FUNC_ARG;
    }

    /* set session auth for key */
    wolfTPM2_SetAuthHandle(dev, 0, &key->handle);

    XMEMSET(&encDecIn, 0, sizeof(encDecIn));
    encDecIn.keyHandle = key->handle.hndl;
    if (iv == NULL || ivSz == 0) {
        encDecIn.ivIn.size = MAX_AES_BLOCK_SIZE_BYTES; /* zeros */
    }
    else {
        encDecIn.ivIn.size = ivSz;
        XMEMCPY(encDecIn.ivIn.buffer, iv, ivSz);
    }
    encDecIn.decrypt = isDecrypt;
    /* use symmetric algorithm from key */
    encDecIn.mode = key->pub.publicArea.parameters.symDetail.sym.mode.aes;

    encDecIn.inData.size = inOutSz;
    XMEMCPY(encDecIn.inData.buffer, in, inOutSz);

    /* make sure its multiple of block size */
    encDecIn.inData.size = (encDecIn.inData.size +
        MAX_AES_BLOCK_SIZE_BYTES - 1) & ~(MAX_AES_BLOCK_SIZE_BYTES - 1);

    rc = TPM2_EncryptDecrypt2(&encDecIn, &encDecOut);
    if (rc == TPM_RC_COMMAND_CODE) { /* some TPM's may not support command */
        /* try to enable support */
        rc = wolfTPM2_SetCommand(dev, TPM_CC_EncryptDecrypt2, YES);
        if (rc == TPM_RC_SUCCESS) {
            /* reset session auth for key */
            wolfTPM2_SetAuthHandle(dev, 0, &key->handle);

            /* try command again */
            rc = TPM2_EncryptDecrypt2(&encDecIn, &encDecOut);
        }
    }

    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_EncryptDecrypt2 failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* update IV */
    if (iv) {
        if (ivSz < encDecOut.ivOut.size)
            ivSz = encDecOut.ivOut.size;
        XMEMCPY(iv, encDecOut.ivOut.buffer, ivSz);
    }

    /* return block */
    if (inOutSz > encDecOut.outData.size)
        inOutSz = encDecOut.outData.size;
    XMEMCPY(out, encDecOut.outData.buffer, inOutSz);

    return rc;
}

int wolfTPM2_EncryptDecrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* in, byte* out, word32 inOutSz,
    byte* iv, word32 ivSz, int isDecrypt)
{
    int rc = 0;
    word32 pos = 0, xfer;

    while (pos < inOutSz) {
        xfer = inOutSz - pos;
        if (xfer > MAX_DIGEST_BUFFER)
            xfer = MAX_DIGEST_BUFFER;

        rc = wolfTPM2_EncryptDecryptBlock(dev, key, &in[pos], &out[pos],
            xfer, iv, ivSz, isDecrypt);
        if (rc != TPM_RC_SUCCESS)
            break;

        pos += xfer;
    }

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_EncryptDecrypt: 0x%x: %s, %d bytes\n",
        rc, TPM2_GetRCString(rc), inOutSz);
#endif

    return rc;
}


int wolfTPM2_SetCommand(WOLFTPM2_DEV* dev, TPM_CC commandCode, int enableFlag)
{
    int rc = TPM_RC_COMMAND_CODE; /* not supported */
#if defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)
    if (TPM2_GetVendorID() == TPM_VENDOR_STM) {
        SetCommandSet_In in;

        /* set blank platform auth */
        wolfTPM2_SetAuthPassword(dev, 0, NULL);

        /* Enable commands (like TPM2_EncryptDecrypt2) */
        XMEMSET(&in, 0, sizeof(in));
        in.authHandle = TPM_RH_PLATFORM;
        in.commandCode = commandCode;
        in.enableFlag = enableFlag;
        rc = TPM2_SetCommandSet(&in);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_SetCommandSet failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
        #endif
        }
    }
#else
    (void)commandCode;
    (void)enableFlag;
#endif
    (void)dev;
    return rc;
}



/* HMAC */
int wolfTPM2_LoadKeyedHashKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    WOLFTPM2_HANDLE* parent, int hashAlg, const byte* keyBuf, word32 keySz,
    const byte* usageAuth, word32 usageAuthSz)
{
    int rc;
    Create_In  createIn;
    Create_Out createOut;
    Load_In  loadIn;
    Load_Out loadOut;
    int hashAlgDigSz;

    if (dev == NULL || key == NULL || parent == NULL || keyBuf == NULL) {
        return BAD_FUNC_ARG;
    }
    if (keySz == 0 || keySz > MAX_SYM_DATA) {
        return BUFFER_E;
    }
    hashAlgDigSz = TPM2_GetHashDigestSize(hashAlg);
    if (hashAlgDigSz <= 0) {
        return BAD_FUNC_ARG;
    }

    /* clear output key buffer */
    XMEMSET(key, 0, sizeof(WOLFTPM2_KEY));

    /* set session auth for parent key */
    wolfTPM2_SetAuthHandle(dev, 0, parent);

    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent->hndl;
    if (usageAuth) {
        createIn.inSensitive.sensitive.userAuth.size = usageAuthSz;
        XMEMCPY(createIn.inSensitive.sensitive.userAuth.buffer, usageAuth,
            createIn.inSensitive.sensitive.userAuth.size);
    }
    createIn.inSensitive.sensitive.data.size = keySz;
    XMEMCPY(createIn.inSensitive.sensitive.data.buffer, keyBuf, keySz);

    rc = wolfTPM2_GetKeyTemplate_KeyedHash(&createIn.inPublic.publicArea,
        hashAlg, YES, NO);
    if (rc != 0) {
        return rc;
    }

    rc = TPM2_Create(&createIn, &createOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Create key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_Create key: pub %d, priv %d\n", createOut.outPublic.size,
        createOut.outPrivate.size);
    TPM2_PrintPublicArea(&createOut.outPublic);
#endif
    wolfTPM2_CopySymmetric(&key->handle.symmetric,
            &createOut.outPublic.publicArea.parameters.asymDetail.symmetric);
    wolfTPM2_CopyPub(&key->pub, &createOut.outPublic);

    /* Load new key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent->hndl;
    wolfTPM2_CopyPriv(&loadIn.inPrivate, &createOut.outPrivate);
    wolfTPM2_CopyPub(&loadIn.inPublic, &key->pub);
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Load key failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }
    key->handle.hndl = loadOut.objectHandle;
    wolfTPM2_CopyAuth(&key->handle.auth, &createIn.inSensitive.sensitive.userAuth);
    wolfTPM2_CopyName(&key->handle.name, &loadOut.name);

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_LoadKeyedHashKey Key Handle 0x%x\n",
        (word32)key->handle.hndl);
#endif

    return rc;
}

int wolfTPM2_HmacStart(WOLFTPM2_DEV* dev, WOLFTPM2_HMAC* hmac,
    WOLFTPM2_HANDLE* parent, TPMI_ALG_HASH hashAlg, const byte* keyBuf,
    word32 keySz, const byte* usageAuth, word32 usageAuthSz)
{
    int rc;
    HMAC_Start_In in;
    HMAC_Start_Out out;

    if (dev == NULL || hmac == NULL || hashAlg == TPM_ALG_NULL) {
        return BAD_FUNC_ARG;
    }

    /* Capture usage auth */
    if (usageAuthSz > sizeof(hmac->hash.handle.auth.buffer))
        usageAuthSz = sizeof(hmac->hash.handle.auth.buffer);
    hmac->hash.handle.auth.size = usageAuthSz;
    XMEMCPY(hmac->hash.handle.auth.buffer, usageAuth, usageAuthSz);

    if (!hmac->hmacKeyLoaded || hmac->key.handle.hndl == TPM_RH_NULL) {
        /* Load Keyed Hash Key */
        rc = wolfTPM2_LoadKeyedHashKey(dev, &hmac->key, parent, hashAlg, keyBuf,
            keySz, usageAuth, usageAuthSz);
        if (rc != 0) {
            return rc;
        }
        hmac->hmacKeyLoaded = 1;
    }

    /* set session auth for hmac key */
    wolfTPM2_SetAuthHandle(dev, 0, &hmac->hash.handle);

    /* Setup HMAC start command */
    XMEMSET(&in, 0, sizeof(in));
    in.handle = hmac->key.handle.hndl;
    wolfTPM2_CopyAuth(&in.auth, &hmac->hash.handle.auth);
    in.hashAlg = hashAlg;
    rc = TPM2_HMAC_Start(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_HMAC_Start failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Capture hash sequence handle */
    hmac->hash.handle.hndl = out.sequenceHandle;

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_HmacStart: Handle 0x%x\n",
        (word32)out.sequenceHandle);
#endif

    return rc;
}

int wolfTPM2_HmacUpdate(WOLFTPM2_DEV* dev, WOLFTPM2_HMAC* hmac,
    const byte* data, word32 dataSz)
{
    if (dev == NULL || hmac == NULL) {
        return BAD_FUNC_ARG;
    }

    return wolfTPM2_HashUpdate(dev, &hmac->hash, data, dataSz);
}

int wolfTPM2_HmacFinish(WOLFTPM2_DEV* dev, WOLFTPM2_HMAC* hmac,
    byte* digest, word32* digestSz)
{
    int rc;

    if (dev == NULL || hmac == NULL) {
        return BAD_FUNC_ARG;
    }

    rc = wolfTPM2_HashFinish(dev, &hmac->hash, digest, digestSz);

    if (!hmac->hmacKeyKeep) {
        /* unload HMAC key */
        wolfTPM2_UnloadHandle(dev, &hmac->key.handle);
        hmac->hmacKeyLoaded = 0;
    }

    return rc;
}

/* performs a reset sequence */
int wolfTPM2_Shutdown(WOLFTPM2_DEV* dev, int doStartup)
{
    int rc;
    Shutdown_In shutdownIn;
    Startup_In startupIn;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    /* shutdown */
    XMEMSET(&shutdownIn, 0, sizeof(shutdownIn));
    shutdownIn.shutdownType = TPM_SU_CLEAR;
    rc = TPM2_Shutdown(&shutdownIn);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_Shutdown failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    #endif
    }

    /* startup */
    if (doStartup) {
        XMEMSET(&startupIn, 0, sizeof(startupIn));
        startupIn.startupType = TPM_SU_CLEAR;
        rc = TPM2_Startup(&startupIn);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_Startup failed %d: %s\n",
                rc, wolfTPM2_GetRCString(rc));
        #endif
            return rc;
        }
    }

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_Shutdown complete\n");
#endif

    return rc;
}

int wolfTPM2_UnloadHandles(WOLFTPM2_DEV* dev, word32 handleStart,
    word32 handleCount)
{
    int rc = TPM_RC_SUCCESS;
    word32 hndl;
    WOLFTPM2_HANDLE handle;
    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(&handle, 0, sizeof(handle));
    wolfTPM2_CopyAuth(&handle.auth, &dev->session[0].auth);

    for (hndl=handleStart; hndl < handleStart+handleCount; hndl++) {
        handle.hndl = hndl;
        /* ignore return code failures */
        (void)wolfTPM2_UnloadHandle(dev, &handle);
    }
    return rc;
}

int wolfTPM2_UnloadHandles_AllTransient(WOLFTPM2_DEV* dev)
{
    return wolfTPM2_UnloadHandles(dev, TRANSIENT_FIRST, MAX_HANDLE_NUM);
}


int wolfTPM2_ChangePlatformAuth(WOLFTPM2_DEV* dev, WOLFTPM2_SESSION* session)
{
    int rc = 0;
    HierarchyChangeAuth_In in;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = TPM_RH_PLATFORM;

    /* use parameter encryption if session supplied */
    if (session != NULL) {
        rc = wolfTPM2_SetAuthSession(dev, 1, session, (TPMA_SESSION_decrypt |
            TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
    }
    if (rc == 0) {
        /* TPM 2.0 PCR's are typically SHA-1 and SHA2-256 */
        in.newAuth.size = TPM2_GetHashDigestSize(WOLFTPM2_WRAP_DIGEST);
        if (in.newAuth.size <= 0) {
            rc = BAD_FUNC_ARG;
        }
    }
    if (rc == 0) {
        rc = TPM2_GetNonce(in.newAuth.buffer, in.newAuth.size);
    }
    if (rc == 0) {
        rc = TPM2_HierarchyChangeAuth(&in);
    }
#ifdef DEBUG_WOLFTPM
    if (rc == 0) {
        printf("Platform auth set to %d bytes of random\n", in.newAuth.size);
        #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("\tAuth Sz %d\n", in.newAuth.size);
            TPM2_PrintBin(in.newAuth.buffer, in.newAuth.size);
        #endif
    }
    else {
        printf("Error %d setting platform auth! %s\n",
            rc, wolfTPM2_GetRCString(rc));
    }
#endif
    /* ensure the random secret is not left in stack */
    TPM2_ForceZero(in.newAuth.buffer, in.newAuth.size);
    return rc;
}

/******************************************************************************/
/* --- END Wrapper Device Functions-- */
/******************************************************************************/


/******************************************************************************/
/* --- BEGIN Utility Functions -- */
/******************************************************************************/

int GetKeyTemplateRSA(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, int keyBits, long exponent,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash)
{
    if (publicTemplate == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_RSA;
    publicTemplate->unique.rsa.size = keyBits / 8;
    publicTemplate->nameAlg = nameAlg;
    publicTemplate->objectAttributes = objectAttributes;
    publicTemplate->parameters.rsaDetail.keyBits = keyBits;
    publicTemplate->parameters.rsaDetail.exponent = (UINT32)exponent;
    publicTemplate->parameters.rsaDetail.scheme.scheme = sigScheme;
    publicTemplate->parameters.rsaDetail.scheme.details.anySig.hashAlg = sigHash;
    /* For fixedParent or (decrypt and restricted) enable symmetric */
    if ((objectAttributes & TPMA_OBJECT_fixedParent) ||
           ((objectAttributes & TPMA_OBJECT_decrypt) &&
            (objectAttributes & TPMA_OBJECT_restricted))) {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
        publicTemplate->parameters.rsaDetail.symmetric.keyBits.aes = 128;
        publicTemplate->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    }

    return TPM_RC_SUCCESS;
}

int GetKeyTemplateECC(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, TPM_ECC_CURVE curve,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash)
{
    int curveSz = TPM2_GetCurveSize(curve);

    if (publicTemplate == NULL || curveSz == 0)
        return BAD_FUNC_ARG;

#if defined(NO_ECC256) && defined(HAVE_ECC384) && ECC_MIN_KEY_SZ <= 384
    /* make sure we use a curve that is enabled */
    if (curve == TPM_ECC_NIST_P256) {
        curve = TPM_ECC_NIST_P384;
        nameAlg = TPM_ALG_SHA384;
        sigHash = TPM_ALG_SHA384;
    }
#endif

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_ECC;
    publicTemplate->nameAlg = nameAlg;
    publicTemplate->unique.ecc.x.size = curveSz;
    publicTemplate->unique.ecc.y.size = curveSz;
    publicTemplate->objectAttributes = objectAttributes;
    /* For fixedParent or (decrypt and restricted) enable symmetric */
    if ((objectAttributes & TPMA_OBJECT_fixedParent) ||
           ((objectAttributes & TPMA_OBJECT_decrypt) &&
            (objectAttributes & TPMA_OBJECT_restricted))) {
        publicTemplate->parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
        publicTemplate->parameters.eccDetail.symmetric.keyBits.aes = 128;
        publicTemplate->parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
    }
    else {
        publicTemplate->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    }
    /* TPM_ALG_ECDSA or TPM_ALG_ECDH */
    publicTemplate->parameters.eccDetail.scheme.scheme = sigScheme;
    publicTemplate->parameters.eccDetail.scheme.details.ecdsa.hashAlg = sigHash;
    publicTemplate->parameters.eccDetail.curveID = curve;
    publicTemplate->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

    return TPM_RC_SUCCESS;
}

int wolfTPM2_GetKeyTemplate_RSA_ex(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, int keyBits, long exponent,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash)
{
    return GetKeyTemplateRSA(publicTemplate, nameAlg,
        objectAttributes, keyBits, exponent, sigScheme, sigHash);
}

int wolfTPM2_GetKeyTemplate_RSA(TPMT_PUBLIC* publicTemplate,
    TPMA_OBJECT objectAttributes)
{
    return GetKeyTemplateRSA(publicTemplate, WOLFTPM2_WRAP_DIGEST,
        objectAttributes, WOLFTPM2_WRAP_RSA_KEY_BITS, WOLFTPM2_WRAP_RSA_EXPONENT,
        TPM_ALG_NULL, WOLFTPM2_WRAP_DIGEST);
}

int wolfTPM2_GetKeyTemplate_ECC_ex(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, TPM_ECC_CURVE curve,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash)
{
    return GetKeyTemplateECC(publicTemplate, nameAlg,
        objectAttributes, curve, sigScheme, sigHash);
}

int wolfTPM2_GetKeyTemplate_ECC(TPMT_PUBLIC* publicTemplate,
    TPMA_OBJECT objectAttributes, TPM_ECC_CURVE curve, TPM_ALG_ID sigScheme)
{
    return GetKeyTemplateECC(publicTemplate, WOLFTPM2_WRAP_DIGEST,
        objectAttributes, curve, sigScheme, WOLFTPM2_WRAP_DIGEST);
}

int wolfTPM2_GetKeyTemplate_Symmetric(TPMT_PUBLIC* publicTemplate, int keyBits,
    TPM_ALG_ID algMode, int isSign, int isDecrypt)
{
    if (publicTemplate == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFTPM_MICROCHIP
    isSign = 0; /* Microchip TPM does not like "sign" set for symmetric keys */
#endif

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_SYMCIPHER;
    publicTemplate->nameAlg = WOLFTPM2_WRAP_DIGEST;
    publicTemplate->unique.sym.size = keyBits / 8;
    publicTemplate->objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA | (isSign ? TPMA_OBJECT_sign : 0) |
        (isDecrypt ? TPMA_OBJECT_decrypt : 0));
    publicTemplate->parameters.symDetail.sym.algorithm = TPM_ALG_AES;
    publicTemplate->parameters.symDetail.sym.keyBits.sym = keyBits;
    publicTemplate->parameters.symDetail.sym.mode.sym = algMode;

    return TPM_RC_SUCCESS;
}

int wolfTPM2_GetKeyTemplate_KeyedHash(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID hashAlg, int isSign, int isDecrypt)
{
    if (publicTemplate == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_KEYEDHASH;
    publicTemplate->nameAlg = WOLFTPM2_WRAP_DIGEST;
    publicTemplate->objectAttributes = (
        TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA |
        (isSign ? TPMA_OBJECT_sign : 0) |
        (isDecrypt ? TPMA_OBJECT_decrypt : 0));
    publicTemplate->parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    publicTemplate->parameters.keyedHashDetail.scheme.details.hmac.hashAlg = hashAlg;
    return TPM_RC_SUCCESS;
}

int wolfTPM2_GetKeyTemplate_KeySeal(TPMT_PUBLIC* publicTemplate, TPM_ALG_ID nameAlg)
{
    if (publicTemplate == NULL)
        return BAD_FUNC_ARG;
    /* Seal Object can be only of type KEYEDHASH and can not be used for
     * signing or encryption. Hash algorithm can be chosen by the developer.
     */
    XMEMSET(publicTemplate, 0, sizeof(TPMT_PUBLIC));
    publicTemplate->type = TPM_ALG_KEYEDHASH;
    publicTemplate->nameAlg = nameAlg;
    publicTemplate->objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_noDA);
    publicTemplate->parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
    return TPM_RC_SUCCESS;
}

int wolfTPM2_GetKeyTemplate_RSA_EK(TPMT_PUBLIC* publicTemplate)
{
    int ret;
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt);

    ret = GetKeyTemplateRSA(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, 2048, 0, TPM_ALG_NULL, TPM_ALG_NULL);
    if (ret == 0) {
        publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY);
        XMEMCPY(publicTemplate->authPolicy.buffer,
            TPM_20_EK_AUTH_POLICY, publicTemplate->authPolicy.size);
    }
    return ret;
}

int wolfTPM2_GetKeyTemplate_ECC_EK(TPMT_PUBLIC* publicTemplate)
{
    int ret;
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt);

    ret = GetKeyTemplateECC(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, TPM_ECC_NIST_P256, TPM_ALG_NULL, TPM_ALG_NULL);
    if (ret == 0) {
        publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY);
        XMEMCPY(publicTemplate->authPolicy.buffer,
            TPM_20_EK_AUTH_POLICY, publicTemplate->authPolicy.size);
    }
    return ret;
}

int wolfTPM2_GetKeyTemplate_RSA_SRK(TPMT_PUBLIC* publicTemplate)
{
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);

    return GetKeyTemplateRSA(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, 2048, 0, TPM_ALG_NULL, TPM_ALG_NULL);
}

int wolfTPM2_GetKeyTemplate_ECC_SRK(TPMT_PUBLIC* publicTemplate)
{
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);

    return GetKeyTemplateECC(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, TPM_ECC_NIST_P256, TPM_ALG_NULL, TPM_ALG_NULL);
}

int wolfTPM2_GetKeyTemplate_RSA_AIK(TPMT_PUBLIC* publicTemplate)
{
    int ret;
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);

    ret = GetKeyTemplateRSA(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, 2048, 0, TPM_ALG_RSASSA, TPM_ALG_SHA256);
    if (ret == 0) {
        publicTemplate->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    }
    return ret;
}

int wolfTPM2_GetKeyTemplate_ECC_AIK(TPMT_PUBLIC* publicTemplate)
{
    int ret;
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);

    ret = GetKeyTemplateECC(publicTemplate, TPM_ALG_SHA256,
        objectAttributes, TPM_ECC_NIST_P256, TPM_ALG_ECDSA, TPM_ALG_SHA256);
    if (ret == 0) {
        publicTemplate->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    }
    return ret;
}

/* Returns key size (in bytes) for the public template */
static int GetKeyTemplateSize(TPMT_PUBLIC* publicTemplate)
{
    int ret;
    if (publicTemplate == NULL) {
        return BAD_FUNC_ARG;
    }
    switch (publicTemplate->type) {
        case TPM_ALG_RSA:
            ret = publicTemplate->parameters.rsaDetail.keyBits / 8;
            break;
        case TPM_ALG_ECC:
            ret = TPM2_GetCurveSize(
                publicTemplate->parameters.eccDetail.curveID);
            break;
        case TPM_ALG_SYMCIPHER:
            ret = publicTemplate->parameters.symDetail.sym.keyBits.sym / 8;
            break;
        case TPM_ALG_KEYEDHASH:
        default:
            ret = BAD_FUNC_ARG;
    }
    return ret;
}

int wolfTPM2_SetKeyTemplate_Unique(TPMT_PUBLIC* publicTemplate,
    const byte* unique, int uniqueSz)
{
    int ret = 0;
    int keySz;

    if (publicTemplate == NULL || (unique != NULL && uniqueSz <= 0)) {
        return BAD_FUNC_ARG;
    }

    keySz = GetKeyTemplateSize(publicTemplate);
    if (keySz <= 0) {
        return BAD_FUNC_ARG;
    }

    switch (publicTemplate->type) {
        case TPM_ALG_RSA:
            if (uniqueSz == 0) {
                uniqueSz = keySz;
            }
            else if (uniqueSz > keySz) {
                uniqueSz = keySz;
            }
            if (uniqueSz > (int)sizeof(publicTemplate->unique.rsa.buffer)) {
                uniqueSz = (int)sizeof(publicTemplate->unique.rsa.buffer);
            }
            if (unique == NULL) {
                XMEMSET(publicTemplate->unique.rsa.buffer, 0, uniqueSz);
            }
            else {
                XMEMCPY(publicTemplate->unique.rsa.buffer, unique, uniqueSz);
            }
            publicTemplate->unique.rsa.size = uniqueSz;
            break;
        case TPM_ALG_ECC:
            /* ECC uses X and Y */
            if (uniqueSz == 0) {
                uniqueSz = keySz * 2;
            }
            else if (uniqueSz > keySz * 2) {
                uniqueSz = keySz * 2;
            }
            uniqueSz /= 2;
            if (uniqueSz > (int)sizeof(publicTemplate->unique.ecc.x.buffer)) {
                uniqueSz = (int)sizeof(publicTemplate->unique.ecc.x.buffer);
            }
            if (unique == NULL) {
                XMEMSET(publicTemplate->unique.ecc.x.buffer, 0, uniqueSz);
                XMEMSET(publicTemplate->unique.ecc.y.buffer, 0, uniqueSz);
            }
            else {
                XMEMCPY(publicTemplate->unique.ecc.x.buffer, unique, uniqueSz);
                XMEMCPY(publicTemplate->unique.ecc.y.buffer, unique + uniqueSz, uniqueSz);
            }
            publicTemplate->unique.ecc.x.size = uniqueSz;
            publicTemplate->unique.ecc.y.size = uniqueSz;
            break;
        case TPM_ALG_SYMCIPHER:
            if (uniqueSz == 0) {
                uniqueSz = keySz;
            }
            else if (uniqueSz > keySz) {
                uniqueSz = keySz;
            }
            if (uniqueSz > (int)sizeof(publicTemplate->unique.sym.buffer)) {
                uniqueSz = (int)sizeof(publicTemplate->unique.sym.buffer);
            }
            if (unique == NULL) {
                XMEMSET(publicTemplate->unique.sym.buffer, 0, uniqueSz);
            }
            else {
                XMEMCPY(publicTemplate->unique.sym.buffer, unique, uniqueSz);
            }
            publicTemplate->unique.sym.size = uniqueSz;
            break;
        case TPM_ALG_KEYEDHASH:
            /* not supported */
            ret = BAD_FUNC_ARG;
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }
    return ret;
}

int wolfTPM2_GetNvAttributesTemplate(TPM_HANDLE auth, word32* nvAttributes)
{
    if (nvAttributes == NULL)
        return BAD_FUNC_ARG;

    *nvAttributes = (
        TPMA_NV_AUTHWRITE  |     /* password or HMAC can authorize writing */
        TPMA_NV_AUTHREAD   |     /* password or HMAC can authorize reading */
        TPMA_NV_OWNERREAD  |     /* Allow owner to read */
        TPMA_NV_NO_DA            /* Don't increment dictionary attack counter */
    );

    if (auth == TPM_RH_PLATFORM) {
        *nvAttributes |= (
            TPMA_NV_PLATFORMCREATE | /* Platform created NV */
            TPMA_NV_PPWRITE |        /* Write may be authorized by platform */
            TPMA_NV_PPREAD           /* Read may be authorized by platform */
        );
    }
    else if (auth == TPM_RH_OWNER) {
        *nvAttributes |= (
            TPMA_NV_OWNERWRITE   /* Owner Hierarchy auth can be used to write */
        );
    }

    return 0;
}

int wolfTPM2_CreateEK(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* ekKey, TPM_ALG_ID alg)
{
    int rc;
    TPMT_PUBLIC publicTemplate;

    if (alg == TPM_ALG_RSA) {
        rc = wolfTPM2_GetKeyTemplate_RSA_EK(&publicTemplate);
    }
    else if (alg == TPM_ALG_ECC) {
        rc = wolfTPM2_GetKeyTemplate_ECC_EK(&publicTemplate);
    }
    else {
        /* Supported algorithms for EK are only RSA 2048-bit & ECC P256 */
        return BAD_FUNC_ARG;
    }
    /* GetKeyTemplate check */
    if (rc != 0)
        return rc;

    rc = wolfTPM2_CreatePrimaryKey(dev, ekKey, TPM_RH_ENDORSEMENT,
        &publicTemplate, NULL, 0);

    return rc;
}

int wolfTPM2_CreateSRK(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* srkKey, TPM_ALG_ID alg,
    const byte* auth, int authSz)
{
    int rc;
    TPMT_PUBLIC publicTemplate;

    /* Supported algorithms for SRK are only 2048bit RSA & ECC */
    if (alg == TPM_ALG_RSA) {
        rc = wolfTPM2_GetKeyTemplate_RSA_SRK(&publicTemplate);
    }
    else if (alg == TPM_ALG_ECC) {
        rc = wolfTPM2_GetKeyTemplate_ECC_SRK(&publicTemplate);
    }
    else {
        /* Supported algorithms for SRK are only RSA 2048-bit & ECC P256 */
        return BAD_FUNC_ARG;
    }
    /* GetKeyTemplate check */
    if (rc != 0)
        return rc;

    rc = wolfTPM2_CreatePrimaryKey(dev, srkKey, TPM_RH_OWNER,
        &publicTemplate, auth, authSz);

    return rc;
}

int wolfTPM2_CreateAndLoadAIK(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* aikKey,
    TPM_ALG_ID alg, WOLFTPM2_KEY* srkKey, const byte* auth, int authSz)
{
    int rc;
    TPMT_PUBLIC publicTemplate;

    if (alg == TPM_ALG_RSA) {
        rc = wolfTPM2_GetKeyTemplate_RSA_AIK(&publicTemplate);
    }
    else if (alg == TPM_ALG_ECC) {
        rc = wolfTPM2_GetKeyTemplate_ECC_AIK(&publicTemplate);
    }
    else {
        return BAD_FUNC_ARG;
    }
    /* GetKeyTemplate check */
    if (rc != 0)
        return rc;

    rc = wolfTPM2_CreateAndLoadKey(dev, aikKey, &srkKey->handle,
        &publicTemplate, auth, authSz);

    return rc;
}

int wolfTPM2_CreateKeySeal(WOLFTPM2_DEV* dev, WOLFTPM2_KEYBLOB* keyBlob,
    WOLFTPM2_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz, const byte* sealData, int sealSize)
{
    return wolfTPM2_CreateKeySeal_ex(dev, keyBlob, parent, publicTemplate, auth,
        authSz, TPM_ALG_NULL, NULL, 0, sealData, sealSize);
}

int wolfTPM2_CreateKeySeal_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEYBLOB* keyBlob,
    WOLFTPM2_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz, TPM_ALG_ID pcrAlg, byte* pcrArray,
    word32 pcrArraySz, const byte* sealData, int sealSize)
{
    int rc;
    Create_In  createIn;
    Create_Out createOut;

    if (dev == NULL || keyBlob == NULL || parent == NULL || publicTemplate == NULL)
        return BAD_FUNC_ARG;

    /* Seal size is limited to TCG defined MAX_SYM_DATA, which is 128 bytes */
    if (sealSize < 0 || sealSize > MAX_SYM_DATA) {
#ifdef DEBUG_WOLFTPM
        printf("Seal size %d should not be larger than %d bytes\n",
            sealSize, MAX_SYM_DATA);
#endif
        return BAD_FUNC_ARG;
    }

    /* clear output key buffer */
    XMEMSET(keyBlob, 0, sizeof(WOLFTPM2_KEYBLOB));
    XMEMSET(&createOut, 0, sizeof(createOut)); /* make sure pub struct is zero init */

    /* set session auth for parent key */
    wolfTPM2_SetAuthHandle(dev, 0, parent);

    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent->hndl;
    if (auth) {
        createIn.inSensitive.sensitive.userAuth.size = authSz;
        XMEMCPY(createIn.inSensitive.sensitive.userAuth.buffer, auth,
            createIn.inSensitive.sensitive.userAuth.size);
    }
    wolfTPM2_CopyPubT(&createIn.inPublic.publicArea, publicTemplate);

    /* Seal user (arbitrary) data in the newly generated TPM key */
    createIn.inSensitive.sensitive.data.size = sealSize;
    XMEMCPY(createIn.inSensitive.sensitive.data.buffer, sealData,
            createIn.inSensitive.sensitive.data.size);

    /* set the pcr selection if passed in */
    if (pcrArray != NULL) {
        TPM2_SetupPCRSelArray(&createIn.creationPCR, pcrAlg, pcrArray,
            pcrArraySz);
    }

    rc = TPM2_Create(&createIn, &createOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("wolfTPM2_CreateKeySeal failed %d: %s\n",
            rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("wolfTPM2_CreateKeySeal generated key with: pub %d, priv %d\n",
        createOut.outPublic.size, createOut.outPrivate.size);
    TPM2_PrintPublicArea(&createOut.outPublic);
#endif

    wolfTPM2_CopyAuth(&keyBlob->handle.auth, &createIn.inSensitive.sensitive.userAuth);
    wolfTPM2_CopySymmetric(&keyBlob->handle.symmetric,
            &createOut.outPublic.publicArea.parameters.asymDetail.symmetric);

    wolfTPM2_CopyPub(&keyBlob->pub, &createOut.outPublic);
    wolfTPM2_CopyPriv(&keyBlob->priv, &createOut.outPrivate);

    return rc;
}

int wolfTPM2_GetTime(WOLFTPM2_KEY* aikKey, GetTime_Out* getTimeOut)
{
    int rc;
    GetTime_In getTimeCmd;

    if (getTimeOut == NULL)
        return BAD_FUNC_ARG;

    /* GetTime */
    XMEMSET(&getTimeCmd, 0, sizeof(getTimeCmd));
    XMEMSET(getTimeOut, 0, sizeof(*getTimeOut));
    getTimeCmd.privacyAdminHandle = TPM_RH_ENDORSEMENT;
    if (aikKey != NULL) {
        TPMT_ASYM_SCHEME* scheme =
            &aikKey->pub.publicArea.parameters.asymDetail.scheme;
        getTimeCmd.signHandle = aikKey->handle.hndl;
        getTimeCmd.inScheme.scheme = scheme->scheme;
        getTimeCmd.inScheme.details.any.hashAlg = scheme->details.anySig.hashAlg;
    }
    else {
        getTimeCmd.signHandle = TPM_RH_NULL;
    }
    getTimeCmd.qualifyingData.size = 0; /* optional */
    rc = TPM2_GetTime(&getTimeCmd, getTimeOut);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_GetTime failed 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    #endif
    }

    return rc;
}

static void wolfTPM2_CopySymmetric(TPMT_SYM_DEF* out, const TPMT_SYM_DEF* in)
{
    if (out == NULL || in == NULL)
        return;

    out->algorithm = in->algorithm;
    switch (out->algorithm) {
        case TPM_ALG_XOR:
            out->keyBits.xorr = in->keyBits.xorr;
            break;
        case TPM_ALG_AES:
            out->keyBits.aes = in->keyBits.aes;
            out->mode.aes = in->mode.aes;
            break;
        case TPM_ALG_NULL:
            break;
        default:
            out->keyBits.sym = in->keyBits.sym;
            out->mode.sym = in->mode.sym;
            break;
    }
}

static void wolfTPM2_CopyName(TPM2B_NAME* out, const TPM2B_NAME* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->name))
            out->size = (UINT16)sizeof(out->name);
        XMEMCPY(out->name, in->name, out->size);
    }
}

static void wolfTPM2_CopyAuth(TPM2B_AUTH* out, const TPM2B_AUTH* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->buffer))
            out->size = (UINT16)sizeof(out->buffer);
        XMEMCPY(out->buffer, in->buffer, out->size);
    }
}

static void wolfTPM2_CopyPubT(TPMT_PUBLIC* out, const TPMT_PUBLIC* in)
{
    if (out == NULL || in == NULL)
        return;

    out->type = in->type;
    out->nameAlg = in->nameAlg;
    out->objectAttributes = in->objectAttributes;
    out->authPolicy.size = in->authPolicy.size;
    if (out->authPolicy.size > 0) {
        if (out->authPolicy.size >
                (UINT16)sizeof(out->authPolicy.buffer))
            out->authPolicy.size =
                (UINT16)sizeof(out->authPolicy.buffer);
        XMEMCPY(out->authPolicy.buffer,
                in->authPolicy.buffer,
                out->authPolicy.size);
    }

    switch (out->type) {
    case TPM_ALG_KEYEDHASH:
        out->parameters.keyedHashDetail.scheme =
            in->parameters.keyedHashDetail.scheme;

        out->unique.keyedHash.size =
            in->unique.keyedHash.size;
        if (out->unique.keyedHash.size >
                (UINT16)sizeof(out->unique.keyedHash.buffer)) {
            out->unique.keyedHash.size =
                (UINT16)sizeof(out->unique.keyedHash.buffer);
        }
        XMEMCPY(out->unique.keyedHash.buffer,
                in->unique.keyedHash.buffer,
                out->unique.keyedHash.size);
        break;
    case TPM_ALG_SYMCIPHER:
        out->parameters.symDetail.sym.algorithm =
            in->parameters.symDetail.sym.algorithm;
        out->parameters.symDetail.sym.keyBits.sym =
            in->parameters.symDetail.sym.keyBits.sym;
        out->parameters.symDetail.sym.mode.sym =
            in->parameters.symDetail.sym.mode.sym;

        out->unique.sym.size =
            in->unique.sym.size;
        if (out->unique.sym.size >
                (UINT16)sizeof(out->unique.sym.buffer)) {
            out->unique.sym.size =
                (UINT16)sizeof(out->unique.sym.buffer);
        }
        XMEMCPY(out->unique.sym.buffer,
                in->unique.sym.buffer,
                out->unique.sym.size);
        break;
    case TPM_ALG_RSA:
        wolfTPM2_CopySymmetric(&out->parameters.rsaDetail.symmetric,
            &in->parameters.rsaDetail.symmetric);
        out->parameters.rsaDetail.scheme.scheme =
            in->parameters.rsaDetail.scheme.scheme;
        if (out->parameters.rsaDetail.scheme.scheme != TPM_ALG_NULL)
            out->parameters.rsaDetail.scheme.details.anySig.hashAlg =
                in->parameters.rsaDetail.scheme.details.anySig.hashAlg;
        out->parameters.rsaDetail.keyBits =
            in->parameters.rsaDetail.keyBits;
        out->parameters.rsaDetail.exponent =
            in->parameters.rsaDetail.exponent;

        out->unique.rsa.size =
            in->unique.rsa.size;
        if (out->unique.rsa.size >
                (UINT16)sizeof(out->unique.rsa.buffer)) {
            out->unique.rsa.size =
                (UINT16)sizeof(out->unique.rsa.buffer);
        }
        XMEMCPY(out->unique.rsa.buffer,
                in->unique.rsa.buffer,
                out->unique.rsa.size);
        break;
    case TPM_ALG_ECC:
        wolfTPM2_CopySymmetric(&out->parameters.eccDetail.symmetric,
            &in->parameters.eccDetail.symmetric);
        out->parameters.eccDetail.scheme.scheme =
            in->parameters.eccDetail.scheme.scheme;
        out->parameters.eccDetail.scheme.details.any.hashAlg =
            in->parameters.eccDetail.scheme.details.any.hashAlg;
        out->parameters.eccDetail.curveID =
            in->parameters.eccDetail.curveID;
        out->parameters.eccDetail.kdf.scheme =
            in->parameters.eccDetail.kdf.scheme;
        out->parameters.eccDetail.kdf.details.any.hashAlg =
            in->parameters.eccDetail.kdf.details.any.hashAlg;
        wolfTPM2_CopyEccParam(&out->unique.ecc.x,
            &in->unique.ecc.x);
        wolfTPM2_CopyEccParam(&out->unique.ecc.y,
            &in->unique.ecc.y);
        break;
    default:
        wolfTPM2_CopySymmetric(&out->parameters.asymDetail.symmetric,
            &in->parameters.asymDetail.symmetric);
        out->parameters.asymDetail.scheme.scheme =
            in->parameters.asymDetail.scheme.scheme;
        out->parameters.asymDetail.scheme.details.anySig.hashAlg =
            in->parameters.asymDetail.scheme.details.anySig.hashAlg;
        break;
    }
}

static void wolfTPM2_CopyPub(TPM2B_PUBLIC* out, const TPM2B_PUBLIC* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        wolfTPM2_CopyPubT(&out->publicArea, &in->publicArea);
    }
}

static void wolfTPM2_CopyPriv(TPM2B_PRIVATE* out, const TPM2B_PRIVATE* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->buffer))
            out->size = (UINT16)sizeof(out->buffer);
        XMEMCPY(out->buffer, in->buffer, out->size);
    }
}

static void wolfTPM2_CopyEccParam(TPM2B_ECC_PARAMETER* out,
    const TPM2B_ECC_PARAMETER* in)
{
    if (out != NULL && in != NULL) {
        out->size = in->size;
        if (out->size > (UINT16)sizeof(out->buffer))
            out->size = (UINT16)sizeof(out->buffer);
        XMEMCPY(out->buffer, in->buffer, out->size);
    }
}

static void wolfTPM2_CopyKeyFromBlob(WOLFTPM2_KEY* key, const WOLFTPM2_KEYBLOB* keyBlob)
{
    if (key != NULL && keyBlob != NULL) {
        key->handle.hndl = keyBlob->handle.hndl;
        wolfTPM2_CopyAuth(&key->handle.auth, &keyBlob->handle.auth);
        wolfTPM2_CopyName(&key->handle.name, &keyBlob->handle.name);
        wolfTPM2_CopySymmetric(&key->handle.symmetric, &keyBlob->handle.symmetric);
        wolfTPM2_CopyPub(&key->pub, &keyBlob->pub);
    }
}

static void wolfTPM2_CopyNvPublic(TPMS_NV_PUBLIC* out, const TPMS_NV_PUBLIC* in)
{
    if (out != NULL && in != NULL) {
        out->attributes = in->attributes;
        out->authPolicy.size = in->authPolicy.size;
        if (out->authPolicy.size > 0) {
            if (out->authPolicy.size > (UINT16)sizeof(out->authPolicy.buffer)) {
                out->authPolicy.size = (UINT16)sizeof(out->authPolicy.buffer);
            }
            XMEMCPY(out->authPolicy.buffer, in->authPolicy.buffer, out->authPolicy.size);
        }
        out->dataSize = in->dataSize;
        out->nameAlg = in->nameAlg;
        out->nvIndex = in->nvIndex;
    }
}

/******************************************************************************/
/* --- END Utility Functions -- */
/******************************************************************************/


/******************************************************************************/
/* --- BEGIN Certificate Signing Request (CSR) Functions -- */
/******************************************************************************/

#if defined(WOLFTPM2_CERT_GEN) && defined(WOLFTPM_CRYPTOCB)

/* Distinguished Name Strings */
typedef struct DNTags {
    const char* tag;
    size_t certNameOff;
} DNTags;

static int CSR_Parse_DN(CertName* name, const char* subject)
{
    int rc = 0, i;
    const DNTags tags[] = {
        {"/CN=",     OFFSETOF(CertName, commonName)}, /* Common Name */
        {"/C=",      OFFSETOF(CertName, country)},    /* Country */
        {"/ST=",     OFFSETOF(CertName, state)},      /* State */
        {"/street=", OFFSETOF(CertName, street)},     /* Street */
        {"/L=",      OFFSETOF(CertName, locality)},   /* Locality */
        {"/SN=",     OFFSETOF(CertName, sur)},        /* Surname */
        {"/O=",      OFFSETOF(CertName, org)},        /* Organization */
        {"/OU=",     OFFSETOF(CertName, unit)},       /* Organization Unit */
        {"/postalCode=",   OFFSETOF(CertName, postalCode)}, /* PostalCode */
        {"/userid=",       OFFSETOF(CertName, userId)},     /* UserID */
        {"/serialNumber=", OFFSETOF(CertName, serialDev)},  /* Serial Number */
        {"/emailAddress=", OFFSETOF(CertName, email)},      /* Email Address */
    #ifdef WOLFSSL_CERT_EXT
        {"/businessCategory=", OFFSETOF(CertName, busCat)}, /* Business Category */
    #endif
    };

    for (i = 0; i < (int)(sizeof(tags) / sizeof(DNTags)); i++) {
        const char *begin, *end;
        word32 len = 0;
        /* find start tag */
        begin = XSTRSTR(subject, tags[i].tag);
        if (begin != NULL) {
            /* find end of string or / */
            begin += XSTRLEN(tags[i].tag);
            end = XSTRSTR(begin, "/");
            if (end == NULL) {
                end = begin + XSTRLEN(begin); /* remainder of string */
            }
            if (end > begin) {
                len = (word32)(size_t)(end - begin);
            }
            if (len > CTC_NAME_SIZE-1) {
                len = CTC_NAME_SIZE-1; /* leave room for null term */
            }
            XMEMCPY((byte*)name + tags[i].certNameOff, begin, len);
        }
    }
    return rc;
}

typedef struct CSRKey {
    int keyType;
    int tpmDevId;
    WOLFTPM2_KEY* tpmKey;
    union {
    #ifndef NO_RSA
        RsaKey rsa;
    #endif
    #ifdef HAVE_ECC
        ecc_key ecc;
    #endif
    } key;
    TpmCryptoDevCtx tpmCtx;
} CSRKey;

static int CSR_MakeAndSign(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr, CSRKey* key,
    int outFormat, byte* out, int outSz, int selfSignCert)
{
    int rc = 0;

    if (dev == NULL || csr == NULL || key == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    if (rc == 0 && selfSignCert) {
    #ifdef WOLFSSL_CERT_GEN
        rc = wc_MakeCert_ex(&csr->req, out, outSz, key->keyType, &key->key,
            wolfTPM2_GetRng(dev));
    #else
        rc = NOT_COMPILED_IN;
    #endif
    }
    if (rc == 0 && !selfSignCert) {
        rc = wc_MakeCertReq_ex(&csr->req, out, outSz, key->keyType, &key->key);
    }

    if (rc >= 0) {
        rc = wc_SignCert_ex(csr->req.bodySz, csr->req.sigType, out,
            (word32)outSz, key->keyType, &key->key, wolfTPM2_GetRng(dev));
    }

    /* Optionally convert to PEM */
    if (rc >= 0 && outFormat == CTC_FILETYPE_PEM) {
    #ifdef WOLFSSL_DER_TO_PEM
        WOLFTPM2_BUFFER tmp;
        tmp.size = rc;
        if (rc > (int)sizeof(tmp.buffer)) {
            rc = BUFFER_E;
        }
        else {
            XMEMCPY(tmp.buffer, out, rc);
            XMEMSET(out, 0, outSz);
            rc = wc_DerToPem(tmp.buffer, tmp.size, out, outSz,
                selfSignCert ? CERT_TYPE : CERTREQ_TYPE);
        }
    #else
        #ifdef DEBUG_WOLFTPM
        printf("CSR_MakeAndSign PEM not supported\n")
        #endif
        rc = NOT_COMPILED_IN;
    #endif
    }

    return rc;
}

static int CSR_KeySetup(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr, WOLFTPM2_KEY* key,
    CSRKey* csrKey, int sigType, int devId)
{
    int rc;

    if (dev == NULL || key == NULL || csrKey == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(csrKey, 0, sizeof(CSRKey));
    csrKey->tpmDevId = INVALID_DEVID;
    csrKey->tpmKey = key;

    /* confirm crypto callback is setup */
    if (devId == INVALID_DEVID) {
        /* Setup the wolf crypto device callback */
    #ifndef NO_RSA
        csrKey->tpmCtx.rsaKey = key;
    #endif
    #ifdef HAVE_ECC
        csrKey->tpmCtx.eccKey = key;
    #endif

        rc = wolfTPM2_GetTpmDevId(dev);
        if (rc >= 0) {
            devId = rc;
            devId += 1; /* use a different devId for the CSR callback */
            rc = 0;
        }
        if (rc == 0) {
            csrKey->tpmCtx.dev = dev;
            rc = wc_CryptoCb_RegisterDevice(devId, wolfTPM2_CryptoDevCb,
                &csrKey->tpmCtx);
        }
        if (rc != 0) {
            return rc;
        }
        csrKey->tpmDevId = devId;
    }

    /* determine the type of key in WOLFTPM2_KEY */
    if (key->pub.publicArea.type == TPM_ALG_ECC) {
        csrKey->keyType = ECC_TYPE;

    #ifdef HAVE_ECC
        /* setup wolf ECC key with TPM deviceID, so crypto callbacks are used */
        rc = wc_ecc_init_ex(&csrKey->key.ecc, NULL, devId);
        if (rc == 0) {
            /* load public portion of key into wolf ECC Key */
            rc = wolfTPM2_EccKey_TpmToWolf(dev, key, &csrKey->key.ecc);
        }
    #else
        rc = NOT_COMPILED_IN;
    #endif
    }
    else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        csrKey->keyType = RSA_TYPE;

    #ifndef NO_RSA
        /* setup wolf RSA key with TPM deviceID, so crypto callbacks are used */
        rc = wc_InitRsaKey_ex(&csrKey->key.rsa, NULL, devId);
        if (rc == 0) {
            /* load public portion of key into wolf RSA Key */
            rc = wolfTPM2_RsaKey_TpmToWolf(dev, key, &csrKey->key.rsa);
        }
    #else
        rc = NOT_COMPILED_IN;
    #endif
    }
    else {
    #ifdef DEBUG_WOLFTPM
        printf("CSR_KeySetup invalid input key\n");
    #endif
        rc = BAD_FUNC_ARG;
    }

    /* Set the signature type */
    if (rc == 0) {
        if (sigType == 0 && csrKey != NULL) {
            /* Choose defaults if sigType is zero */
            if (csrKey->keyType == RSA_TYPE) {
                csr->req.sigType = CTC_SHA256wRSA;
            }
            else if (csrKey->keyType == ECC_TYPE) {
                csr->req.sigType = CTC_SHA256wECDSA;
            }
        }
        else if (sigType != 0) {
            csr->req.sigType = sigType;
        }
    }

#ifdef WOLFSSL_CERT_EXT
    /* add SKID from the Public Key */
    if (rc == 0 && csrKey != NULL) {
        rc = wc_SetSubjectKeyIdFromPublicKey_ex(&csr->req, csrKey->keyType,
            &csrKey->key);
    }
#endif

    return rc;
}

static void CSR_KeyCleanup(WOLFTPM2_DEV* dev, CSRKey* csrKey)
{
    if (dev != NULL && csrKey != NULL) {
    #ifdef HAVE_ECC
        if (csrKey->keyType == ECC_TYPE) {
            wc_ecc_free(&csrKey->key.ecc);
        }
    #endif
    #ifndef NO_RSA
        if (csrKey->keyType == RSA_TYPE) {
            wc_FreeRsaKey(&csrKey->key.rsa);
        }
    #endif
        if (csrKey->tpmDevId != INVALID_DEVID) {
            wolfTPM2_ClearCryptoDevCb(dev, csrKey->tpmDevId);
        }
    }
}

int wolfTPM2_CSR_SetCustomExt(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr,
    int critical, const char *oid, const byte *der, word32 derSz)
{
    int rc;
    if (csr == NULL) {
        return BAD_FUNC_ARG;
    }
#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_CUSTOM_OID) && \
    defined(HAVE_OID_ENCODING)
    rc = wc_SetCustomExtension(&csr->req, critical, oid, der, derSz);
#else
    (void)critical;
    (void)oid;
    (void)der;
    (void)derSz;
    /* Requires:
     * ./configure --enable-wolftpm --enable-certgen --enable-asn=template \
                 CFLAGS="-DWOLFSSL_CUSTOM_OID -DHAVE_OID_ENCODING"
     */
    rc = NOT_COMPILED_IN;
#endif
    (void)dev; /* not used */
    return rc;
}

int wolfTPM2_CSR_SetSubject(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr,
    const char* subject)
{
    int rc = BAD_FUNC_ARG;
    if (csr != NULL && subject != NULL) {
        rc = CSR_Parse_DN(&csr->req.subject, subject);
    }
    (void)dev; /* not used */
    return rc;
}

int wolfTPM2_CSR_SetKeyUsage(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr,
    const char* keyUsage)
{
    int rc;

    if (csr == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_CERT_EXT
    if (keyUsage == NULL) {
        /* use a default key usage value */
        keyUsage = "serverAuth,clientAuth,codeSigning";
    }

    /* add Extended Key Usage */
    rc = wc_SetExtKeyUsage(&csr->req, keyUsage);
    if (rc == EXTKEYUSAGE_E) {
        /* try setting key usage values */
        rc = wc_SetKeyUsage(&csr->req, keyUsage);
    }
#else
    if (keyUsage != NULL) {
    #ifdef DEBUG_WOLFTPM
        printf("CSR_Generate key usage supplied, but not available\n");
    #endif
        rc = NOT_COMPILED_IN;
    }
#endif
    (void)dev; /* not used */
    return rc;
}

int wolfTPM2_CSR_MakeAndSign_ex(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr,
    WOLFTPM2_KEY* key, int outFormat, byte* out, int outSz,
    int sigType, int selfSignCert, int devId)
{
    int rc;
    CSRKey csrKey;

    if (dev == NULL || key == NULL || csr == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    rc = CSR_KeySetup(dev, csr, key, &csrKey, sigType, devId);
    if (rc == 0) {
        rc = CSR_MakeAndSign(dev, csr, &csrKey, outFormat, out, outSz,
            selfSignCert);
    }
    CSR_KeyCleanup(dev, &csrKey);

    return rc;
}
int wolfTPM2_CSR_MakeAndSign(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr,
    WOLFTPM2_KEY* key, int outFormat, byte* out, int outSz)
{
    return wolfTPM2_CSR_MakeAndSign_ex(dev, csr, key, outFormat, out, outSz,
        0, 0, INVALID_DEVID);
}

int wolfTPM2_CSR_Generate_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const char* subject, const char* keyUsage, int outFormat,
    byte* out, int outSz, int sigType, int selfSignCert, int devId)
{
    int rc;
    WOLFTPM2_CSR csr;
    CSRKey csrKey;

    if (dev == NULL || key == NULL || subject == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&csrKey, 0, sizeof(csrKey));
    rc = wc_InitCert(&csr.req);
    if (rc == 0) {
        rc = CSR_KeySetup(dev, &csr, key, &csrKey, sigType, devId);
    }
    if (rc == 0) {
        rc = wolfTPM2_CSR_SetSubject(dev, &csr, subject);
    }
    if (rc == 0) {
        rc = wolfTPM2_CSR_SetKeyUsage(dev, &csr, keyUsage);
    }
    if (rc == 0) {
        rc = CSR_MakeAndSign(dev, &csr, &csrKey, outFormat, out, outSz,
            selfSignCert);
    }
    CSR_KeyCleanup(dev, &csrKey);

    return rc;
}

int wolfTPM2_CSR_Generate(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const char* subject, const char* keyUsage, int outFormat,
    byte* out, int outSz)
{
    return wolfTPM2_CSR_Generate_ex(dev, key, subject, keyUsage, outFormat,
        out, outSz, 0, 0, INVALID_DEVID);
}

#endif /* WOLFTPM2_CERT_GEN && WOLFTPM_CRYPTOCB */

/******************************************************************************/
/* --- END Certificate Signing Request (CSR) Functions -- */
/******************************************************************************/



/******************************************************************************/
/* --- BEGIN Policy Support -- */
/******************************************************************************/

int wolfTPM2_PolicyRestart(WOLFTPM2_DEV* dev, TPM_HANDLE sessionHandle)
{
    int rc;
    PolicyRestart_In policyRestartIn[1];

    if (dev == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(policyRestartIn, 0, sizeof(PolicyRestart_In));

    policyRestartIn->sessionHandle = sessionHandle;

    rc = TPM2_PolicyRestart(policyRestartIn);

    return rc;
}

int wolfTPM2_GetPolicyDigest(WOLFTPM2_DEV* dev, TPM_HANDLE sessionHandle,
    byte* policyDigest, word32* policyDigestSz)
{
    int rc;
    PolicyGetDigest_In policyGetDigestIn[1];
    PolicyGetDigest_Out policyGetDigestOut[1];

    if (dev == NULL || policyDigestSz == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(policyGetDigestIn, 0, sizeof(PolicyGetDigest_In));
    XMEMSET(policyGetDigestOut, 0, sizeof(PolicyGetDigest_Out));

    policyGetDigestIn->policySession = sessionHandle;

    rc = TPM2_PolicyGetDigest(policyGetDigestIn, policyGetDigestOut);

    if (rc == 0) {
        if (policyDigest == NULL) {
            rc = LENGTH_ONLY_E;
        }
        else if (policyGetDigestOut->policyDigest.size > *policyDigestSz) {
            rc = BUFFER_E;
        }
        else {
            XMEMCPY(policyDigest, policyGetDigestOut->policyDigest.buffer,
                policyGetDigestOut->policyDigest.size);
        }

        *policyDigestSz = policyGetDigestOut->policyDigest.size;
    }

    return rc;
}

int wolfTPM2_PolicyPCR(WOLFTPM2_DEV* dev, TPM_HANDLE sessionHandle,
    TPM_ALG_ID pcrAlg, byte* pcrArray, word32 pcrArraySz)
{
    int rc;
    PolicyPCR_In policyPcr[1];

    if (dev == NULL || pcrArray == NULL || pcrArraySz == 0)
        return BAD_FUNC_ARG;

    XMEMSET(policyPcr, 0, sizeof(PolicyPCR_In));

    /* add PolicyPCR to the policy */
    policyPcr->policySession = sessionHandle;
    TPM2_SetupPCRSelArray(&policyPcr->pcrs, pcrAlg, pcrArray, pcrArraySz);

    rc = TPM2_PolicyPCR(policyPcr);

    return rc;
}

#ifndef WOLFTPM2_NO_WOLFCRYPT
/* Authorize a policy based on external key for a verified policy digiest signature */
int wolfTPM2_PolicyAuthorize(WOLFTPM2_DEV* dev, TPM_HANDLE sessionHandle,
    const TPM2B_PUBLIC* pub, const TPMT_TK_VERIFIED* checkTicket,
    const byte* pcrDigest, word32 pcrDigestSz,
    const byte* policyRef, word32 policyRefSz)
{
    int rc;
    PolicyAuthorize_In policyAuthIn;

    if (dev == NULL || pub == NULL || checkTicket == NULL || pcrDigest == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&policyAuthIn, 0, sizeof(policyAuthIn));
    policyAuthIn.policySession = sessionHandle;
    XMEMCPY(&policyAuthIn.checkTicket, checkTicket, sizeof(TPMT_TK_VERIFIED));

    /* set the approved policy digest */
    policyAuthIn.approvedPolicy.size = pcrDigestSz;
    XMEMCPY(policyAuthIn.approvedPolicy.buffer, pcrDigest, pcrDigestSz);

    /* policyRef (nonce) */
    policyAuthIn.policyRef.size = policyRefSz;
    if (policyRef != NULL) {
        XMEMCPY(policyAuthIn.policyRef.buffer, policyRef, policyRefSz);
    }

    /* Compute name for the authoring public key for policy */
    rc = wolfTPM2_ComputeName(pub, &policyAuthIn.keySign);
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2_PolicyAuthorize(&policyAuthIn);
    }
#ifdef DEBUG_WOLFTPM
    if (rc != TPM_RC_SUCCESS) {
        printf("PolicyAuthorize failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
    }
#endif
    return rc;
}

/* Build Hash of PCR's */
int wolfTPM2_PCRGetDigest(WOLFTPM2_DEV* dev, TPM_ALG_ID pcrAlg,
    byte* pcrArray, word32 pcrArraySz, byte* pcrDigest, word32* pcrDigestSz)
{
    int rc;
    word32 i;
    enum wc_HashType hashType;
    wc_HashAlg hash_ctx;

    if (dev == NULL || pcrArray == NULL || pcrArraySz == 0 ||
            pcrDigest == NULL || pcrDigestSz == NULL) {
        return BAD_FUNC_ARG;
    }

    rc = TPM2_GetHashType(pcrAlg);
    hashType = (enum wc_HashType)rc;
    rc = wc_HashGetDigestSize(hashType);
    if (rc < 0)
        return rc;
    *pcrDigestSz = rc; /* set actual size */

    rc = wc_HashInit(&hash_ctx, hashType);
    if (rc != 0)
        return rc;

    /* PCR(s) hash */
    for (i=0; i<pcrArraySz && rc == 0; i++) {
        rc = wolfTPM2_ReadPCR(dev, pcrArray[i], pcrAlg,
            pcrDigest, (int*)pcrDigestSz);
        if (rc == 0) {
            rc = wc_HashUpdate(&hash_ctx, hashType, pcrDigest, *pcrDigestSz);
        }
    }
    if (rc == 0) {
        rc = wc_HashFinal(&hash_ctx, hashType, pcrDigest);
    }
    wc_HashFree(&hash_ctx, hashType);

#ifdef DEBUG_WOLFTPM
    if (rc != 0) {
        printf("wolfTPM2_PCRGetDigest failed %d: %s\n",
            rc, wolfTPM2_GetRCString(rc));
    }
    #ifdef WOLFTPM_DEBUG_VERBOSE
    else {
        printf("wolfTPM2_PCRGetDigest: %d\n", *pcrDigestSz);
        TPM2_PrintBin(pcrDigest, *pcrDigestSz);
    }
    #endif
#endif
    return rc;
}

/* Assemble a PCR policy */
/* policyDigestnew = hash(policyDigestOld || TPM_CC_PolicyPCR  || PCRS ||
 *                        pcrDigest) */
int wolfTPM2_PolicyPCRMake(TPM_ALG_ID pcrAlg, byte* pcrArray, word32 pcrArraySz,
    const byte* pcrDigest, word32 pcrDigestSz, byte* digest, word32* digestSz)
{
    int rc;
    word32 val;
    enum wc_HashType hashType;
    wc_HashAlg hash_ctx;
    word32 inSz;

    if (pcrArray == NULL || pcrArraySz == 0 || digest == NULL ||
            digestSz == NULL) {
        return BAD_FUNC_ARG;
    }

    inSz = *digestSz; /* capture input digest size (for policyDigestOld) */
    rc = TPM2_GetHashType(pcrAlg);
    hashType = (enum wc_HashType)rc;
    rc = wc_HashGetDigestSize(hashType);
    if (rc < 0)
        return rc;
    *digestSz = rc; /* set actual size */

    rc = wc_HashInit(&hash_ctx, hashType);
    if (rc != 0)
        return rc;

    /* policyDigestOld */
    if (rc == 0 && inSz > 0) {
        rc = wc_HashUpdate(&hash_ctx, hashType, digest, inSz);
    }
    /* Command Code */
    if (rc == 0) {
        val = TPM2_Packet_SwapU32(TPM_CC_PolicyPCR);
        rc = wc_HashUpdate(&hash_ctx, hashType, (byte*)&val, sizeof(val));
    }
    /* PCR Count and PCR Selection */
    if (rc == 0) {
        TPM2_Packet packet;
        byte buf[sizeof(TPML_PCR_SELECTION)];
        TPML_PCR_SELECTION pcr;
        XMEMSET(&pcr, 0, sizeof(pcr));
        XMEMSET(&packet, 0, sizeof(packet));

        TPM2_SetupPCRSelArray(&pcr, pcrAlg, pcrArray, pcrArraySz);
        packet.buf = buf;
        packet.size = sizeof(buf);
        TPM2_Packet_AppendPCR(&packet, &pcr);
        rc = wc_HashUpdate(&hash_ctx, hashType, buf, packet.pos);
    }
    /* Hash of PCR(s) */
    if (rc == 0) {
        rc = wc_HashUpdate(&hash_ctx, hashType, pcrDigest, pcrDigestSz);
    }
    if (rc == 0) {
        rc = wc_HashFinal(&hash_ctx, hashType, digest);
    }
    wc_HashFree(&hash_ctx, hashType);

#ifdef DEBUG_WOLFTPM
    if (rc != 0) {
        printf("wolfTPM2_PolicyPCRMake failed %d: %s\n",
            rc, wolfTPM2_GetRCString(rc));
    }
    #ifdef WOLFTPM_DEBUG_VERBOSE
    else {
        printf("wolfTPM2_PolicyPCRMake: %d\n", *digestSz);
        TPM2_PrintBin(digest, *digestSz);
    }
    #endif
#endif
    return rc;
}

/* Assemble a PCR policy ref - optional */
/* aHash = hash(approvedPolicy || policyRef) */
int wolfTPM2_PolicyRefMake(TPM_ALG_ID pcrAlg, byte* digest, word32* digestSz,
    const byte* policyRef, word32 policyRefSz)
{
    int rc;
    enum wc_HashType hashType;
    wc_HashAlg hash_ctx;
    word32 inSz;

    if (digest == NULL || digestSz == NULL ||
            (policyRef == NULL && policyRefSz > 0)) {
        return BAD_FUNC_ARG;
    }

    inSz = *digestSz; /* capture input digest size (for approvedPolicy) */
    rc = TPM2_GetHashType(pcrAlg);
    hashType = (enum wc_HashType)rc;
    rc = wc_HashGetDigestSize(hashType);
    if (rc < 0)
        return rc;
    *digestSz = rc; /* set actual size */

    rc = wc_HashInit(&hash_ctx, hashType);
    if (rc != 0)
        return rc;

    /* approvedPolicy */
    if (rc == 0 && inSz > 0) {
        rc = wc_HashUpdate(&hash_ctx, hashType, digest, inSz);
    }
    /* policyRef */
    if (rc == 0 && policyRefSz > 0) {
        rc = wc_HashUpdate(&hash_ctx, hashType, policyRef, policyRefSz);
    }
    if (rc == 0) {
        rc = wc_HashFinal(&hash_ctx, hashType, digest);
    }

    wc_HashFree(&hash_ctx, hashType);

#ifdef DEBUG_WOLFTPM
    if (rc != 0) {
        printf("wolfTPM_PolicyRefMake failed %d: %s\n",
            rc, wolfTPM2_GetRCString(rc));
    }
    #ifdef WOLFTPM_DEBUG_VERBOSE
    else {
        printf("wolfTPM_PolicyRefMake: %d\n", *digestSz);
        TPM2_PrintBin(digest, *digestSz);
    }
    #endif
#endif
    return rc;
}

/* Assemble a PCR Authorization for a public key */
/* policyDigestnew = hash(policyDigestOld || TPM_CC_PolicyAuthorize ||
 *                        Public.Name || PolicyRef) */
int wolfTPM2_PolicyAuthorizeMake(TPM_ALG_ID pcrAlg,
    const TPM2B_PUBLIC* pub, byte* digest, word32* digestSz,
    const byte* policyRef, word32 policyRefSz)
{
    int rc;
    word32 val;
    enum wc_HashType hashType;
    wc_HashAlg hash_ctx;
    word32 inSz;

    if (pub == NULL || digest == NULL || digestSz == NULL) {
        return BAD_FUNC_ARG;
    }

    inSz = *digestSz; /* capture input digest size (for policyDigestOld) */
    rc = TPM2_GetHashType(pcrAlg);
    hashType = (enum wc_HashType)rc;
    rc = wc_HashGetDigestSize(hashType);
    if (rc < 0)
        return rc;
    *digestSz = rc;

    rc = wc_HashInit(&hash_ctx, hashType);
    if (rc != 0)
        return rc;

    /* policyDigestOld */
    if (rc == 0 && inSz > 0) {
        rc = wc_HashUpdate(&hash_ctx, hashType, digest, inSz);
    }
    /* Command Code */
    if (rc == 0) {
        val = TPM2_Packet_SwapU32(TPM_CC_PolicyAuthorize);
        rc = wc_HashUpdate(&hash_ctx, hashType, (byte*)&val, sizeof(val));
    }
    /* Public Name Compute */
    if (rc == 0) {
        TPM2B_NAME name;
        rc = wolfTPM2_ComputeName(pub, &name);
        if (rc == 0) {
            rc = wc_HashUpdate(&hash_ctx, hashType, name.name, name.size);
        }
    }
    if (rc == 0) {
        rc = wc_HashFinal(&hash_ctx, hashType, digest);
    }
    wc_HashFree(&hash_ctx, hashType);

    if (rc == 0) {
        rc = wolfTPM2_PolicyRefMake(pcrAlg, digest, digestSz,
            policyRef, policyRefSz);
    }

#ifdef DEBUG_WOLFTPM
    if (rc != 0) {
        printf("wolfTPM2_PolicyAuthorizeMake failed %d: %s\n",
            rc, wolfTPM2_GetRCString(rc));
    }
    #ifdef WOLFTPM_DEBUG_VERBOSE
    else {
        printf("wolfTPM2_PolicyAuthorizeMake: %d\n", *digestSz);
        TPM2_PrintBin(digest, *digestSz);
    }
    #endif
#endif
    return rc;
}
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

/******************************************************************************/
/* --- END Policy Support -- */
/******************************************************************************/



/******************************************************************************/
/* --- BEGIN Provisioned TPM Support -- */
/******************************************************************************/

/* pre-provisioned IAK and IDevID key/cert from TPM vendor */
#ifdef WOLFTPM_MFG_IDENTITY

#ifdef TEST_SAMPLE
static const uint8_t TPM2_IAK_SAMPLE_MASTER_PASSWORD[] = {
    0xFE, 0xEF, 0x8C, 0xDF, 0x1B, 0x77, 0xBD, 0x00,
    0x30, 0x58, 0x5E, 0x47, 0xB8, 0x21, 0x46, 0x0B
};
#endif

int wolfTPM2_SetIdentityAuth(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* handle,
    uint8_t* masterPassword, uint16_t masterPasswordSz)
{
    int rc;
    uint8_t serialNum[7];
    wc_HashAlg hash_ctx;
    enum wc_HashType hashType = WC_HASH_TYPE_SHA256;
    uint8_t digest[TPM_SHA256_DIGEST_SIZE];

    /* Get TPM serial number */
    rc = TPM2_GetProductInfo(serialNum, (uint16_t)sizeof(serialNum));
    if (rc != 0) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_GetProductInfo failed %d: %s\n",
            rc, wolfTPM2_GetRCString(rc));
    #endif
        return rc;
    }

    /* Hash both values */
    rc = wc_HashInit(&hash_ctx, hashType);
    if (rc == 0) {
        rc = wc_HashUpdate(&hash_ctx, hashType, serialNum, sizeof(serialNum));
        if (rc == 0) {
        #ifdef TEST_SAMPLE
            rc = wc_HashUpdate(&hash_ctx, hashType,
                TPM2_IAK_SAMPLE_MASTER_PASSWORD,
                sizeof(TPM2_IAK_SAMPLE_MASTER_PASSWORD));
            (void)masterPassword;
            (void)masterPasswordSz;
        #else
            rc = wc_HashUpdate(&hash_ctx, hashType,
                masterPassword, masterPasswordSz);
        #endif
        }
        if (rc == 0) {
            rc = wc_HashFinal(&hash_ctx, hashType, digest);
        }

        wc_HashFree(&hash_ctx, hashType);
    }

    /* Hash Final truncate to 16 bytes */
    /* Use 16-byte for auth when accessing key */
    handle->auth.size = 16;
    XMEMCPY(handle->auth.buffer, &digest[16], 16);

    (void)dev;

    return rc;
}

#endif /* WOLFTPM_MFG_IDENTITY */

/******************************************************************************/
/* --- END Provisioned TPM Support -- */
/******************************************************************************/





/******************************************************************************/
/* --- BEGIN Firmware Upgrade Support -- */
/******************************************************************************/

#ifdef WOLFTPM_FIRMWARE_UPGRADE
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)

/* Maximum size of firmware chunks */
#define IFX_FW_MAX_CHUNK_SZ 1024

/* Setup the policy to enable firmware upgrade start */
static int tpm2_ifx_firmware_enable_policy(WOLFTPM2_DEV* dev)
{
    int rc;
    PolicyCommandCode_In policyCC;
    SetPrimaryPolicy_In policy;
    WOLFTPM2_SESSION tpmSession;

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&policyCC, 0, sizeof(policyCC));
    XMEMSET(&policy, 0, sizeof(policy));

    rc = wolfTPM2_StartSession(dev, &tpmSession, NULL, NULL,
        TPM_SE_POLICY, TPM_ALG_NULL);
    if (rc == TPM_RC_SUCCESS) {
        policyCC.policySession = tpmSession.handle.hndl;
        policyCC.code = TPM_CC_FieldUpgradeStartVendor;
        rc = TPM2_PolicyCommandCode(&policyCC);
        if (rc == TPM_RC_SUCCESS) {
            word32 policySz = (word32)sizeof(policy.authPolicy.buffer);
            rc = wolfTPM2_GetPolicyDigest(dev, tpmSession.handle.hndl,
                policy.authPolicy.buffer, &policySz);
            policy.authPolicy.size = policySz;
        }
        wolfTPM2_UnloadHandle(dev, &tpmSession.handle);
    }
    if (rc == TPM_RC_SUCCESS) {
        policy.authHandle = TPM_RH_PLATFORM;
        policy.hashAlg = TPM_ALG_SHA256;
        rc = TPM2_SetPrimaryPolicy(&policy);
    }

#ifdef DEBUG_WOLFTPM
    if (rc != TPM_RC_SUCCESS) {
        printf("Enable firmware start policy failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }
#endif
    return rc;
}

static int tpm2_ifx_firmware_start(WOLFTPM2_DEV* dev, TPM_ALG_ID hashAlg,
    uint8_t* manifest_hash, uint32_t manifest_hash_sz)
{
    int rc;
    WOLFTPM2_SESSION tpmSession;
    PolicyCommandCode_In policyCC;

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&policyCC, 0, sizeof(policyCC));

    rc = wolfTPM2_StartSession(dev, &tpmSession, NULL, NULL,
        TPM_SE_POLICY, TPM_ALG_NULL);
    if (rc == TPM_RC_SUCCESS) {
        policyCC.policySession = tpmSession.handle.hndl;
        policyCC.code = TPM_CC_FieldUpgradeStartVendor;
        rc = TPM2_PolicyCommandCode(&policyCC);
        if (rc == TPM_RC_SUCCESS) {
            /* build command for manifest header */
            uint16_t val16;
            /* max cmd: type (1) + data sz (2) + hash alg (2) + max digest (64) */
            uint8_t cmd[1 + 2 + 2 + TPM_SHA512_DIGEST_SIZE];
            cmd[0] = 0x01; /* type */
            val16 = be16_to_cpu(manifest_hash_sz + 2);
            XMEMCPY(&cmd[1], &val16, sizeof(val16)); /* data size */
            val16 = be16_to_cpu(hashAlg);
            XMEMCPY(&cmd[3], &val16, sizeof(val16)); /* hash algorithm */
            XMEMCPY(&cmd[5], manifest_hash, manifest_hash_sz);

            rc = TPM2_IFX_FieldUpgradeStart(tpmSession.handle.hndl,
                cmd, 1 + 2 + 2 + manifest_hash_sz);
        }
        if (rc == TPM_RC_SUCCESS) {
            /* delay to give the TPM time to switch modes */
            XSLEEP_MS(300);
            /* it is not required to release session handle,
             * since TPM reset into firmware upgrade mode */

        #if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_SWTPM) && \
            !defined(WOLFTPM_WINAPI)
            /* Do chip startup and request locality again */
            rc = TPM2_ChipStartup(&dev->ctx, 10);
        #endif
        }
        else {
            wolfTPM2_UnloadHandle(dev, &tpmSession.handle);
        }
    }
#ifdef DEBUG_WOLFTPM
    if (rc != TPM_RC_SUCCESS) {
        printf("Firmware upgrade start failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }
#endif
    return rc;
}

static int tpm2_ifx_firmware_manifest(WOLFTPM2_DEV* dev,
    uint8_t* manifest, uint32_t manifest_sz)
{
    int rc = TPM_RC_FAILURE;
    uint32_t offset, chunk_sz;
    uint8_t state; /* 1=start, 2=more, 0=done */

    (void)dev;
    for (offset = 0; offset < manifest_sz; offset += chunk_sz) {
        /* max cmd: type (1) + chunk sz (2) + max chunk (1024) */
        uint8_t cmd[1 + 2 + IFX_FW_MAX_CHUNK_SZ];
        uint16_t val16;

        chunk_sz = manifest_sz - offset;
        if (chunk_sz > IFX_FW_MAX_CHUNK_SZ) {
            chunk_sz = IFX_FW_MAX_CHUNK_SZ;
            state = (offset == 0) ? 1 : 2;
        }
        else {
            state = 0;
        }
    #ifdef DEBUG_WOLFTPM
        printf("Firmware manifest chunk %u offset (%u / %u), state %d\n",
            chunk_sz, offset, manifest_sz, state);
    #endif

        cmd[0] = state;
        val16 = be16_to_cpu(chunk_sz);
        XMEMCPY(&cmd[1], &val16, sizeof(val16)); /* chunk size */
        XMEMCPY(&cmd[3], &manifest[offset], chunk_sz);

        rc = TPM2_IFX_FieldUpgradeCommand(TPM_CC_FieldUpgradeManifestVendor,
            cmd, 1 + 2 + chunk_sz);
        if (rc != TPM_RC_SUCCESS) {
            break;
        }
    }
#ifdef DEBUG_WOLFTPM
    if (rc != TPM_RC_SUCCESS) {
        printf("Firmware upgrade manifest failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }
#endif
    return rc;
}

static int tpm2_ifx_firmware_data(WOLFTPM2_DEV* dev,
    wolfTPM2FwDataCb cb, void* cb_ctx)
{
    int rc;
    uint32_t offset, chunk_sz;
    uint8_t cmd[2 + IFX_FW_MAX_CHUNK_SZ];
    uint16_t val16;

    (void)dev;
    for (offset = 0; ; offset += chunk_sz) {
        XMEMSET(cmd, 0, sizeof(cmd));

        /* get chunk */
        rc = cb(&cmd[2], IFX_FW_MAX_CHUNK_SZ, offset, cb_ctx);
        if (rc > 0 && rc <= IFX_FW_MAX_CHUNK_SZ) {
            chunk_sz = rc;
            rc = 0;
        }
        else if (rc == 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Firmware data done\n");
        #endif
            break;
        }
        else {
        #ifdef DEBUG_WOLFTPM
            printf("Firmware data callback error! %d\n", rc);
        #endif
            break;
        }

    #ifdef DEBUG_WOLFTPM
        printf("Firmware data chunk offset %u\n", offset);
    #endif

        val16 = be16_to_cpu(chunk_sz);
        XMEMCPY(&cmd[0], &val16, sizeof(val16)); /* chunk size */

        rc = TPM2_IFX_FieldUpgradeCommand(TPM_CC_FieldUpgradeDataVendor,
            cmd, 2 + chunk_sz);
        if (rc != TPM_RC_SUCCESS) {
            break;
        }
    }

    if (rc == TPM_RC_SUCCESS) {
        /* Give the TPM time to start the new firmware */
        XSLEEP_MS(300);

    #if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_SWTPM) && \
        !defined(WOLFTPM_WINAPI)
        /* Do chip startup and request locality again */
        rc = TPM2_ChipStartup(&dev->ctx, 10);
    #endif
    }
#ifdef DEBUG_WOLFTPM
    else {
        printf("Firmware upgrade data failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }
#endif
    return rc;
}

static int tpm2_ifx_firmware_final(WOLFTPM2_DEV* dev)
{
    int rc;
    uint8_t cmd[2];
    uint16_t val16;

    (void)dev;

    val16 = 0;
    XMEMCPY(&cmd[0], &val16, sizeof(val16)); /* data size */

    rc = TPM2_IFX_FieldUpgradeCommand(TPM_CC_FieldUpgradeFinalizeVendor,
        cmd, sizeof(cmd));
#ifdef DEBUG_WOLFTPM
    if (rc != TPM_RC_SUCCESS) {
        printf("Firmware finalize failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }
#endif
    return rc;
}

int wolfTPM2_FirmwareUpgrade(WOLFTPM2_DEV* dev,
    uint8_t* manifest, uint32_t manifest_sz,
    wolfTPM2FwDataCb cb, void* cb_ctx)
{
    int rc;
    WOLFTPM2_CAPS caps;
    TPM_ALG_ID hashAlg;
    uint8_t  manifest_hash[TPM_SHA384_DIGEST_SIZE];
    uint32_t manifest_hash_sz = (uint32_t)sizeof(manifest_hash);

    /* check the operational mode */
    rc = wolfTPM2_GetCapabilities(dev, &caps);
    if (rc == TPM_RC_SUCCESS) {
        if (caps.opMode == 0x03) {
            /* firmware update is done, just needs finalized and TPM reset */
        #ifdef DEBUG_WOLFTPM
            printf("Firmware update done, finalizing\n");
        #endif
            return tpm2_ifx_firmware_final(dev);
        }
    }

    /* hash the manifest */
    hashAlg = TPM_ALG_SHA384; /* use SHA2-384 or SHA2-512 for manifest hash */
    rc = wc_Sha384Hash(manifest, manifest_sz, manifest_hash);
    if (rc == TPM_RC_SUCCESS) {
        rc = tpm2_ifx_firmware_enable_policy(dev);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = tpm2_ifx_firmware_start(dev, hashAlg, manifest_hash, manifest_hash_sz);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = tpm2_ifx_firmware_manifest(dev, manifest, manifest_sz);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = tpm2_ifx_firmware_data(dev, cb, cb_ctx);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = tpm2_ifx_firmware_final(dev);
    }
#ifdef DEBUG_WOLFTPM
    if (rc != TPM_RC_SUCCESS) {
        printf("Firmware update failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }
#endif
    return rc;
}

/* terminate a firmware update */
int wolfTPM2_FirmwareUpgradeCancel(WOLFTPM2_DEV* dev)
{
    int rc;
    uint8_t cmd[2];
    uint16_t val16;

    (void)dev;

    val16 = 0; /* data size */
    XMEMCPY(&cmd[0], &val16, sizeof(val16));

    rc = TPM2_IFX_FieldUpgradeCommand(TPM_CC_FieldUpgradeAbandonVendor,
        cmd, sizeof(cmd));
#ifdef DEBUG_WOLFTPM
    if (rc != TPM_RC_SUCCESS) {
        printf("Firmware abandon failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }
#endif
    return rc;
}

#endif /* WOLFTPM_SLB9672 || WOLFTPM_SLB9673 */
#endif /* WOLFTPM_FIRMWARE_UPGRADE */

/******************************************************************************/
/* --- END Firmware Upgrade Support -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */
