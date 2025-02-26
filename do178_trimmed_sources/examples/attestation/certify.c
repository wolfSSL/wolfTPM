/* certify.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/* This example shows how to create a attestation for a key (like IAK)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/attestation/attestation.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>


/******************************************************************************/
/* --- BEGIN TPM2.0 Certify example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/attestation/certify [-rsa/-ecc] [-certify=] [-signer=]\n");
    printf("\t* -ecc/-rsa: RSA or ECC (default is RSA)\n");
    printf("\t* -certify=[handle] Key to certify (default 0x%x)\n",  0x80000001U);
    printf("\t* -signer=[handle] Key to sign with (default 0x%x)\n", 0x80000000U);
    printf("\nExample Usage:\n");
    printf("./examples/keygen/create_primary -rsa -eh -iak -keep\n");
    printf("./examples/keygen/create_primary -rsa -eh -idevid -keep\n");
    printf("./examples/attestation/certify -rsa -certify=0x80000001 "
        "-signer=0x80000000\n");
    printf("./examples/management/flush 0x80000001\n");
    printf("./examples/management/flush 0x80000000\n");
}

/* Policies for IDevID/IAK from:
 * "TPM 2.0 Keys for Device Identity and Attestation" */
static const byte PA_User_Policy[] = {
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
    0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
    };
static const byte Certify[] = {
    0xB2, 0xA6, 0x9E, 0x63, 0x91, 0xE2, 0x68, 0x4A,
    0x0F, 0xE7, 0x52, 0xD3, 0x9E, 0x14, 0xAC, 0xD2,
    0xE5, 0xCB, 0x92, 0x2E, 0x4B, 0xD0, 0x35, 0x83,
    0x0E, 0xEA, 0x31, 0xF2, 0xAA, 0xBE, 0x98, 0x70
};
static const byte Activate_CredentialPolicy[] = {
    0xCD, 0x99, 0x17, 0xCF, 0x18, 0xC3, 0x84, 0x8C,
    0x3A, 0x2E, 0x60, 0x69, 0x86, 0xA0, 0x66, 0xC6,
    0x81, 0x42, 0xF9, 0xBC, 0x27, 0x10, 0xA2, 0x78,
    0x28, 0x7A, 0x65, 0x0C, 0xA3, 0xBB, 0xF2, 0x45};
static const byte Policy_Authorize_NV_IDevID[] = {
    0x62, 0x9C, 0x50, 0xB0, 0x5F, 0x1A, 0xDB, 0x5B,
    0x42, 0x97, 0xFE, 0xB2, 0x41, 0x54, 0x9D, 0x42,
    0x17, 0xA1, 0xC7, 0x92, 0xC1, 0x62, 0xFE, 0xB8,
    0x61, 0x02, 0x2D, 0xEF, 0x88, 0xFA, 0x95, 0x01
};


int TPM2_Certify_Example(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION tpmSession;
    TPM_HANDLE certifyHandle = 0x80000001;
    TPM_HANDLE signerHandle  = 0x80000000;
    WOLFTPM2_KEY certify;
    WOLFTPM2_KEY signer;
    TPM_ALG_ID hashAlg = TPM_ALG_SHA256;
    TPM_ALG_ID alg = TPM_ALG_RSA;
    Certify_In  certifyIn;
    Certify_Out certifyOut;
    PolicyOR_In policyOR;
    const char keyCreationNonce[] = "RandomServerPickedCreationNonce";

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-ecc") == 0) {
            alg = TPM_ALG_ECC;
        }
        else if (XSTRCMP(argv[argc-1], "-rsa") == 0) {
            alg = TPM_ALG_RSA;
        }
        else if (XSTRNCMP(argv[argc-1], "-certify=", XSTRLEN("-certify=")) == 0) {
            const char* certifyStr = argv[argc-1] + XSTRLEN("-certify=");
            certifyHandle = (word32)XSTRTOUL(certifyStr, NULL, 0);
        }
        else if (XSTRNCMP(argv[argc-1], "-signer=", XSTRLEN("-signer=")) == 0) {
            const char* signerStr = argv[argc-1] + XSTRLEN("-signer=");
            signerHandle = (word32)XSTRTOUL(signerStr, NULL, 0);
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&certify, 0, sizeof(certify));
    XMEMSET(&signer, 0, sizeof(signer));

    printf("Certify 0x%x with 0x%x to generate TPM-signed attestation info\n",
        certifyHandle, signerHandle);

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* Read public information for each handle */
    rc = wolfTPM2_ReadPublicKey(&dev, &certify, certifyHandle);
    if (rc != 0) goto exit;
    rc = wolfTPM2_ReadPublicKey(&dev, &signer, signerHandle);
    if (rc != 0) goto exit;

    /* Start a policy session for using endorsement */
    rc = wolfTPM2_CreateAuthSession_EkPolicy(&dev, &tpmSession);
    if (rc != 0) goto exit;
    /* Set the created Policy Session for use in next operation */
    rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession, 0);
    if (rc != 0) goto exit;
    printf("EK Policy Session: Handle 0x%x\n", (word32)tpmSession.handle.hndl);

    /* satisfy policy for using certify command */
    rc = wolfTPM2_PolicyCommandCode(&dev, &tpmSession, TPM_CC_Certify);
    if (rc != 0) goto exit;

    /* satisfy the TPM2_PolicyOR for SHA2-256 for IDevID/IAK admin policy */
    XMEMSET(&policyOR, 0, sizeof(policyOR));
    policyOR.policySession = tpmSession.handle.hndl;
    policyOR.pHashList.count = 4;

    policyOR.pHashList.digests[0].size = sizeof(PA_User_Policy);
    XMEMCPY(policyOR.pHashList.digests[0].buffer, PA_User_Policy,
        sizeof(PA_User_Policy));
    policyOR.pHashList.digests[1].size = sizeof(Certify);
    XMEMCPY(policyOR.pHashList.digests[1].buffer, Certify, sizeof(Certify));
    policyOR.pHashList.digests[2].size = sizeof(Activate_CredentialPolicy);
    XMEMCPY(policyOR.pHashList.digests[2].buffer, Activate_CredentialPolicy,
        sizeof(Activate_CredentialPolicy));
    policyOR.pHashList.digests[3].size = sizeof(Policy_Authorize_NV_IDevID);
    XMEMCPY(policyOR.pHashList.digests[3].buffer, Policy_Authorize_NV_IDevID,
        sizeof(Policy_Authorize_NV_IDevID));

    rc = TPM2_PolicyOR(&policyOR);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PolicyOR failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    /* Setup the session object names used for policy HMAC */
    (void)wolfTPM2_SetAuthHandleName(&dev, 0, &certify.handle);
    (void)wolfTPM2_SetAuthHandle(&dev, 1, &signer.handle);

    /* Create signed certify structure */
    XMEMSET(&certifyIn, 0, sizeof(certifyIn));
    /* the first handle (objectHandle) requires ADMIN role */
    certifyIn.objectHandle = certifyHandle;
    certifyIn.signHandle = signerHandle;
    certifyIn.inScheme.scheme =
        (alg == TPM_ALG_ECC) ? TPM_ALG_ECDSA : TPM_ALG_RSASSA;;
    certifyIn.inScheme.details.any.hashAlg = hashAlg;
    /* provide a random nonce from remote server (optional) */
    certifyIn.qualifyingData.size = sizeof(keyCreationNonce)-1;
    XMEMCPY(certifyIn.qualifyingData.buffer, keyCreationNonce,
        certifyIn.qualifyingData.size);
    rc = TPM2_Certify(&certifyIn, &certifyOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Certify RSA key failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Certify complete\n");

    printf("Certify Info %d\n", certifyOut.certifyInfo.size);
    TPM2_PrintBin(certifyOut.certifyInfo.attestationData,
        certifyOut.certifyInfo.size);

    if (certifyOut.signature.sigAlg == TPM_ALG_RSASSA) {
        printf("RSA Signature: %d\n",
            certifyOut.signature.signature.rsassa.sig.size);
        TPM2_PrintBin(certifyOut.signature.signature.rsassa.sig.buffer,
            certifyOut.signature.signature.rsassa.sig.size);
    }
    else if (certifyOut.signature.sigAlg == TPM_ALG_ECDSA) {
        printf("ECDSA Signature R %d / S %d\n",
            certifyOut.signature.signature.ecdsa.signatureR.size,
            certifyOut.signature.signature.ecdsa.signatureS.size);
        TPM2_PrintBin(certifyOut.signature.signature.ecdsa.signatureR.buffer,
            certifyOut.signature.signature.ecdsa.signatureR.size);
        TPM2_PrintBin(certifyOut.signature.signature.ecdsa.signatureS.buffer,
            certifyOut.signature.signature.ecdsa.signatureS.size);
    }
    /* the policy session is automatically closed */
    tpmSession.handle.hndl = TPM_RH_NULL;

    /* Perform software verification of signature by hashing the attestation
     * information and use the signer public key to verify the signature */

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Certify example tool -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Certify_Example(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
