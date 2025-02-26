/* verify_ek_cert.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* This example shows how to generate and validate an EK based on a
 * trusted public key. This example is supported in stand-alone (no wolfCrypt)
 * This example assumes ST33KTPM2X with signer
 * "STSAFE TPM RSA Intermediate CA 20" : RSA 4096-bit key with SHA2-384
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_asn.h>

#include <stdio.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <examples/endorsement/endorsement.h>
#include <hal/tpm_io.h>

#include "trusted_certs_der.h"


static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/endorsement/verify_ek_cert\n");
}

static void dump_hex_bytes(const byte* buf, word32 sz)
{
    word32 i;
    /* Print as : separated hex bytes - max 15 bytes per line */
    printf("\t");
    for (i=0; i<sz; i++) {
        printf("%02x", buf[i]);
        if (i+1 < sz) {
            printf(":");
            if (i>0 && ((i+1)%16)==0) printf("\n\t");
        }
    }
    printf("\n");
}

/* Display EK public information */
static void show_tpm_public(const char* desc, const TPM2B_PUBLIC* pub)
{
    printf("%s %s, Hash: %s, objAttr: 0x%X\n",
        desc,
        TPM2_GetAlgName(pub->publicArea.type),
        TPM2_GetAlgName(pub->publicArea.nameAlg),
        (unsigned int)pub->publicArea.objectAttributes);

    /* parameters and unique field depend on algType */
    if (pub->publicArea.type == TPM_ALG_RSA) {
        printf("\tKeyBits: %d, exponent: 0x%X, unique size %d\n",
            pub->publicArea.parameters.rsaDetail.keyBits,
            (unsigned int)pub->publicArea.parameters.rsaDetail.exponent,
            pub->publicArea.unique.rsa.size);
        dump_hex_bytes(pub->publicArea.unique.rsa.buffer,
                       pub->publicArea.unique.rsa.size);
    }
    else if (pub->publicArea.type == TPM_ALG_ECC) {
        const char* curveName = "NULL";
        printf("\tCurveID %s (0x%x), size %d, unique X/Y size %d/%d\n",
            curveName, pub->publicArea.parameters.eccDetail.curveID,
            TPM2_GetCurveSize(pub->publicArea.parameters.eccDetail.curveID),
            pub->publicArea.unique.ecc.x.size,
            pub->publicArea.unique.ecc.y.size);
        dump_hex_bytes(pub->publicArea.unique.ecc.x.buffer,
                       pub->publicArea.unique.ecc.x.size);
        dump_hex_bytes(pub->publicArea.unique.ecc.y.buffer,
                       pub->publicArea.unique.ecc.y.size);
    }
}

int TPM2_EndorsementCertVerify_Example(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY endorse;
    TPMS_NV_PUBLIC nvPublic;
    WOLFTPM2_KEY issuer;
    WOLFTPM2_NV nv;
    WOLFTPM2_HASH hash;
    TPMT_PUBLIC publicTemplate;
    TPM2B_PUBLIC ekPub;
    DecodedX509 issuerX509, ekX509;

    uint32_t nvIndex = TPM2_NV_RSA_EK_CERT; /* RSA 2048-bit EK Cert Index */
    uint8_t  cert[MAX_CERT_SZ]; /* buffer to hold device cert from NV */
    uint32_t certSz;
    TPM_ALG_ID hashAlg = TPM_ALG_SHA384; /* Signer uses SHA2-384 */
    uint8_t  hashBuf[TPM_MAX_DIGEST_SIZE]; /* hash of device cert, for verify */
    uint32_t hashSz = 0;
    uint8_t  sig[512]; /* 4096-bit max, hold decrypted signature */
    int      sigSz = (int)sizeof(sig);
    uint8_t* sigDigest; /* offset to digest in signature */
    int      sigDigestSz = 0;

    XMEMSET(&endorse, 0, sizeof(endorse));
    XMEMSET(&nvPublic, 0, sizeof(nvPublic));
    XMEMSET(&issuer, 0, sizeof(issuer));
    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&hash, 0, sizeof(hash));
    XMEMSET(&issuerX509, 0, sizeof(issuerX509));
    XMEMSET(&ekX509, 0, sizeof(ekX509));
    XMEMSET(&ekPub, 0, sizeof(ekPub));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }

    printf("Endorsement Certificate Verify\n");

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    /* Get Endorsement Public Key template using NV index */
    rc = wolfTPM2_GetKeyTemplate_EKIndex(nvIndex, &publicTemplate);
    if (rc != 0) {
        printf("EK Index 0x%08x not valid\n", nvIndex);
        goto exit;
    }

    /* Read Public portion of NV to get actual size */
    if (rc == 0)
    rc = wolfTPM2_NVReadPublic(&dev, nvIndex, &nvPublic);
    if (rc != 0) {
        printf("Failed to read public for NV Index 0x%08x\n", nvIndex);
    }
    if (rc == 0) { /* Read data */
        certSz = (uint32_t)sizeof(cert);
        if (certSz > nvPublic.dataSize) {
            certSz = nvPublic.dataSize;
        }
        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, cert, &certSz, 0);
        if (rc == 0) {
        }
    }

    /* Create Endorsement Key */
    if (rc == 0) {
        /* Create Endorsement Key using EK auth policy */
        printf("Creating Endorsement Key\n");
        rc = wolfTPM2_CreatePrimaryKey(&dev, &endorse, TPM_RH_ENDORSEMENT,
            &publicTemplate, NULL, 0);
        if (rc != 0) goto exit;
        printf("Endorsement key loaded at handle 0x%08x\n",
            endorse.handle.hndl);

        /* Display EK public information */
        show_tpm_public("EK", &endorse.pub);
    }

    if (rc == 0) {
        /* Parse device certificate and extract public key */
        rc = TPM2_ASN_DecodeX509Cert(cert, certSz, &ekX509);
        if (rc == 0) {
            /* Parse RSA Public Key Raw Modulus */
            rc = TPM2_ASN_DecodeRsaPubKey((uint8_t*)ekX509.publicKey, ekX509.pubKeySz,
                &ekPub);
        }
    }

    if (rc == 0) {
        /* Compare certificate public key with generated EK public key */
        if (ekPub.publicArea.unique.rsa.size !=
                endorse.pub.publicArea.unique.rsa.size ||
            XMEMCMP(ekPub.publicArea.unique.rsa.buffer,
                endorse.pub.publicArea.unique.rsa.buffer,
                endorse.pub.publicArea.unique.rsa.size) != 0)
        {
            printf("Error: Generated EK public key does not match NV cert "
                   "public key!\n");
            rc = -1;
        }
    }

    if (rc == 0) {
        /* Hash certificate (excluding signature) */
        rc = wolfTPM2_HashStart(&dev, &hash, hashAlg, NULL, 0);
        if (rc == 0) {
            rc = wolfTPM2_HashUpdate(&dev, &hash, ekX509.cert, ekX509.certSz);
            if (rc == 0) {
                hashSz = sizeof(hashBuf);
                rc = wolfTPM2_HashFinish(&dev, &hash, hashBuf, &hashSz);
            }

            printf("Cert Hash: %d\n", hashSz);
            dump_hex_bytes(hashBuf, hashSz);
        }
    }

    if (rc == 0) {
        /* Parse and extract the issuer's public key modulus from certificate */
        rc = TPM2_ASN_DecodeX509Cert((uint8_t*)kSTSAFEIntCa20,
            (int)sizeof(kSTSAFEIntCa20), &issuerX509);
        if (rc == 0) {
            /* Parse RSA Public Key Raw Modulus */
            rc = TPM2_ASN_DecodeRsaPubKey((uint8_t*)issuerX509.publicKey,
                issuerX509.pubKeySz, &issuer.pub);
        }
    }
    if (rc == 0) {
        printf("Issuer Public Exponent 0x%x, Modulus %d\n",
        issuer.pub.publicArea.parameters.rsaDetail.exponent,
            issuer.pub.publicArea.unique.rsa.size);
        dump_hex_bytes(issuer.pub.publicArea.unique.rsa.buffer,
            issuer.pub.publicArea.unique.rsa.size);

        /* Import issuer certificate public key */
        issuer.pub.publicArea.type = TPM_ALG_RSA;
        issuer.pub.publicArea.nameAlg = hashAlg;
        issuer.pub.publicArea.objectAttributes = (TPMA_OBJECT_decrypt);
        issuer.pub.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        issuer.pub.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = hashAlg;
        issuer.pub.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
        rc = wolfTPM2_LoadPublicKey(&dev, &issuer, &issuer.pub);
    }

    if (rc == 0) {
        /* Display Cert public information */
        show_tpm_public("Issuer", &issuer.pub);

        printf("EK Certificate Signature: %d\n", ekX509.sigSz);
        dump_hex_bytes(ekX509.signature, ekX509.sigSz);

        /* RSA Public Decrypt EK certificate signature */
        rc = wolfTPM2_RsaEncrypt(&dev, &issuer,
            TPM_ALG_NULL, /* no padding */
            ekX509.signature, ekX509.sigSz,
            sig, &sigSz);
        if (rc != 0) {
            printf("RSA Public Failed!\n");
            goto exit;
        }
        printf("Decrypted Sig: %d\n", sigSz);
        dump_hex_bytes(sig, sigSz);
    }

    if (rc == 0) {
        sigDigest = sig;
        rc = TPM2_ASN_RsaUnpadPkcsv15(&sigDigest, &sigSz);
    }
    if (rc == 0) {
        rc = TPM2_ASN_RsaDecodeSignature(&sigDigest, sigSz);
        if (rc > 0) {
            sigDigestSz = rc;
            rc = 0;
        }
    }
    if (rc == 0) {
        printf("Expected Hash: %d\n", hashSz);
        dump_hex_bytes(hashBuf, hashSz);

        printf("Sig Hash: %d\n", sigDigestSz);
        dump_hex_bytes(sigDigest, sigDigestSz);

        /* Compare certificate hash with signature hash */
        if (sigDigestSz == (int)hashSz &&
                memcmp(sigDigest, hashBuf, hashSz) == 0) {
            printf("Certificate signature is valid\n");
        }
        else {
            printf("Error: Certificate signature is invalid!\n");
            rc = -1;
        }
    }

exit:

    if (rc != 0) {
        printf("Error verifying EK certificate! %s (%d)\n",
            TPM2_GetRCString(rc), rc);
    }

    wolfTPM2_UnloadHandle(&dev, &issuer.handle);
    wolfTPM2_UnloadHandle(&dev, &endorse.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Endorsement certificate tool  -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_EndorsementCertVerify_Example(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
