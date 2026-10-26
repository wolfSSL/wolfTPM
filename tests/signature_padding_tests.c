/* signature_padding_tests.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_packet.h>

#include <stdio.h>
#include <stdlib.h>

/* Use the existing unit-test assertion convention. */
#define Fail(description, result) do {                                      \
    printf("\nERROR - %s line %d failed with:", __FILE__, __LINE__);        \
    printf("\n    expected: "); printf description;                         \
    printf("\n    result:   "); printf result; printf("\n\n");              \
    fflush(stdout);                                                         \
    abort();                                                                \
} while (0)
#define Assert(test, description, result) if (!(test)) Fail(description, result)
#define AssertInt(x, y, op, er) do {                                        \
    int _x = (int)(x);                                                       \
    int _y = (int)(y);                                                       \
    Assert(_x op _y, ("%s " #op " %s", #x, #y),                           \
        ("%d(0x%x) " #er " %d(0x%x)", _x, _x, _y, _y));                   \
} while (0)
#define AssertIntEQ(x, y) AssertInt(x, y, ==, !=)

static TPMT_SIGNATURE wireSignature;
static TPM_CC expectedCommand;
static TPM_RC wireError;

/* Exercise the real command builders, response parser and wrappers without a
 * TPM or socket. The response may have shorter ECC scalars than the curve. */
#if defined(WOLFTPM_LINUX_DEV)
    #define TPM2_LINUX_SendCommand test_signature_send
#elif defined(WOLFTPM_LINUX_DEV_AUTODETECT)
    #define TPM2_LINUX_AUTODETECT_SendCommand test_signature_send
#elif defined(WOLFTPM_SWTPM)
    #define TPM2_SWTPM_SendCommand test_signature_send
#elif defined(WOLFTPM_WINAPI)
    #define TPM2_WinApi_SendCommand test_signature_send
#else
    #define TPM2_TIS_SendCommand test_signature_send
#endif
#include "../src/tpm2.c"

int test_signature_send(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    TPM2_Packet rsp;
    UINT32 code;
    int i, authCount = 1;

    code = ((UINT32)packet->buf[6] << 24) |
        ((UINT32)packet->buf[7] << 16) |
        ((UINT32)packet->buf[8] << 8) | packet->buf[9];
    AssertIntEQ(code, expectedCommand);
    TPM2_Packet_Init(ctx, &rsp);
    if (wireError != TPM_RC_SUCCESS) {
        TPM2_Packet_Finalize(&rsp, TPM_ST_NO_SESSIONS, wireError);
    }
    else {
    #ifdef WOLFTPM_MLDSA_SIGN
        if (code == TPM_CC_SignSequenceComplete) {
            authCount = 2;
        }
    #endif
        TPM2_Packet_AppendU32(&rsp, 8 +
            wireSignature.signature.ecdsa.signatureR.size +
            wireSignature.signature.ecdsa.signatureS.size);
        TPM2_Packet_AppendSignature(&rsp, &wireSignature);
        for (i = 0; i < authCount; i++) {
            TPM2_Packet_AppendU16(&rsp, 0); /* nonce */
            TPM2_Packet_AppendU8(&rsp, 0);  /* attributes */
            TPM2_Packet_AppendU16(&rsp, 0); /* password response */
        }
        TPM2_Packet_Finalize(&rsp, TPM_ST_SESSIONS, TPM_RC_SUCCESS);
    }
    packet->size = rsp.pos;
    return TPM_RC_SUCCESS;
}

#if !defined(WOLFTPM_LINUX_DEV) && !defined(WOLFTPM_SWTPM) && \
    !defined(WOLFTPM_WINAPI)
#ifdef WOLFTPM_ADV_IO
static int test_signature_io(TPM2_CTX* ctx, INT32 read, UINT32 addr,
    BYTE* buf, UINT16 sz, void* user)
{
    (void)read;
    (void)addr;
    (void)buf;
#else
static int test_signature_io(TPM2_CTX* ctx, const BYTE* tx, BYTE* rx,
    UINT16 sz, void* user)
{
    (void)tx;
    (void)rx;
#endif
    (void)ctx;
    (void)sz;
    (void)user;
    return TPM_RC_FAILURE;
}
#endif /* callback transports */

static int sign_fixture(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key, int method,
    byte* sig, int* sigSz)
{
    byte digest[TPM_SHA256_DIGEST_SIZE];
    XMEMSET(digest, 0x5A, sizeof(digest));
    if (method == 0) {
        expectedCommand = TPM_CC_Sign;
        return wolfTPM2_SignHashScheme(dev, key, digest, sizeof(digest),
            sig, sigSz, wireSignature.sigAlg, TPM_ALG_SHA256);
    }
#ifdef WOLFTPM_MLDSA_SIGN
    if (method == 1) {
        expectedCommand = TPM_CC_SignDigest;
        return wolfTPM2_SignDigest(dev, key, digest, sizeof(digest), NULL, 0,
            sig, sigSz);
    }
    expectedCommand = TPM_CC_SignSequenceComplete;
    return wolfTPM2_SignSequenceComplete(dev, TRANSIENT_FIRST + 1,
        key, NULL, 0, sig, sigSz);
#else
    return BAD_FUNC_ARG;
#endif
}

static void test_signature_case(int method, TPM_ECC_CURVE curve,
    UINT16 scheme, int rSize, int sSize, int capacity, int expectedRc)
{
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY key;
    byte sig[2 * MAX_ECC_KEY_BYTES + 16];
    byte expected[sizeof(sig)];
    int i, rc, sigSz = capacity;
    int curveSize = wolfTPM2_GetCurveSize(curve);

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&wireSignature, 0, sizeof(wireSignature));
    XMEMSET(sig, 0xA5, sizeof(sig));
    XMEMSET(expected, 0xA5, sizeof(expected));
#if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || \
    defined(WOLFTPM_WINAPI)
    rc = TPM2_Init_minimal(&dev.ctx);
#else
    rc = TPM2_Init_ex(&dev.ctx, test_signature_io, NULL, 0);
#endif
    AssertIntEQ(rc, TPM_RC_SUCCESS);
    key.handle.hndl = TRANSIENT_FIRST;
    key.pub.publicArea.type = TPM_ALG_ECC;
    key.pub.publicArea.parameters.eccDetail.curveID = curve;
    wireSignature.sigAlg = scheme;
    wireSignature.signature.ecdsa.hash = TPM_ALG_SHA256;
    wireSignature.signature.ecdsa.signatureR.size = (UINT16)rSize;
    wireSignature.signature.ecdsa.signatureS.size = (UINT16)sSize;
    for (i = 0; i < rSize; i++) {
        wireSignature.signature.ecdsa.signatureR.buffer[i] = (byte)(i + 1);
    }
    for (i = 0; i < sSize; i++) {
        wireSignature.signature.ecdsa.signatureS.buffer[i] = (byte)(i + 0x61);
    }
    if (expectedRc == TPM_RC_SUCCESS) {
        XMEMSET(expected, 0, 2 * curveSize);
        XMEMCPY(expected + curveSize - rSize,
            wireSignature.signature.ecdsa.signatureR.buffer, rSize);
        XMEMCPY(expected + 2 * curveSize - sSize,
            wireSignature.signature.ecdsa.signatureS.buffer, sSize);
    }
    rc = sign_fixture(&dev, &key, method, sig, &sigSz);
    AssertIntEQ(rc, expectedRc);
    AssertIntEQ(sigSz, expectedRc == TPM_RC_SUCCESS ? 2 * curveSize : capacity);
    AssertIntEQ(XMEMCMP(sig, expected, sizeof(sig)), 0);
    TPM2_Cleanup(&dev.ctx);
}

int main(void)
{
    static const TPM_ECC_CURVE curves[] = {
        TPM_ECC_NIST_P256, TPM_ECC_NIST_P384, TPM_ECC_NIST_P521
    };
    int method, methods = 1, i, j, curveSize;
    UINT16 scheme;

#ifdef WOLFTPM_MLDSA_SIGN
    methods = MAX_SESSION_NUM > 1 ? 3 : 2;
#endif
    for (method = 0; method < methods; method++) {
        for (i = 0; i < (int)(sizeof(curves) / sizeof(curves[0])); i++) {
            curveSize = wolfTPM2_GetCurveSize(curves[i]);
            if (curveSize > (int)sizeof(
                    wireSignature.signature.ecdsa.signatureR.buffer)) {
                continue;
            }
            for (j = 0; j < 2; j++) {
                scheme = j == 0 ? TPM_ALG_ECDSA : TPM_ALG_ECDAA;
                test_signature_case(method, curves[i], scheme,
                    curveSize - 1, curveSize - 2, 2 * curveSize,
                    TPM_RC_SUCCESS);
                test_signature_case(method, curves[i], scheme,
                    curveSize, curveSize, 2 * curveSize, TPM_RC_SUCCESS);
                test_signature_case(method, curves[i], scheme,
                    curveSize - 1, curveSize - 2, 2 * curveSize - 1, BUFFER_E);
                test_signature_case(method, curves[i], scheme,
                    curveSize - 1, curveSize - 2, -1, BUFFER_E);
                if (curveSize < (int)sizeof(
                        wireSignature.signature.ecdsa.signatureR.buffer)) {
                    test_signature_case(method, curves[i], scheme,
                        curveSize + 1, curveSize - 2, 2 * curveSize, BUFFER_E);
                    test_signature_case(method, curves[i], scheme,
                        curveSize - 2, curveSize + 1, 2 * curveSize, BUFFER_E);
                }
            }
        }
        test_signature_case(method, (TPM_ECC_CURVE)0x7FFF, TPM_ALG_ECDSA,
            1, 1, sizeof(wireSignature.signature.ecdsa.signatureR.buffer) * 2,
            BAD_FUNC_ARG);
        wireError = TPM_RC_FAILURE;
        test_signature_case(method, TPM_ECC_NIST_P256, TPM_ALG_ECDSA,
            1, 1, 64, TPM_RC_FAILURE);
        wireError = TPM_RC_SUCCESS;
    }
    printf("PASS: fixed-width ECC signatures and error bounds across %d wrappers\n",
        methods);
    return 0;
}
