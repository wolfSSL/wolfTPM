/* tpm2_wrap.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolftpm/tpm2_wrap.h>

int wolfTPM2_ReadPCR(int pcrIndex, int alg, byte* digest, int* digest_len)
{
    int rc;
    PCR_Read_In pcrReadIn;
    PCR_Read_Out pcrReadOut;

    wolfTPM2_SetupPCRSel(&pcrReadIn.pcrSelectionIn, alg, pcrIndex);
    rc = TPM2_PCR_Read(&pcrReadIn, &pcrReadOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

    *digest_len = (int)pcrReadOut.pcrValues.digests[0].size;
    XMEMCPY(digest, pcrReadOut.pcrValues.digests[0].buffer, *digest_len);

#ifdef DEBUG_WOLFTPM
    printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
        pcrIndex, *digest_len, (int)pcrReadOut.pcrUpdateCounter);
    wolfTPM2_PrintBin(digest, *digest_len);
#endif

    return rc;
}

int wolfTPM2_UnloadHandle(word32* handle)
{
    int rc = TPM_RC_SUCCESS;
    FlushContext_In flushCtxIn;

    if (handle == NULL)
        return TPM_RC_FAILURE;

    if (*handle != TPM_RH_NULL) {
        flushCtxIn.flushHandle = *handle;
        rc = TPM2_FlushContext(&flushCtxIn);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_FlushContext failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
            return rc;
        }

    #ifdef DEBUG_WOLFTPM
        printf("TPM2_FlushContext: Closed handle 0x%x\n", *handle);
    #endif

        *handle = TPM_RH_NULL;
    }

    return rc;
}

int wolfTPM2_NVReadPublic(word32 nvIndex)
{
    int rc = TPM_RC_SUCCESS;
    NV_ReadPublic_In in;
    NV_ReadPublic_Out out;

    in.nvIndex = nvIndex;
    rc = TPM2_NV_ReadPublic(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_NV_ReadPublic failed %d: %s\n", rc, wolfTPM2_GetRCString(rc));
        return rc;
    }

#ifdef DEBUG_WOLFTPM
    printf("TPM2_NV_ReadPublic: Sz %d, Idx 0x%x, nameAlg %d, Attr 0x%x, authPol %d, dataSz %d, name %d\n",
        out.nvPublic.size,
        out.nvPublic.nvPublic.nvIndex,
        out.nvPublic.nvPublic.nameAlg,
        out.nvPublic.nvPublic.attributes,
        out.nvPublic.nvPublic.authPolicy.size,
        out.nvPublic.nvPublic.dataSize,
        out.nvName.size);
#endif

    return rc;
}

const char* wolfTPM2_GetAlgName(TPM_ALG_ID alg)
{
    switch (alg) {
        case TPM_ALG_RSA:
            return "RSA";
        case TPM_ALG_SHA1:
            return "SHA1";
        case TPM_ALG_HMAC:
            return "HMAC";
        case TPM_ALG_AES:
            return "AES";
        case TPM_ALG_MGF1:
            return "MGF1";
        case TPM_ALG_KEYEDHASH:
            return "KEYEDHASH";
        case TPM_ALG_XOR:
            return "XOR";
        case TPM_ALG_SHA256:
            return "SHA256";
        case TPM_ALG_SHA384:
            return "SHA384";
        case TPM_ALG_SHA512:
            return "SHA512";
        case TPM_ALG_NULL:
            return "NULL";
        case TPM_ALG_SM3_256:
            return "SM3_256";
        case TPM_ALG_SM4:
            return "SM4";
        case TPM_ALG_RSASSA:
            return "RSASSA";
        case TPM_ALG_RSAES:
            return "RSAES";
        case TPM_ALG_RSAPSS:
            return "RSAPSS";
        case TPM_ALG_OAEP:
            return "OAEP";
        case TPM_ALG_ECDSA:
            return "ECDSA";
        case TPM_ALG_ECDH:
            return "ECDH";
        case TPM_ALG_ECDAA:
            return "ECDAA";
        case TPM_ALG_SM2:
            return "SM2";
        case TPM_ALG_ECSCHNORR:
            return "ECSCHNORR";
        case TPM_ALG_ECMQV:
            return "ECMQV";
        case TPM_ALG_KDF1_SP800_56A:
            return "KDF1_SP800_56A";
        case TPM_ALG_KDF2:
            return "KDF2";
        case TPM_ALG_KDF1_SP800_108:
            return "KDF1_SP800_108";
        case TPM_ALG_ECC:
            return "ECC";
        case TPM_ALG_SYMCIPHER:
            return "SYMCIPHER";
        case TPM_ALG_CTR:
            return "CTR";
        case TPM_ALG_OFB:
            return "OFB";
        case TPM_ALG_CBC:
            return "CBC";
        case TPM_ALG_CFB:
            return "CFB";
        case TPM_ALG_ECB:
            return "ECB";
        default:
            break;
    }
    return "Unknown";
}


const char* wolfTPM2_GetRCString(TPM_RC rc)
{
    if (rc & RC_VER1) {
        rc &= RC_MAX_FM0;

        switch (rc) {
        case TPM_RC_SUCCESS:
            return "Success";
        case TPM_RC_BAD_TAG:
            return "Bad Tag";
        case TPM_RC_BAD_ARG:
            return "Bad Argument";
        case TPM_RC_INITIALIZE:
            return "TPM not initialized by TPM2_Startup or already initialized";
        case TPM_RC_FAILURE:
            return "Commands not being accepted because of a TPM failure";
        case TPM_RC_SEQUENCE:
            return "Improper use of a sequence handle";
        case TPM_RC_DISABLED:
            return "The command is disabled";
        case TPM_RC_EXCLUSIVE:
            return "Command failed because audit sequence required exclusivity";
        case TPM_RC_AUTH_TYPE:
            return "Authorization handle is not correct for command";
        case TPM_RC_AUTH_MISSING:
            return "Command requires an authorization session for handle and "
                "it is not present";
        case TPM_RC_POLICY:
            return "Policy failure in math operation or an invalid authPolicy "
                "value";
        case TPM_RC_PCR:
            return "PCR check fail";
        case TPM_RC_PCR_CHANGED:
            return "PCR have changed since checked";
        case TPM_RC_UPGRADE:
            return "Indicates that the TPM is in field upgrade mode";
        case TPM_RC_TOO_MANY_CONTEXTS:
            return "Context ID counter is at maximum";
        case TPM_RC_AUTH_UNAVAILABLE:
            return "The authValue or authPolicy is not available for selected "
                "entity";
        case TPM_RC_REBOOT:
            return "A _TPM_Init and Startup(CLEAR) is required before the TPM "
                "can resume operation";
        case TPM_RC_UNBALANCED:
            return "The protection algorithms (hash and symmetric) are not "
                "reasonably balanced";
        case TPM_RC_COMMAND_SIZE:
            return "Command commandSize value is inconsistent with contents of "
                "the command buffer";
        case TPM_RC_COMMAND_CODE:
            return "Command code not supported";
        case TPM_RC_AUTHSIZE:
            return "The value of authorizationSize is out of range or the "
                "number of octets in the Authorization Area is greater than "
                "required";
        case TPM_RC_AUTH_CONTEXT:
            return "Use of an authorization session with a context command or "
                "another command that cannot have an authorization session";
        case TPM_RC_NV_RANGE:
            return "NV offset+size is out of range";
        case TPM_RC_NV_SIZE:
            return "Requested allocation size is larger than allowed";
        case TPM_RC_NV_LOCKED:
            return "NV access locked";
        case TPM_RC_NV_AUTHORIZATION:
            return "NV access authorization fails in command actions";
        case TPM_RC_NV_UNINITIALIZED:
            return "An NV Index is used before being initialized or the state "
                "saved by TPM2_Shutdown(STATE) could not be restored";
        case TPM_RC_NV_SPACE:
            return "Insufficient space for NV allocation";
        case TPM_RC_NV_DEFINED:
            return "NV Index or persistent object already defined";
        case TPM_RC_BAD_CONTEXT:
            return "Context in TPM2_ContextLoad() is not valid";
        case TPM_RC_CPHASH:
            return "The cpHash value already set or not correct for use";
        case TPM_RC_PARENT:
            return "Handle for parent is not a valid parent";
        case TPM_RC_NEEDS_TEST:
            return "Some function needs testing";
        case TPM_RC_NO_RESULT:
            return "Cannot process a request due to an unspecified problem";
        case TPM_RC_SENSITIVE:
            return "The sensitive area did not unmarshal correctly after "
                "decryption";
        default:
            break;
        }
    }

    if (rc & RC_FMT1) {
        rc &= RC_MAX_FMT1;

        switch (rc) {
        case TPM_RC_ASYMMETRIC:
            return "Asymmetric algorithm not supported or not correct";
        case TPM_RC_ATTRIBUTES:
            return "Inconsistent attributes";
        case TPM_RC_HASH:
            return "Hash algorithm not supported or not appropriate";
        case TPM_RC_VALUE:
            return "Value is out of range or is not correct for the context";
        case TPM_RC_HIERARCHY:
            return "Hierarchy is not enabled or is not correct for the use";
        case TPM_RC_KEY_SIZE:
            return "Key size is not supported";
        case TPM_RC_MGF:
            return "Mask generation function not supported";
        case TPM_RC_MODE:
            return "Mode of operation not supported";
        case TPM_RC_TYPE:
            return "The type of the value is not appropriate for the use";
        case TPM_RC_HANDLE:
            return "The handle is not correct for the use";
        case TPM_RC_KDF:
            return "Unsupported key derivation function or function not "
                "appropriate for use";
        case TPM_RC_RANGE:
            return "Value was out of allowed range";
        case TPM_RC_AUTH_FAIL:
            return "The authorization HMAC check failed and DA counter "
                "incremented";
        case TPM_RC_NONCE:
            return "Invalid nonce size or nonce value mismatch";
        case TPM_RC_PP:
            return "Authorization requires assertion of PP";
        case TPM_RC_SCHEME:
            return "Unsupported or incompatible scheme";
        case TPM_RC_SIZE:
            return "Structure is the wrong size";
        case TPM_RC_SYMMETRIC:
            return "Unsupported symmetric algorithm or key size, or not "
                "appropriate for instance";
        case TPM_RC_TAG:
            return "Incorrect structure tag";
        case TPM_RC_SELECTOR:
            return "Union selector is incorrect";
        case TPM_RC_INSUFFICIENT:
            return "The TPM was unable to unmarshal a value because there were "
                "not enough octets in the input buffer";
        case TPM_RC_SIGNATURE:
            return "The signature is not valid";
        case TPM_RC_KEY:
            return "Key fields are not compatible with the selected use";
        case TPM_RC_POLICY_FAIL:
            return "A policy check failed";
        case TPM_RC_INTEGRITY:
            return "Integrity check failed";
        case TPM_RC_TICKET:
            return "Invalid ticket";
        case TPM_RC_RESERVED_BITS:
            return "Reserved bits not set to zero as required";
        case TPM_RC_BAD_AUTH:
            return "Authorization failure without DA implications";
        case TPM_RC_EXPIRED:
            return "The policy has expired";
        case TPM_RC_POLICY_CC:
            return "The commandCode in the policy is not the commandCode of "
                "the command or the command code in a policy command "
                "references a command that is not implemented";
        case TPM_RC_BINDING:
            return "Public and sensitive portions of an object are not "
                "cryptographically bound";
        case TPM_RC_CURVE:
            return "Curve not supported";
        case TPM_RC_ECC_POINT:
            return "Point is not on the required curve";
        default:
            break;
        }
    }

    if (rc & RC_WARN) {
        rc &= RC_MAX_WARN;

        switch (rc) {
        case TPM_RC_CONTEXT_GAP:
            return "Gap for context ID is too large";
        case TPM_RC_OBJECT_MEMORY:
            return "Out of memory for object contexts";
        case TPM_RC_SESSION_MEMORY:
            return "Out of memory for session contexts";
        case TPM_RC_MEMORY:
            return "Out of shared object/session memory or need space for "
                "internal operations";
        case TPM_RC_SESSION_HANDLES:
            return "Out of session handles; a session must be flushed before "
                "a new session may be created";
        case TPM_RC_OBJECT_HANDLES:
            return "Out of object handles";
        case TPM_RC_LOCALITY:
            return "Bad locality";
        case TPM_RC_YIELDED:
            return "The TPM has suspended operation on the command";
        case TPM_RC_CANCELED:
            return "The command was canceled";
        case TPM_RC_TESTING:
            return "TPM is performing self-tests";
        case TPM_RC_NV_RATE:
            return "The TPM is rate-limiting accesses to prevent wearout of NV";
        case TPM_RC_LOCKOUT:
            return "Authorizations for objects subject to DA protection are not"
                " allowed at this time because the TPM is in DA lockout mode";
        case TPM_RC_RETRY:
            return "The TPM was not able to start the command";
        case TPM_RC_NV_UNAVAILABLE:
            return "The command may require writing of NV and NV is not current"
                " accessible";
        case TPM_RC_NOT_USED:
            return "This value is reserved and shall not be returned by the "
                "TPM";
        default:
            break;
        }
    }
    return "Unknown";
}

void wolfTPM2_SetupPCRSel(TPML_PCR_SELECTION* pcr, TPM_ALG_ID alg, int pcrIndex)
{
    if (pcr) {
        pcr->count = 1;
        pcr->pcrSelections[0].hash = alg;
        pcr->pcrSelections[0].sizeofSelect = PCR_SELECT_MIN;
        XMEMSET(pcr->pcrSelections[0].pcrSelect, 0, PCR_SELECT_MIN);
        pcr->pcrSelections[0].pcrSelect[pcrIndex >> 3] = (1 << (pcrIndex & 0x7));
    }
}



#ifdef DEBUG_WOLFTPM
#define LINE_LEN 16
void wolfTPM2_PrintBin(const byte* buffer, word32 length)
{
    word32 i;
    char line[80];

    if (!buffer) {
        printf("\tNULL");
        return;
    }

    sprintf(line, "\t");

    for (i = 0; i < LINE_LEN; i++) {
        if (i < length)
            sprintf(line + 1 + i * 3,"%02x ", buffer[i]);
        else
            sprintf(line + 1 + i * 3, "   ");
    }

    sprintf(line + 1 + LINE_LEN * 3, "| ");

    for (i = 0; i < LINE_LEN; i++)
        if (i < length)
            sprintf(line + 3 + LINE_LEN * 3 + i,
                 "%c", 31 < buffer[i] && buffer[i] < 127 ? buffer[i] : '.');

    printf("%s\n", line);

    if (length > LINE_LEN)
        wolfTPM2_PrintBin(buffer + LINE_LEN, length - LINE_LEN);
}
#endif
