/* tpm2.h
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

#ifndef __TPM2_H__
#define __TPM2_H__

#include <wolftpm/tpm2_types.h>

#ifdef __cplusplus
    extern "C" {
#endif


/** @defgroup TPM2_Standard TPM2 Standard Commands
 *
 * wolfTPM has support for all TPM 2.0 Commands as defined in the TCG specification.
 *
 * wolfTPM has internal TIS layer to enable communication with a TPM 2.0 on every system:
 * * Baremetal
 * * RTOS
 * * Windows systems
 * * Hybrid SoC
 * * Linux using /dev/tpm0
 * * Linux using devspi
 * * Linux using i2c driver
 *
 * Typically, a wolfTPM developer would use the wolfTPM2 wrappers for quicker development.
 *
 * If you want to use TPM 2.0 Commands directly See tpm2.h under Files -> File List above.
 *
 */



/* ---------------------------------------------------------------------------*/
/* TYPES */
/* ---------------------------------------------------------------------------*/

typedef UINT32 TPM_ALGORITHM_ID;
typedef UINT32 TPM_MODIFIER_INDICATOR;
typedef UINT32 TPM_AUTHORIZATION_SIZE;
typedef UINT32 TPM_PARAMETER_SIZE;
typedef UINT16 TPM_KEY_SIZE;
typedef UINT16 TPM_KEY_BITS;
typedef UINT32 TPM_GENERATED;

/* ---------------------------------------------------------------------------*/
/* ENUMERATIONS */
/* ---------------------------------------------------------------------------*/

#define TPM_SPEC_FAMILY       0x322E3000
#define TPM_SPEC_LEVEL        0
#define TPM_SPEC_VERSION      138
#define TPM_SPEC_YEAR         2016
#define TPM_SPEC_DAY_OF_YEAR  273

#define TPM_GENERATED_VALUE   0xff544347


typedef enum {
    TPM_ALG_ERROR           = 0x0000,
    TPM_ALG_RSA             = 0x0001,
    TPM_ALG_SHA             = 0x0004,
    TPM_ALG_SHA1            = TPM_ALG_SHA,
    TPM_ALG_HMAC            = 0x0005,
    TPM_ALG_AES             = 0x0006,
    TPM_ALG_MGF1            = 0x0007,
    TPM_ALG_KEYEDHASH       = 0x0008,
    TPM_ALG_XOR             = 0x000A,
    TPM_ALG_SHA256          = 0x000B,
    TPM_ALG_SHA384          = 0x000C,
    TPM_ALG_SHA512          = 0x000D,
    TPM_ALG_NULL            = 0x0010,
    TPM_ALG_SM3_256         = 0x0012,
    TPM_ALG_SM4             = 0x0013,
    TPM_ALG_RSASSA          = 0x0014,
    TPM_ALG_RSAES           = 0x0015,
    TPM_ALG_RSAPSS          = 0x0016,
    TPM_ALG_OAEP            = 0x0017,
    TPM_ALG_ECDSA           = 0x0018,
    TPM_ALG_ECDH            = 0x0019,
    TPM_ALG_ECDAA           = 0x001A,
    TPM_ALG_SM2             = 0x001B,
    TPM_ALG_ECSCHNORR       = 0x001C,
    TPM_ALG_ECMQV           = 0x001D,
    TPM_ALG_KDF1_SP800_56A  = 0x0020,
    TPM_ALG_KDF2            = 0x0021,
    TPM_ALG_KDF1_SP800_108  = 0x0022,
    TPM_ALG_ECC             = 0x0023,
    TPM_ALG_SYMCIPHER       = 0x0025,
    TPM_ALG_CAMELLIA        = 0x0026,
    TPM_ALG_CTR             = 0x0040,
    TPM_ALG_OFB             = 0x0041,
    TPM_ALG_CBC             = 0x0042,
    TPM_ALG_CFB             = 0x0043,
    TPM_ALG_ECB             = 0x0044,
} TPM_ALG_ID_T;
typedef UINT16 TPM_ALG_ID;

typedef enum {
    TPM_ECC_NONE        = 0x0000,
    TPM_ECC_NIST_P192   = 0x0001,
    TPM_ECC_NIST_P224   = 0x0002,
    TPM_ECC_NIST_P256   = 0x0003,
    TPM_ECC_NIST_P384   = 0x0004,
    TPM_ECC_NIST_P521   = 0x0005,
    TPM_ECC_BN_P256     = 0x0010,
    TPM_ECC_BN_P638     = 0x0011,
    TPM_ECC_SM2_P256    = 0x0020,
} TPM_ECC_CURVE_T;
typedef UINT16 TPM_ECC_CURVE;

/* Command Codes */
typedef enum {
    TPM_CC_FIRST                    = 0x0000011F,
    TPM_CC_NV_UndefineSpaceSpecial  = TPM_CC_FIRST,
    TPM_CC_EvictControl             = 0x00000120,
    TPM_CC_HierarchyControl         = 0x00000121,
    TPM_CC_NV_UndefineSpace         = 0x00000122,
    TPM_CC_ChangeEPS                = 0x00000124,
    TPM_CC_ChangePPS                = 0x00000125,
    TPM_CC_Clear                    = 0x00000126,
    TPM_CC_ClearControl             = 0x00000127,
    TPM_CC_ClockSet                 = 0x00000128,
    TPM_CC_HierarchyChangeAuth      = 0x00000129,
    TPM_CC_NV_DefineSpace           = 0x0000012A,
    TPM_CC_PCR_Allocate             = 0x0000012B,
    TPM_CC_PCR_SetAuthPolicy        = 0x0000012C,
    TPM_CC_PP_Commands              = 0x0000012D,
    TPM_CC_SetPrimaryPolicy         = 0x0000012E,
    TPM_CC_FieldUpgradeStart        = 0x0000012F,
    TPM_CC_ClockRateAdjust          = 0x00000130,
    TPM_CC_CreatePrimary            = 0x00000131,
    TPM_CC_NV_GlobalWriteLock       = 0x00000132,
    TPM_CC_GetCommandAuditDigest    = 0x00000133,
    TPM_CC_NV_Increment             = 0x00000134,
    TPM_CC_NV_SetBits               = 0x00000135,
    TPM_CC_NV_Extend                = 0x00000136,
    TPM_CC_NV_Write                 = 0x00000137,
    TPM_CC_NV_WriteLock             = 0x00000138,
    TPM_CC_DictionaryAttackLockReset = 0x00000139,
    TPM_CC_DictionaryAttackParameters = 0x0000013A,
    TPM_CC_NV_ChangeAuth            = 0x0000013B,
    TPM_CC_PCR_Event                = 0x0000013C,
    TPM_CC_PCR_Reset                = 0x0000013D,
    TPM_CC_SequenceComplete         = 0x0000013E,
    TPM_CC_SetAlgorithmSet          = 0x0000013F,
    TPM_CC_SetCommandCodeAuditStatus = 0x00000140,
    TPM_CC_FieldUpgradeData         = 0x00000141,
    TPM_CC_IncrementalSelfTest      = 0x00000142,
    TPM_CC_SelfTest                 = 0x00000143,
    TPM_CC_Startup                  = 0x00000144,
    TPM_CC_Shutdown                 = 0x00000145,
    TPM_CC_StirRandom               = 0x00000146,
    TPM_CC_ActivateCredential       = 0x00000147,
    TPM_CC_Certify                  = 0x00000148,
    TPM_CC_PolicyNV                 = 0x00000149,
    TPM_CC_CertifyCreation          = 0x0000014A,
    TPM_CC_Duplicate                = 0x0000014B,
    TPM_CC_GetTime                  = 0x0000014C,
    TPM_CC_GetSessionAuditDigest    = 0x0000014D,
    TPM_CC_NV_Read                  = 0x0000014E,
    TPM_CC_NV_ReadLock              = 0x0000014F,
    TPM_CC_ObjectChangeAuth         = 0x00000150,
    TPM_CC_PolicySecret             = 0x00000151,
    TPM_CC_Rewrap                   = 0x00000152,
    TPM_CC_Create                   = 0x00000153,
    TPM_CC_ECDH_ZGen                = 0x00000154,
    TPM_CC_HMAC                     = 0x00000155,
    TPM_CC_Import                   = 0x00000156,
    TPM_CC_Load                     = 0x00000157,
    TPM_CC_Quote                    = 0x00000158,
    TPM_CC_RSA_Decrypt              = 0x00000159,
    TPM_CC_HMAC_Start               = 0x0000015B,
    TPM_CC_SequenceUpdate           = 0x0000015C,
    TPM_CC_Sign                     = 0x0000015D,
    TPM_CC_Unseal                   = 0x0000015E,
    TPM_CC_PolicySigned             = 0x00000160,
    TPM_CC_ContextLoad              = 0x00000161,
    TPM_CC_ContextSave              = 0x00000162,
    TPM_CC_ECDH_KeyGen              = 0x00000163,
    TPM_CC_EncryptDecrypt           = 0x00000164,
    TPM_CC_FlushContext             = 0x00000165,
    TPM_CC_LoadExternal             = 0x00000167,
    TPM_CC_MakeCredential           = 0x00000168,
    TPM_CC_NV_ReadPublic            = 0x00000169,
    TPM_CC_PolicyAuthorize          = 0x0000016A,
    TPM_CC_PolicyAuthValue          = 0x0000016B,
    TPM_CC_PolicyCommandCode        = 0x0000016C,
    TPM_CC_PolicyCounterTimer       = 0x0000016D,
    TPM_CC_PolicyCpHash             = 0x0000016E,
    TPM_CC_PolicyLocality           = 0x0000016F,
    TPM_CC_PolicyNameHash           = 0x00000170,
    TPM_CC_PolicyOR                 = 0x00000171,
    TPM_CC_PolicyTicket             = 0x00000172,
    TPM_CC_ReadPublic               = 0x00000173,
    TPM_CC_RSA_Encrypt              = 0x00000174,
    TPM_CC_StartAuthSession         = 0x00000176,
    TPM_CC_VerifySignature          = 0x00000177,
    TPM_CC_ECC_Parameters           = 0x00000178,
    TPM_CC_FirmwareRead             = 0x00000179,
    TPM_CC_GetCapability            = 0x0000017A,
    TPM_CC_GetRandom                = 0x0000017B,
    TPM_CC_GetTestResult            = 0x0000017C,
    TPM_CC_Hash                     = 0x0000017D,
    TPM_CC_PCR_Read                 = 0x0000017E,
    TPM_CC_PolicyPCR                = 0x0000017F,
    TPM_CC_PolicyRestart            = 0x00000180,
    TPM_CC_ReadClock                = 0x00000181,
    TPM_CC_PCR_Extend               = 0x00000182,
    TPM_CC_PCR_SetAuthValue         = 0x00000183,
    TPM_CC_NV_Certify               = 0x00000184,
    TPM_CC_EventSequenceComplete    = 0x00000185,
    TPM_CC_HashSequenceStart        = 0x00000186,
    TPM_CC_PolicyPhysicalPresence   = 0x00000187,
    TPM_CC_PolicyDuplicationSelect  = 0x00000188,
    TPM_CC_PolicyGetDigest          = 0x00000189,
    TPM_CC_TestParms                = 0x0000018A,
    TPM_CC_Commit                   = 0x0000018B,
    TPM_CC_PolicyPassword           = 0x0000018C,
    TPM_CC_ZGen_2Phase              = 0x0000018D,
    TPM_CC_EC_Ephemeral             = 0x0000018E,
    TPM_CC_PolicyNvWritten          = 0x0000018F,
    TPM_CC_PolicyTemplate           = 0x00000190,
    TPM_CC_CreateLoaded             = 0x00000191,
    TPM_CC_PolicyAuthorizeNV        = 0x00000192,
    TPM_CC_EncryptDecrypt2          = 0x00000193,
    TPM_CC_LAST                     = TPM_CC_EncryptDecrypt2,

    CC_VEND                         = 0x20000000,
    TPM_CC_Vendor_TCG_Test          = CC_VEND + 0x0000,
#if defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)
    TPM_CC_SetMode                  = CC_VEND + 0x0307,
    TPM_CC_SetCommandSet            = CC_VEND + 0x0309,
    TPM_CC_GetRandom2               = CC_VEND + 0x030E,
#endif
#ifdef WOLFTPM_ST33
    TPM_CC_RestoreEK                = CC_VEND + 0x030A,
    TPM_CC_SetCommandSetLock        = CC_VEND + 0x030B,
    TPM_CC_GPIO_Config              = CC_VEND + 0x030F,
#endif
#ifdef WOLFTPM_NUVOTON
    TPM_CC_NTC2_PreConfig           = CC_VEND + 0x0211,
    TPM_CC_NTC2_GetConfig           = CC_VEND + 0x0213,
#endif
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
    TPM_CC_FieldUpgradeStartVendor    = CC_VEND + 0x12F,
    TPM_CC_FieldUpgradeAbandonVendor  = CC_VEND + 0x130,
    TPM_CC_FieldUpgradeManifestVendor = CC_VEND + 0x131,
    TPM_CC_FieldUpgradeDataVendor     = CC_VEND + 0x132,
    TPM_CC_FieldUpgradeFinalizeVendor = CC_VEND + 0x133,
#endif
} TPM_CC_T;
typedef UINT32 TPM_CC;

/* Response Codes */
typedef enum {
    TPM_RC_SUCCESS  = 0x000,
    TPM_RC_BAD_TAG  = 0x01E,

    RC_VER1 = 0x100,
    TPM_RC_INITIALIZE           = RC_VER1 + 0x000,
    TPM_RC_FAILURE              = RC_VER1 + 0x001,
    TPM_RC_SEQUENCE             = RC_VER1 + 0x003,
    TPM_RC_PRIVATE              = RC_VER1 + 0x00B,
    TPM_RC_HMAC                 = RC_VER1 + 0x019,
    TPM_RC_DISABLED             = RC_VER1 + 0x020,
    TPM_RC_EXCLUSIVE            = RC_VER1 + 0x021,
    TPM_RC_AUTH_TYPE            = RC_VER1 + 0x024,
    TPM_RC_AUTH_MISSING         = RC_VER1 + 0x025,
    TPM_RC_POLICY               = RC_VER1 + 0x026,
    TPM_RC_PCR                  = RC_VER1 + 0x027,
    TPM_RC_PCR_CHANGED          = RC_VER1 + 0x028,
    TPM_RC_UPGRADE              = RC_VER1 + 0x02D,
    TPM_RC_TOO_MANY_CONTEXTS    = RC_VER1 + 0x02E,
    TPM_RC_AUTH_UNAVAILABLE     = RC_VER1 + 0x02F,
    TPM_RC_REBOOT               = RC_VER1 + 0x030,
    TPM_RC_UNBALANCED           = RC_VER1 + 0x031,
    TPM_RC_COMMAND_SIZE         = RC_VER1 + 0x042,
    TPM_RC_COMMAND_CODE         = RC_VER1 + 0x043,
    TPM_RC_AUTHSIZE             = RC_VER1 + 0x044,
    TPM_RC_AUTH_CONTEXT         = RC_VER1 + 0x045,
    TPM_RC_NV_RANGE             = RC_VER1 + 0x046,
    TPM_RC_NV_SIZE              = RC_VER1 + 0x047,
    TPM_RC_NV_LOCKED            = RC_VER1 + 0x048,
    TPM_RC_NV_AUTHORIZATION     = RC_VER1 + 0x049,
    TPM_RC_NV_UNINITIALIZED     = RC_VER1 + 0x04A,
    TPM_RC_NV_SPACE             = RC_VER1 + 0x04B,
    TPM_RC_NV_DEFINED           = RC_VER1 + 0x04C,
    TPM_RC_BAD_CONTEXT          = RC_VER1 + 0x050,
    TPM_RC_CPHASH               = RC_VER1 + 0x051,
    TPM_RC_PARENT               = RC_VER1 + 0x052,
    TPM_RC_NEEDS_TEST           = RC_VER1 + 0x053,
    TPM_RC_NO_RESULT            = RC_VER1 + 0x054,
    TPM_RC_SENSITIVE            = RC_VER1 + 0x055,
    RC_MAX_FM0                  = RC_VER1 + 0x07F,

    RC_FMT1 = 0x080,
    TPM_RC_ASYMMETRIC       = RC_FMT1 + 0x001,
    TPM_RC_ATTRIBUTES       = RC_FMT1 + 0x002,
    TPM_RC_HASH             = RC_FMT1 + 0x003,
    TPM_RC_VALUE            = RC_FMT1 + 0x004,
    TPM_RC_HIERARCHY        = RC_FMT1 + 0x005,
    TPM_RC_KEY_SIZE         = RC_FMT1 + 0x007,
    TPM_RC_MGF              = RC_FMT1 + 0x008,
    TPM_RC_MODE             = RC_FMT1 + 0x009,
    TPM_RC_TYPE             = RC_FMT1 + 0x00A,
    TPM_RC_HANDLE           = RC_FMT1 + 0x00B,
    TPM_RC_KDF              = RC_FMT1 + 0x00C,
    TPM_RC_RANGE            = RC_FMT1 + 0x00D,
    TPM_RC_AUTH_FAIL        = RC_FMT1 + 0x00E,
    TPM_RC_NONCE            = RC_FMT1 + 0x00F,
    TPM_RC_PP               = RC_FMT1 + 0x010,
    TPM_RC_SCHEME           = RC_FMT1 + 0x012,
    TPM_RC_SIZE             = RC_FMT1 + 0x015,
    TPM_RC_SYMMETRIC        = RC_FMT1 + 0x016,
    TPM_RC_TAG              = RC_FMT1 + 0x017,
    TPM_RC_SELECTOR         = RC_FMT1 + 0x018,
    TPM_RC_INSUFFICIENT     = RC_FMT1 + 0x01A,
    TPM_RC_SIGNATURE        = RC_FMT1 + 0x01B,
    TPM_RC_KEY              = RC_FMT1 + 0x01C,
    TPM_RC_POLICY_FAIL      = RC_FMT1 + 0x01D,
    TPM_RC_INTEGRITY        = RC_FMT1 + 0x01F,
    TPM_RC_TICKET           = RC_FMT1 + 0x020,
    TPM_RC_RESERVED_BITS    = RC_FMT1 + 0x021,
    TPM_RC_BAD_AUTH         = RC_FMT1 + 0x022,
    TPM_RC_EXPIRED          = RC_FMT1 + 0x023,
    TPM_RC_POLICY_CC        = RC_FMT1 + 0x024,
    TPM_RC_BINDING          = RC_FMT1 + 0x025,
    TPM_RC_CURVE            = RC_FMT1 + 0x026,
    TPM_RC_ECC_POINT        = RC_FMT1 + 0x027,
    RC_MAX_FMT1             = RC_FMT1 + 0x03F,

    RC_WARN = 0x900,
    TPM_RC_CONTEXT_GAP      = RC_WARN + 0x001,
    TPM_RC_OBJECT_MEMORY    = RC_WARN + 0x002,
    TPM_RC_SESSION_MEMORY   = RC_WARN + 0x003,
    TPM_RC_MEMORY           = RC_WARN + 0x004,
    TPM_RC_SESSION_HANDLES  = RC_WARN + 0x005,
    TPM_RC_OBJECT_HANDLES   = RC_WARN + 0x006,
    TPM_RC_LOCALITY         = RC_WARN + 0x007,
    TPM_RC_YIELDED          = RC_WARN + 0x008,
    TPM_RC_CANCELED         = RC_WARN + 0x009,
    TPM_RC_TESTING          = RC_WARN + 0x00A,
    TPM_RC_REFERENCE_H0     = RC_WARN + 0x010,
    TPM_RC_REFERENCE_H1     = RC_WARN + 0x011,
    TPM_RC_REFERENCE_H2     = RC_WARN + 0x012,
    TPM_RC_REFERENCE_H3     = RC_WARN + 0x013,
    TPM_RC_REFERENCE_H4     = RC_WARN + 0x014,
    TPM_RC_REFERENCE_H5     = RC_WARN + 0x015,
    TPM_RC_REFERENCE_H6     = RC_WARN + 0x016,
    TPM_RC_REFERENCE_S0     = RC_WARN + 0x018,
    TPM_RC_REFERENCE_S1     = RC_WARN + 0x019,
    TPM_RC_REFERENCE_S2     = RC_WARN + 0x01A,
    TPM_RC_REFERENCE_S3     = RC_WARN + 0x01B,
    TPM_RC_REFERENCE_S4     = RC_WARN + 0x01C,
    TPM_RC_REFERENCE_S5     = RC_WARN + 0x01D,
    TPM_RC_REFERENCE_S6     = RC_WARN + 0x01E,
    TPM_RC_NV_RATE          = RC_WARN + 0x020,
    TPM_RC_LOCKOUT          = RC_WARN + 0x021,
    TPM_RC_RETRY            = RC_WARN + 0x022,
    TPM_RC_NV_UNAVAILABLE   = RC_WARN + 0x023,
    RC_MAX_WARN             = RC_WARN + 0x03F,

    TPM_RC_NOT_USED         = RC_WARN + 0x07F,

    TPM_RC_H        = 0x000,
    TPM_RC_P        = 0x040,
    TPM_RC_S        = 0x800,
    TPM_RC_1        = 0x100,
    TPM_RC_2        = 0x200,
    TPM_RC_3        = 0x300,
    TPM_RC_4        = 0x400,
    TPM_RC_5        = 0x500,
    TPM_RC_6        = 0x600,
    TPM_RC_7        = 0x700,
    TPM_RC_8        = 0x800,
    TPM_RC_9        = 0x900,
    TPM_RC_A        = 0xA00,
    TPM_RC_B        = 0xB00,
    TPM_RC_C        = 0xC00,
    TPM_RC_D        = 0xD00,
    TPM_RC_E        = 0xE00,
    TPM_RC_F        = 0xF00,
    TPM_RC_N_MASK   = 0xF00,

    /* use negative codes for internal errors */
    TPM_RC_TIMEOUT = -100,
} TPM_RC_T;
typedef INT32 TPM_RC; /* type is unsigned 16-bits, but internally use signed 32-bit */

typedef enum {
    TPM_CLOCK_COARSE_SLOWER = -3,
    TPM_CLOCK_MEDIUM_SLOWER = -2,
    TPM_CLOCK_FINE_SLOWER   = -1,
    TPM_CLOCK_NO_CHANGE     = 0,
    TPM_CLOCK_FINE_FASTER   = 1,
    TPM_CLOCK_MEDIUM_FASTER = 2,
    TPM_CLOCK_COARSE_FASTER = 3,
} TPM_CLOCK_ADJUST_T;
typedef UINT8 TPM_CLOCK_ADJUST;

/* EA Arithmetic Operands */
typedef enum {
    TPM_EO_EQ           = 0x0000,
    TPM_EO_NEQ          = 0x0001,
    TPM_EO_SIGNED_GT    = 0x0002,
    TPM_EO_UNSIGNED_GT  = 0x0003,
    TPM_EO_SIGNED_LT    = 0x0004,
    TPM_EO_UNSIGNED_LT  = 0x0005,
    TPM_EO_SIGNED_GE    = 0x0006,
    TPM_EO_UNSIGNED_GE  = 0x0007,
    TPM_EO_SIGNED_LE    = 0x0008,
    TPM_EO_UNSIGNED_LE  = 0x0009,
    TPM_EO_BITSET       = 0x000A,
    TPM_EO_BITCLEAR     = 0x000B,
} TPM_EO_T;
typedef UINT16 TPM_EO;

/* Structure Tags */
typedef enum {
    TPM_ST_RSP_COMMAND          = 0x00C4,
    TPM_ST_NULL                 = 0X8000,
    TPM_ST_NO_SESSIONS          = 0x8001,
    TPM_ST_SESSIONS             = 0x8002,
    TPM_ST_ATTEST_NV            = 0x8014,
    TPM_ST_ATTEST_COMMAND_AUDIT = 0x8015,
    TPM_ST_ATTEST_SESSION_AUDIT = 0x8016,
    TPM_ST_ATTEST_CERTIFY       = 0x8017,
    TPM_ST_ATTEST_QUOTE         = 0x8018,
    TPM_ST_ATTEST_TIME          = 0x8019,
    TPM_ST_ATTEST_CREATION      = 0x801A,
    TPM_ST_CREATION             = 0x8021,
    TPM_ST_VERIFIED             = 0x8022,
    TPM_ST_AUTH_SECRET          = 0x8023,
    TPM_ST_HASHCHECK            = 0x8024,
    TPM_ST_AUTH_SIGNED          = 0x8025,
    TPM_ST_FU_MANIFEST          = 0x8029,
} TPM_ST_T;
typedef UINT16 TPM_ST;

/* Session Type */
typedef enum {
    TPM_SE_HMAC     = 0x00,
    TPM_SE_POLICY   = 0x01,
    TPM_SE_TRIAL    = 0x03,
} TPM_SE_T;
typedef UINT8 TPM_SE;


/* Startup Type */
typedef enum {
    TPM_SU_CLEAR = 0x0000,
    TPM_SU_STATE = 0x0001,
} TPM_SU_T;
typedef UINT16 TPM_SU;

/* Capabilities */
typedef enum {
    TPM_CAP_FIRST           = 0x00000000,
    TPM_CAP_ALGS            = TPM_CAP_FIRST,
    TPM_CAP_HANDLES         = 0x00000001,
    TPM_CAP_COMMANDS        = 0x00000002,
    TPM_CAP_PP_COMMANDS     = 0x00000003,
    TPM_CAP_AUDIT_COMMANDS  = 0x00000004,
    TPM_CAP_PCRS            = 0x00000005,
    TPM_CAP_TPM_PROPERTIES  = 0x00000006,
    TPM_CAP_PCR_PROPERTIES  = 0x00000007,
    TPM_CAP_ECC_CURVES      = 0x00000008,
    TPM_CAP_LAST            = TPM_CAP_ECC_CURVES,

    TPM_CAP_VENDOR_PROPERTY = 0x00000100,
} TPM_CAP_T;
typedef UINT32 TPM_CAP;

/* Property Tag */
typedef enum {
    TPM_PT_NONE    = 0x00000000,
    PT_GROUP       = 0x00000100,

    PT_FIXED = PT_GROUP * 1,
    TPM_PT_FAMILY_INDICATOR     = PT_FIXED + 0,
    TPM_PT_LEVEL                = PT_FIXED + 1,
    TPM_PT_REVISION             = PT_FIXED + 2,
    TPM_PT_DAY_OF_YEAR          = PT_FIXED + 3,
    TPM_PT_YEAR                 = PT_FIXED + 4,
    TPM_PT_MANUFACTURER         = PT_FIXED + 5,
    TPM_PT_VENDOR_STRING_1      = PT_FIXED + 6,
    TPM_PT_VENDOR_STRING_2      = PT_FIXED + 7,
    TPM_PT_VENDOR_STRING_3      = PT_FIXED + 8,
    TPM_PT_VENDOR_STRING_4      = PT_FIXED + 9,
    TPM_PT_VENDOR_TPM_TYPE      = PT_FIXED + 10,
    TPM_PT_FIRMWARE_VERSION_1   = PT_FIXED + 11,
    TPM_PT_FIRMWARE_VERSION_2   = PT_FIXED + 12,
    TPM_PT_INPUT_BUFFER         = PT_FIXED + 13,
    TPM_PT_HR_TRANSIENT_MIN     = PT_FIXED + 14,
    TPM_PT_HR_PERSISTENT_MIN    = PT_FIXED + 15,
    TPM_PT_HR_LOADED_MIN        = PT_FIXED + 16,
    TPM_PT_ACTIVE_SESSIONS_MAX  = PT_FIXED + 17,
    TPM_PT_PCR_COUNT            = PT_FIXED + 18,
    TPM_PT_PCR_SELECT_MIN       = PT_FIXED + 19,
    TPM_PT_CONTEXT_GAP_MAX      = PT_FIXED + 20,
    TPM_PT_NV_COUNTERS_MAX      = PT_FIXED + 22,
    TPM_PT_NV_INDEX_MAX         = PT_FIXED + 23,
    TPM_PT_MEMORY               = PT_FIXED + 24,
    TPM_PT_CLOCK_UPDATE         = PT_FIXED + 25,
    TPM_PT_CONTEXT_HASH         = PT_FIXED + 26,
    TPM_PT_CONTEXT_SYM          = PT_FIXED + 27,
    TPM_PT_CONTEXT_SYM_SIZE     = PT_FIXED + 28,
    TPM_PT_ORDERLY_COUNT        = PT_FIXED + 29,
    TPM_PT_MAX_COMMAND_SIZE     = PT_FIXED + 30,
    TPM_PT_MAX_RESPONSE_SIZE    = PT_FIXED + 31,
    TPM_PT_MAX_DIGEST           = PT_FIXED + 32,
    TPM_PT_MAX_OBJECT_CONTEXT   = PT_FIXED + 33,
    TPM_PT_MAX_SESSION_CONTEXT  = PT_FIXED + 34,
    TPM_PT_PS_FAMILY_INDICATOR  = PT_FIXED + 35,
    TPM_PT_PS_LEVEL             = PT_FIXED + 36,
    TPM_PT_PS_REVISION          = PT_FIXED + 37,
    TPM_PT_PS_DAY_OF_YEAR       = PT_FIXED + 38,
    TPM_PT_PS_YEAR              = PT_FIXED + 39,
    TPM_PT_SPLIT_MAX            = PT_FIXED + 40,
    TPM_PT_TOTAL_COMMANDS       = PT_FIXED + 41,
    TPM_PT_LIBRARY_COMMANDS     = PT_FIXED + 42,
    TPM_PT_VENDOR_COMMANDS      = PT_FIXED + 43,
    TPM_PT_NV_BUFFER_MAX        = PT_FIXED + 44,
    TPM_PT_MODES                = PT_FIXED + 45,
    TPM_PT_MAX_CAP_BUFFER       = PT_FIXED + 46,

    PT_VAR = PT_GROUP * 2,
    TPM_PT_PERMANENT            = PT_VAR + 0,
    TPM_PT_STARTUP_CLEAR        = PT_VAR + 1,
    TPM_PT_HR_NV_INDEX          = PT_VAR + 2,
    TPM_PT_HR_LOADED            = PT_VAR + 3,
    TPM_PT_HR_LOADED_AVAIL      = PT_VAR + 4,
    TPM_PT_HR_ACTIVE            = PT_VAR + 5,
    TPM_PT_HR_ACTIVE_AVAIL      = PT_VAR + 6,
    TPM_PT_HR_TRANSIENT_AVAIL   = PT_VAR + 7,
    TPM_PT_HR_PERSISTENT        = PT_VAR + 8,
    TPM_PT_HR_PERSISTENT_AVAIL  = PT_VAR + 9,
    TPM_PT_NV_COUNTERS          = PT_VAR + 10,
    TPM_PT_NV_COUNTERS_AVAIL    = PT_VAR + 11,
    TPM_PT_ALGORITHM_SET        = PT_VAR + 12,
    TPM_PT_LOADED_CURVES        = PT_VAR + 13,
    TPM_PT_LOCKOUT_COUNTER      = PT_VAR + 14,
    TPM_PT_MAX_AUTH_FAIL        = PT_VAR + 15,
    TPM_PT_LOCKOUT_INTERVAL     = PT_VAR + 16,
    TPM_PT_LOCKOUT_RECOVERY     = PT_VAR + 17,
    TPM_PT_NV_WRITE_RECOVERY    = PT_VAR + 18,
    TPM_PT_AUDIT_COUNTER_0      = PT_VAR + 19,
    TPM_PT_AUDIT_COUNTER_1      = PT_VAR + 20,
} TPM_PT_T;
typedef UINT32 TPM_PT;

/* PCR Property Tag */
typedef enum {
    TPM_PT_PCR_FIRST        = 0x00000000,
    TPM_PT_PCR_SAVE         = TPM_PT_PCR_FIRST,
    TPM_PT_PCR_EXTEND_L0    = 0x00000001,
    TPM_PT_PCR_RESET_L0     = 0x00000002,
    TPM_PT_PCR_EXTEND_L1    = 0x00000003,
    TPM_PT_PCR_RESET_L1     = 0x00000004,
    TPM_PT_PCR_EXTEND_L2    = 0x00000005,
    TPM_PT_PCR_RESET_L2     = 0x00000006,
    TPM_PT_PCR_EXTEND_L3    = 0x00000007,
    TPM_PT_PCR_RESET_L3     = 0x00000008,
    TPM_PT_PCR_EXTEND_L4    = 0x00000009,
    TPM_PT_PCR_RESET_L4     = 0x0000000A,
    TPM_PT_PCR_NO_INCREMENT = 0x00000011,
    TPM_PT_PCR_DRTM_RESET   = 0x00000012,
    TPM_PT_PCR_POLICY       = 0x00000013,
    TPM_PT_PCR_AUTH         = 0x00000014,
    TPM_PT_PCR_LAST         = TPM_PT_PCR_AUTH,
} TPM_PT_PCR_T;
typedef UINT32 TPM_PT_PCR;

/* Platform Specific */
typedef enum {
    TPM_PS_MAIN             = 0x00000000,
    TPM_PS_PC               = 0x00000001,
    TPM_PS_PDA              = 0x00000002,
    TPM_PS_CELL_PHONE       = 0x00000003,
    TPM_PS_SERVER           = 0x00000004,
    TPM_PS_PERIPHERAL       = 0x00000005,
    TPM_PS_TSS              = 0x00000006,
    TPM_PS_STORAGE          = 0x00000007,
    TPM_PS_AUTHENTICATION   = 0x00000008,
    TPM_PS_EMBEDDED         = 0x00000009,
    TPM_PS_HARDCOPY         = 0x0000000A,
    TPM_PS_INFRASTRUCTURE   = 0x0000000B,
    TPM_PS_VIRTUALIZATION   = 0x0000000C,
    TPM_PS_TNC              = 0x0000000D,
    TPM_PS_MULTI_TENANT     = 0x0000000E,
    TPM_PS_TC               = 0x0000000F,
} TPM_PS_T;
typedef UINT32 TPM_PS;


/* HANDLES */
typedef UINT32 TPM_HANDLE;

/* Handle Types */
typedef enum {
    TPM_HT_PCR              = 0x00,
    TPM_HT_NV_INDEX         = 0x01,
    TPM_HT_HMAC_SESSION     = 0x02,
    TPM_HT_LOADED_SESSION   = 0x02,
    TPM_HT_POLICY_SESSION   = 0x03,
    TPM_HT_ACTIVE_SESSION   = 0x03,
    TPM_HT_PERMANENT        = 0x40,
    TPM_HT_TRANSIENT        = 0x80,
    TPM_HT_PERSISTENT       = 0x81,
} TPM_HT_T;
typedef UINT8 TPM_HT;

/* Permanent Handles */
typedef enum {
    TPM_RH_FIRST        = 0x40000000,
    TPM_RH_SRK          = TPM_RH_FIRST,
    TPM_RH_OWNER        = 0x40000001,
    TPM_RH_REVOKE       = 0x40000002,
    TPM_RH_TRANSPORT    = 0x40000003,
    TPM_RH_OPERATOR     = 0x40000004,
    TPM_RH_ADMIN        = 0x40000005,
    TPM_RH_EK           = 0x40000006,
    TPM_RH_NULL         = 0x40000007,
    TPM_RH_UNASSIGNED   = 0x40000008,
    TPM_RS_PW           = 0x40000009,
    TPM_RH_LOCKOUT      = 0x4000000A,
    TPM_RH_ENDORSEMENT  = 0x4000000B,
    TPM_RH_PLATFORM     = 0x4000000C,
    TPM_RH_PLATFORM_NV  = 0x4000000D,
    TPM_RH_AUTH_00      = 0x40000010,
    TPM_RH_AUTH_FF      = 0x4000010F,
    TPM_RH_LAST         = TPM_RH_AUTH_FF,
} TPM_RH_T;
typedef UINT32 TPM_RH;

/* Handle Value Constants */
/* Using defines, not "enum TPM_HC_T" to avoid pedantic error:
 * "ISO C restricts enumerator values to range of 'int'"
 */
#define HR_HANDLE_MASK       0x00FFFFFFUL
#define HR_RANGE_MASK        0xFF000000UL
#define HR_SHIFT             24
#define HR_PCR               ((UINT32)TPM_HT_PCR << HR_SHIFT)
#define HR_HMAC_SESSION      ((UINT32)TPM_HT_HMAC_SESSION << HR_SHIFT)
#define HR_POLICY_SESSION    ((UINT32)TPM_HT_POLICY_SESSION << HR_SHIFT)
#define HR_TRANSIENT         ((UINT32)TPM_HT_TRANSIENT << HR_SHIFT)
#define HR_PERSISTENT        ((UINT32)TPM_HT_PERSISTENT << HR_SHIFT)
#define HR_NV_INDEX          ((UINT32)TPM_HT_NV_INDEX << HR_SHIFT)
#define HR_PERMANENT         ((UINT32)TPM_HT_PERMANENT << HR_SHIFT)
#define PCR_FIRST            (HR_PCR + 0)
#define PCR_LAST             (PCR_FIRST + IMPLEMENTATION_PCR-1)
#define HMAC_SESSION_FIRST   (HR_HMAC_SESSION + 0)
#define HMAC_SESSION_LAST    (HMAC_SESSION_FIRST+MAX_ACTIVE_SESSIONS-1)
#define LOADED_SESSION_FIRST HMAC_SESSION_FIRST
#define LOADED_SESSION_LAST  HMAC_SESSION_LAST
#define POLICY_SESSION_FIRST (HR_POLICY_SESSION + 0)
#define POLICY_SESSION_LAST  (POLICY_SESSION_FIRST+MAX_ACTIVE_SESSIONS-1)
#define TRANSIENT_FIRST      (HR_TRANSIENT + 0)
#define ACTIVE_SESSION_FIRST POLICY_SESSION_FIRST
#define ACTIVE_SESSION_LAST  POLICY_SESSION_LAST
#define TRANSIENT_LAST       (TRANSIENT_FIRST+MAX_LOADED_OBJECTS-1)
#define PERSISTENT_FIRST     (HR_PERSISTENT + 0)
#define PERSISTENT_LAST      (PERSISTENT_FIRST + 0x00FFFFFFUL)
#define PLATFORM_PERSISTENT  (PERSISTENT_FIRST + 0x00800000UL)
#define NV_INDEX_FIRST       (HR_NV_INDEX + 0)
#define NV_INDEX_LAST        (NV_INDEX_FIRST + 0x00FFFFFFUL)
#define PERMANENT_FIRST      TPM_RH_FIRST
#define PERMANENT_LAST       TPM_RH_LAST
typedef UINT32 TPM_HC;


/* Attributes */
typedef UINT32 TPMA_ALGORITHM;
enum TPMA_ALGORITHM_mask {
    TPMA_ALGORITHM_asymmetric = 0x00000001,
    TPMA_ALGORITHM_symmetric  = 0x00000002,
    TPMA_ALGORITHM_hash       = 0x00000004,
    TPMA_ALGORITHM_object     = 0x00000008,
    TPMA_ALGORITHM_signing    = 0x00000010,
    TPMA_ALGORITHM_encrypting = 0x00000020,
    TPMA_ALGORITHM_method     = 0x00000040,
};

typedef UINT32 TPMA_OBJECT;
enum TPMA_OBJECT_mask {
    TPMA_OBJECT_fixedTPM            = 0x00000002,
    TPMA_OBJECT_stClear             = 0x00000004,
    TPMA_OBJECT_fixedParent         = 0x00000010,
    TPMA_OBJECT_sensitiveDataOrigin = 0x00000020,
    TPMA_OBJECT_userWithAuth        = 0x00000040,
    TPMA_OBJECT_adminWithPolicy     = 0x00000080,
    TPMA_OBJECT_derivedDataOrigin   = 0x00000200,
    TPMA_OBJECT_noDA                = 0x00000400,
    TPMA_OBJECT_encryptedDuplication= 0x00000800,
    TPMA_OBJECT_restricted          = 0x00010000,
    TPMA_OBJECT_decrypt             = 0x00020000,
    TPMA_OBJECT_sign                = 0x00040000,
};

typedef BYTE TPMA_SESSION;
enum TPMA_SESSION_mask {
    TPMA_SESSION_continueSession    = 0x01,
    TPMA_SESSION_auditExclusive     = 0x02,
    TPMA_SESSION_auditReset         = 0x04,
    TPMA_SESSION_decrypt            = 0x20,
    TPMA_SESSION_encrypt            = 0x40,
    TPMA_SESSION_audit              = 0x80,
};

typedef BYTE TPMA_LOCALITY;
enum TPMA_LOCALITY_mask {
    TPM_LOC_ZERO = 0x01,
    TPM_LOC_ONE = 0x02,
    TPM_LOC_TWO = 0x04,
    TPM_LOC_THREE = 0x08,
    TPM_LOC_FOUR = 0x10,
};

typedef UINT32 TPMA_PERMANENT;
enum TPMA_PERMANENT_mask {
    TPMA_PERMANENT_ownerAuthSet         = 0x00000001,
    TPMA_PERMANENT_endorsementAuthSet   = 0x00000002,
    TPMA_PERMANENT_lockoutAuthSet       = 0x00000004,
    TPMA_PERMANENT_disableClear         = 0x00000100,
    TPMA_PERMANENT_inLockout            = 0x00000200,
    TPMA_PERMANENT_tpmGeneratedEPS      = 0x00000400,
};

typedef UINT32 TPMA_STARTUP_CLEAR;
/* Using defines, not "enum TPMA_STARTUP_CLEAR_mask" to avoid pedantic error:
 * "ISO C restricts enumerator values to range of 'int'"
 */
#define TPMA_STARTUP_CLEAR_phEnable   0x00000001UL
#define TPMA_STARTUP_CLEAR_shEnable   0x00000002UL
#define TPMA_STARTUP_CLEAR_ehEnable   0x00000004UL
#define TPMA_STARTUP_CLEAR_phEnableNV 0x00000008UL
#define TPMA_STARTUP_CLEAR_orderly    0x80000000UL

typedef UINT32 TPMA_MEMORY;
enum TPMA_MEMORY_mask {
    TPMA_MEMORY_sharedRAM           = 0x00000001,
    TPMA_MEMORY_sharedNV            = 0x00000002,
    TPMA_MEMORY_objectCopiedToRam   = 0x00000004,
};

typedef UINT32 TPMA_CC;
enum TPMA_CC_mask {
    TPMA_CC_commandIndex = 0x0000FFFF,
    TPMA_CC_nv           = 0x00400000,
    TPMA_CC_extensive    = 0x00800000,
    TPMA_CC_flushed      = 0x01000000,
    TPMA_CC_cHandles     = 0x0E000000,
    TPMA_CC_rHandle      = 0x10000000,
    TPMA_CC_V            = 0x20000000,
};



/* Interface Types */

typedef BYTE TPMI_YES_NO;
typedef TPM_HANDLE TPMI_DH_OBJECT;
typedef TPM_HANDLE TPMI_DH_PARENT;
typedef TPM_HANDLE TPMI_DH_PERSISTENT;
typedef TPM_HANDLE TPMI_DH_ENTITY;
typedef TPM_HANDLE TPMI_DH_PCR;
typedef TPM_HANDLE TPMI_SH_AUTH_SESSION;
typedef TPM_HANDLE TPMI_SH_HMAC;
typedef TPM_HANDLE TPMI_SH_POLICY;
typedef TPM_HANDLE TPMI_DH_CONTEXT;
typedef TPM_HANDLE TPMI_RH_HIERARCHY;
typedef TPM_HANDLE TPMI_RH_ENABLES;
typedef TPM_HANDLE TPMI_RH_HIERARCHY_AUTH;
typedef TPM_HANDLE TPMI_RH_PLATFORM;
typedef TPM_HANDLE TPMI_RH_OWNER;
typedef TPM_HANDLE TPMI_RH_ENDORSEMENT;
typedef TPM_HANDLE TPMI_RH_PROVISION;
typedef TPM_HANDLE TPMI_RH_CLEAR;
typedef TPM_HANDLE TPMI_RH_NV_AUTH;
typedef TPM_HANDLE TPMI_RH_LOCKOUT;
typedef TPM_HANDLE TPMI_RH_NV_INDEX;

typedef TPM_ALG_ID TPMI_ALG_HASH;
typedef TPM_ALG_ID TPMI_ALG_ASYM;
typedef TPM_ALG_ID TPMI_ALG_SYM;
typedef TPM_ALG_ID TPMI_ALG_SYM_OBJECT;
typedef TPM_ALG_ID TPMI_ALG_SYM_MODE;
typedef TPM_ALG_ID TPMI_ALG_KDF;
typedef TPM_ALG_ID TPMI_ALG_SIG_SCHEME;
typedef TPM_ALG_ID TPMI_ECC_KEY_EXCHANGE;

typedef TPM_ST TPMI_ST_COMMAND_TAG;


/* Structures */

typedef struct TPMS_ALGORITHM_DESCRIPTION {
    TPM_ALG_ID alg;
    TPMA_ALGORITHM attributes;
} TPMS_ALGORITHM_DESCRIPTION;


typedef union TPMU_HA {
    BYTE sha512[TPM_SHA512_DIGEST_SIZE];
    BYTE sha384[TPM_SHA384_DIGEST_SIZE];
    BYTE sha256[TPM_SHA256_DIGEST_SIZE];
    BYTE sha224[TPM_SHA224_DIGEST_SIZE];
    BYTE sha[TPM_SHA_DIGEST_SIZE];
    BYTE md5[TPM_MD5_DIGEST_SIZE];
    BYTE H[TPM_MAX_DIGEST_SIZE];
} TPMU_HA;

typedef struct TPMT_HA {
    TPMI_ALG_HASH hashAlg;
    TPMU_HA digest;
} TPMT_HA;

typedef struct TPM2B_DIGEST {
    UINT16 size;
    BYTE buffer[sizeof(TPMU_HA)];
} TPM2B_DIGEST;

typedef struct TPM2B_DATA {
    UINT16 size;
    BYTE buffer[sizeof(TPMT_HA)];
} TPM2B_DATA;

typedef TPM2B_DIGEST TPM2B_NONCE;
typedef TPM2B_DIGEST TPM2B_AUTH;
typedef TPM2B_DIGEST TPM2B_OPERAND;

typedef struct TPM2B_EVENT {
    UINT16 size;
    BYTE buffer[1024];
} TPM2B_EVENT;

typedef struct TPM2B_MAX_BUFFER {
    UINT16 size;
    BYTE buffer[MAX_DIGEST_BUFFER];
} TPM2B_MAX_BUFFER;

typedef struct TPM2B_MAX_NV_BUFFER {
    UINT16 size;
    BYTE buffer[MAX_NV_BUFFER_SIZE];
} TPM2B_MAX_NV_BUFFER;


typedef TPM2B_DIGEST TPM2B_TIMEOUT;

typedef struct TPM2B_IV {
    UINT16 size;
    BYTE buffer[MAX_SYM_BLOCK_SIZE];
} TPM2B_IV;


/* Names */
typedef union TPMU_NAME {
    TPMT_HA digest;
    TPM_HANDLE handle;
} TPMU_NAME;

typedef struct TPM2B_NAME {
    UINT16 size;
    BYTE name[sizeof(TPMU_NAME)];
} TPM2B_NAME;


/* PCR */

typedef struct TPMS_PCR_SELECT {
    BYTE sizeofSelect;
    BYTE pcrSelect[PCR_SELECT_MIN];
} TPMS_PCR_SELECT;


typedef struct TPMS_PCR_SELECTION {
    TPMI_ALG_HASH hash;
    BYTE sizeofSelect;
    BYTE pcrSelect[PCR_SELECT_MIN];
} TPMS_PCR_SELECTION;


/* Tickets */

typedef struct TPMT_TK_CREATION {
    TPM_ST tag;
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_DIGEST digest;
} TPMT_TK_CREATION;

typedef struct TPMT_TK_VERIFIED {
    TPM_ST tag;
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_DIGEST digest;
} TPMT_TK_VERIFIED;

typedef struct TPMT_TK_AUTH {
    TPM_ST tag;
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_DIGEST digest;
} TPMT_TK_AUTH;

typedef struct TPMT_TK_HASHCHECK {
    TPM_ST tag;
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_DIGEST digest;
} TPMT_TK_HASHCHECK;

typedef struct TPMS_ALG_PROPERTY {
    TPM_ALG_ID alg;
    TPMA_ALGORITHM algProperties;
} TPMS_ALG_PROPERTY;

typedef struct TPMS_TAGGED_PROPERTY {
    TPM_PT property;
    UINT32 value;
} TPMS_TAGGED_PROPERTY;

typedef struct TPMS_TAGGED_PCR_SELECT {
    TPM_PT_PCR tag;
    BYTE sizeofSelect;
    BYTE pcrSelect[PCR_SELECT_MAX];
} TPMS_TAGGED_PCR_SELECT;

typedef struct TPMS_TAGGED_POLICY {
    TPM_HANDLE handle;
    TPMT_HA policyHash;
} TPMS_TAGGED_POLICY;


/* Lists */

typedef struct TPML_CC {
    UINT32 count;
    TPM_CC commandCodes[MAX_CAP_CC];
} TPML_CC;

typedef struct TPML_CCA {
    UINT32 count;
    TPMA_CC commandAttributes[MAX_CAP_CC];
} TPML_CCA;

typedef struct TPML_ALG {
    UINT32 count;
    TPM_ALG_ID algorithms[MAX_ALG_LIST_SIZE];
} TPML_ALG;

typedef struct TPML_HANDLE {
    UINT32 count;
    TPM_HANDLE handle[MAX_CAP_HANDLES];
} TPML_HANDLE;

typedef struct TPML_DIGEST {
    UINT32 count;
    TPM2B_DIGEST digests[8];
} TPML_DIGEST;

typedef struct TPML_DIGEST_VALUES {
    UINT32 count;
    TPMT_HA digests[HASH_COUNT];
} TPML_DIGEST_VALUES;

typedef struct TPML_PCR_SELECTION {
    UINT32 count;
    TPMS_PCR_SELECTION pcrSelections[HASH_COUNT];
} TPML_PCR_SELECTION;

typedef struct TPML_ALG_PROPERTY {
    UINT32 count;
    TPMS_ALG_PROPERTY algProperties[MAX_CAP_ALGS];
} TPML_ALG_PROPERTY;

typedef struct TPML_TAGGED_TPM_PROPERTY {
    UINT32 count;
    TPMS_TAGGED_PROPERTY tpmProperty[MAX_TPM_PROPERTIES];
} TPML_TAGGED_TPM_PROPERTY;

typedef struct TPML_TAGGED_PCR_PROPERTY {
    UINT32 count;
    TPMS_TAGGED_PCR_SELECT pcrProperty[MAX_PCR_PROPERTIES];
} TPML_TAGGED_PCR_PROPERTY;

typedef struct TPML_ECC_CURVE {
    UINT32 count;
    TPM_ECC_CURVE eccCurves[MAX_ECC_CURVES];
} TPML_ECC_CURVE;

typedef struct TPML_TAGGED_POLICY {
    UINT32 count;
    TPMS_TAGGED_POLICY policies[MAX_TAGGED_POLICIES];
} TPML_TAGGED_POLICY;


/* Capabilities Structures */

typedef union TPMU_CAPABILITIES {
    TPML_ALG_PROPERTY algorithms; /* TPM_CAP_ALGS */
    TPML_HANDLE handles; /* TPM_CAP_HANDLES */
    TPML_CCA command; /* TPM_CAP_COMMANDS */
    TPML_CC ppCommands; /* TPM_CAP_PP_COMMANDS */
    TPML_CC auditCommands; /* TPM_CAP_AUDIT_COMMANDS */
    TPML_PCR_SELECTION assignedPCR; /* TPM_CAP_PCRS */
    TPML_TAGGED_TPM_PROPERTY tpmProperties; /* TPM_CAP_TPM_PROPERTIES */
    TPML_TAGGED_PCR_PROPERTY pcrProperties; /* TPM_CAP_PCR_PROPERTIES */
    TPML_ECC_CURVE eccCurves; /* TPM_CAP_ECC_CURVES */
    TPML_TAGGED_POLICY authPolicies; /* TPM_CAP_AUTH_POLICIES */
    TPM2B_MAX_BUFFER vendor;
} TPMU_CAPABILITIES;

typedef struct TPMS_CAPABILITY_DATA {
    TPM_CAP capability;
    TPMU_CAPABILITIES data;
} TPMS_CAPABILITY_DATA;

typedef struct TPMS_CLOCK_INFO {
    UINT64 clock;
    UINT32 resetCount;
    UINT32 restartCount;
    TPMI_YES_NO safe;
} TPMS_CLOCK_INFO;

typedef struct TPMS_TIME_INFO {
    UINT64 time;
    TPMS_CLOCK_INFO clockInfo;
} TPMS_TIME_INFO;

typedef struct TPMS_TIME_ATTEST_INFO {
    TPMS_TIME_INFO time;
    UINT64 firmwareVersion;
} TPMS_TIME_ATTEST_INFO;

typedef struct TPMS_CERTIFY_INFO {
    TPM2B_NAME name;
    TPM2B_NAME qualifiedName;
} TPMS_CERTIFY_INFO;

typedef struct TPMS_QUOTE_INFO {
    TPML_PCR_SELECTION pcrSelect;
    TPM2B_DIGEST pcrDigest;
} TPMS_QUOTE_INFO;

typedef struct TPMS_COMMAND_AUDIT_INFO {
    UINT64 auditCounter;
    TPM_ALG_ID digestAlg;
    TPM2B_DIGEST auditDigest;
    TPM2B_DIGEST commandDigest;
} TPMS_COMMAND_AUDIT_INFO;

typedef struct TPMS_SESSION_AUDIT_INFO {
    TPMI_YES_NO exclusiveSession;
    TPM2B_DIGEST sessionDigest;
} TPMS_SESSION_AUDIT_INFO;

typedef struct TPMS_CREATION_INFO {
    TPM2B_NAME objectName;
    TPM2B_DIGEST creationHash;
} TPMS_CREATION_INFO;

typedef struct TPMS_NV_CERTIFY_INFO {
    TPM2B_NAME indexName;
    UINT16 offset;
    TPM2B_MAX_NV_BUFFER nvContents;
} TPMS_NV_CERTIFY_INFO;


typedef TPM_ST TPMI_ST_ATTEST;
typedef union TPMU_ATTEST {
    TPMS_CERTIFY_INFO       certify;        /* TPM_ST_ATTEST_CERTIFY */
    TPMS_CREATION_INFO      creation;       /* TPM_ST_ATTEST_CREATION */
    TPMS_QUOTE_INFO         quote;          /* TPM_ST_ATTEST_QUOTE */
    TPMS_COMMAND_AUDIT_INFO commandAudit;   /* TPM_ST_ATTEST_COMMAND_AUDIT */
    TPMS_SESSION_AUDIT_INFO sessionAudit;   /* TPM_ST_ATTEST_SESSION_AUDIT */
    TPMS_TIME_ATTEST_INFO   time;           /* TPM_ST_ATTEST_TIME */
    TPMS_NV_CERTIFY_INFO    nv;             /* TPM_ST_ATTEST_NV */
} TPMU_ATTEST;

typedef struct TPMS_ATTEST {
    TPM_GENERATED magic;
    TPMI_ST_ATTEST type;
    TPM2B_NAME qualifiedSigner;
    TPM2B_DATA extraData;
    TPMS_CLOCK_INFO clockInfo;
    UINT64 firmwareVersion;
    TPMU_ATTEST attested;
} TPMS_ATTEST;

typedef struct TPM2B_ATTEST {
    UINT16 size;
    BYTE attestationData[sizeof(TPMS_ATTEST)];
} TPM2B_ATTEST;


/* Algorithm Parameters and Structures */

/* Symmetric */
typedef TPM_KEY_BITS TPMI_AES_KEY_BITS;

typedef union TPMU_SYM_KEY_BITS {
    TPMI_AES_KEY_BITS aes;
    TPM_KEY_BITS sym;
    TPMI_ALG_HASH xorr;
} TPMU_SYM_KEY_BITS;

typedef union TPMU_SYM_MODE {
    TPMI_ALG_SYM_MODE aes;
    TPMI_ALG_SYM_MODE sym;
} TPMU_SYM_MODE;

typedef struct TPMT_SYM_DEF {
    TPMI_ALG_SYM algorithm;
    TPMU_SYM_KEY_BITS keyBits;
    TPMU_SYM_MODE mode;
    /*TPMU_SYM_DETAILS details;*/ /* not used */
} TPMT_SYM_DEF;

typedef TPMT_SYM_DEF TPMT_SYM_DEF_OBJECT;

typedef struct TPM2B_SYM_KEY {
    UINT16 size;
    BYTE buffer[MAX_SYM_KEY_BYTES];
} TPM2B_SYM_KEY;

typedef struct TPMS_SYMCIPHER_PARMS {
    TPMT_SYM_DEF_OBJECT sym;
} TPMS_SYMCIPHER_PARMS;

typedef struct TPM2B_LABEL {
    UINT16 size;
    BYTE buffer[LABEL_MAX_BUFFER];
} TPM2B_LABEL;

typedef struct TPMS_DERIVE {
    TPM2B_LABEL label;
    TPM2B_LABEL context;
} TPMS_DERIVE;

typedef struct TPM2B_DERIVE {
    UINT16 size;
    BYTE buffer[sizeof(TPMS_DERIVE)];
} TPM2B_DERIVE;

typedef union TPMU_SENSITIVE_CREATE {
    BYTE create[MAX_SYM_DATA];
    TPMS_DERIVE derive;
} TPMU_SENSITIVE_CREATE;

typedef struct TPM2B_SENSITIVE_DATA {
    UINT16 size;
    BYTE buffer[sizeof(TPMU_SENSITIVE_CREATE)];
} TPM2B_SENSITIVE_DATA;

typedef struct TPMS_SENSITIVE_CREATE {
    TPM2B_AUTH userAuth;
    TPM2B_SENSITIVE_DATA data;
} TPMS_SENSITIVE_CREATE;

typedef struct TPM2B_SENSITIVE_CREATE {
    UINT16 size;
    TPMS_SENSITIVE_CREATE sensitive;
} TPM2B_SENSITIVE_CREATE;

typedef struct TPMS_SCHEME_HASH {
    TPMI_ALG_HASH hashAlg;
} TPMS_SCHEME_HASH;

typedef struct TPMS_SCHEME_ECDAA {
    TPMI_ALG_HASH hashAlg;
    UINT16 count;
} TPMS_SCHEME_ECDAA;

typedef TPM_ALG_ID TPMI_ALG_KEYEDHASH_SCHEME;
typedef TPMS_SCHEME_HASH TPMS_SCHEME_HMAC;

typedef union TPMU_SCHEME_KEYEDHASH {
    TPMS_SCHEME_HMAC hmac;
} TPMU_SCHEME_KEYEDHASH;

typedef struct TPMT_KEYEDHASH_SCHEME {
    TPMI_ALG_KEYEDHASH_SCHEME scheme;
    TPMU_SCHEME_KEYEDHASH details;
} TPMT_KEYEDHASH_SCHEME;


/* Asymmetric */

typedef TPMS_SCHEME_HASH  TPMS_SIG_SCHEME_RSASSA;
typedef TPMS_SCHEME_HASH  TPMS_SIG_SCHEME_RSAPSS;
typedef TPMS_SCHEME_HASH  TPMS_SIG_SCHEME_ECDSA;

typedef TPMS_SCHEME_ECDAA TPMS_SIG_SCHEME_ECDAA;


typedef union TPMU_SIG_SCHEME {
    TPMS_SIG_SCHEME_RSASSA rsassa;
    TPMS_SIG_SCHEME_RSAPSS rsapss;
    TPMS_SIG_SCHEME_ECDSA  ecdsa;
    TPMS_SIG_SCHEME_ECDAA  ecdaa;
    TPMS_SCHEME_HMAC       hmac;
    TPMS_SCHEME_HASH       any;
} TPMU_SIG_SCHEME;

typedef struct TPMT_SIG_SCHEME {
    TPMI_ALG_SIG_SCHEME scheme;
    TPMU_SIG_SCHEME details;
} TPMT_SIG_SCHEME;


/* Encryption / Key Exchange Schemes */
typedef TPMS_SCHEME_HASH TPMS_ENC_SCHEME_OAEP;
typedef TPMS_SCHEME_HASH TPMS_KEY_SCHEME_ECDH;
typedef TPMS_SCHEME_HASH TPMS_KEY_SCHEME_ECMQV;

/* Key Derivation Schemes */
typedef TPMS_SCHEME_HASH TPMS_SCHEME_MGF1;
typedef TPMS_SCHEME_HASH TPMS_SCHEME_KDF1_SP800_56A;
typedef TPMS_SCHEME_HASH TPMS_SCHEME_KDF2;
typedef TPMS_SCHEME_HASH TPMS_SCHEME_KDF1_SP800_108;

typedef union TPMU_KDF_SCHEME {
    TPMS_SCHEME_MGF1            mgf1;
    TPMS_SCHEME_KDF1_SP800_56A  kdf1_sp800_56a;
    TPMS_SCHEME_KDF2            kdf2;
    TPMS_SCHEME_KDF1_SP800_108  kdf1_sp800_108;
    TPMS_SCHEME_HASH            any;
} TPMU_KDF_SCHEME;

typedef struct TPMT_KDF_SCHEME {
    TPMI_ALG_KDF scheme;
    TPMU_KDF_SCHEME details;
} TPMT_KDF_SCHEME;

typedef TPM_ALG_ID TPMI_ALG_ASYM_SCHEME;
typedef union TPMU_ASYM_SCHEME {
    TPMS_KEY_SCHEME_ECDH    ecdh;
    TPMS_SIG_SCHEME_RSASSA  rsassa;
    TPMS_SIG_SCHEME_RSAPSS  rsapss;
    TPMS_SIG_SCHEME_ECDSA   ecdsa;
    TPMS_ENC_SCHEME_OAEP    oaep;
    TPMS_SCHEME_HASH        anySig;
} TPMU_ASYM_SCHEME;

typedef struct TPMT_ASYM_SCHEME {
    TPMI_ALG_ASYM_SCHEME scheme;
    TPMU_ASYM_SCHEME details;
} TPMT_ASYM_SCHEME;

/* RSA */
typedef TPM_ALG_ID TPMI_ALG_RSA_SCHEME;
typedef struct TPMT_RSA_SCHEME {
    TPMI_ALG_RSA_SCHEME scheme;
    TPMU_ASYM_SCHEME details;
} TPMT_RSA_SCHEME;

typedef TPM_ALG_ID TPMI_ALG_RSA_DECRYPT;
typedef struct TPMT_RSA_DECRYPT {
    TPMI_ALG_RSA_DECRYPT scheme;
    TPMU_ASYM_SCHEME details;
} TPMT_RSA_DECRYPT;

typedef struct TPM2B_PUBLIC_KEY_RSA {
    UINT16 size;
    BYTE buffer[MAX_RSA_KEY_BYTES];
} TPM2B_PUBLIC_KEY_RSA;

typedef TPM_KEY_BITS TPMI_RSA_KEY_BITS;
typedef struct TPM2B_PRIVATE_KEY_RSA {
    UINT16 size;
    BYTE buffer[MAX_RSA_KEY_BYTES/2];
} TPM2B_PRIVATE_KEY_RSA;


/* ECC */
typedef struct TPM2B_ECC_PARAMETER {
    UINT16 size;
    BYTE buffer[MAX_ECC_KEY_BYTES];
} TPM2B_ECC_PARAMETER;

typedef struct TPMS_ECC_POINT {
    TPM2B_ECC_PARAMETER x;
    TPM2B_ECC_PARAMETER y;
} TPMS_ECC_POINT;

typedef struct TPM2B_ECC_POINT {
    UINT16 size;
    TPMS_ECC_POINT point;
} TPM2B_ECC_POINT;


typedef TPM_ALG_ID TPMI_ALG_ECC_SCHEME;
typedef TPM_ECC_CURVE TPMI_ECC_CURVE;
typedef TPMT_SIG_SCHEME TPMT_ECC_SCHEME;

typedef struct TPMS_ALGORITHM_DETAIL_ECC {
    TPM_ECC_CURVE curveID;
    UINT16 keySize;
    TPMT_KDF_SCHEME kdf;
    TPMT_ECC_SCHEME sign;
    TPM2B_ECC_PARAMETER p;
    TPM2B_ECC_PARAMETER a;
    TPM2B_ECC_PARAMETER b;
    TPM2B_ECC_PARAMETER gX;
    TPM2B_ECC_PARAMETER gY;
    TPM2B_ECC_PARAMETER n;
    TPM2B_ECC_PARAMETER h;
} TPMS_ALGORITHM_DETAIL_ECC;


/* Signatures */

typedef struct TPMS_SIGNATURE_RSA {
    TPMI_ALG_HASH hash;
    TPM2B_PUBLIC_KEY_RSA sig;
} TPMS_SIGNATURE_RSA;

typedef TPMS_SIGNATURE_RSA TPMS_SIGNATURE_RSASSA;
typedef TPMS_SIGNATURE_RSA TPMS_SIGNATURE_RSAPSS;

typedef struct TPMS_SIGNATURE_ECC {
    TPMI_ALG_HASH hash;
    TPM2B_ECC_PARAMETER signatureR;
    TPM2B_ECC_PARAMETER signatureS;
} TPMS_SIGNATURE_ECC;

typedef TPMS_SIGNATURE_ECC TPMS_SIGNATURE_ECDSA;
typedef TPMS_SIGNATURE_ECC TPMS_SIGNATURE_ECDAA;

typedef union TPMU_SIGNATURE {
    TPMS_SIGNATURE_ECDSA ecdsa;
    TPMS_SIGNATURE_ECDAA ecdaa;
    TPMS_SIGNATURE_RSASSA rsassa;
    TPMS_SIGNATURE_RSAPSS rsapss;
    TPMT_HA hmac;
    TPMS_SCHEME_HASH any;
} TPMU_SIGNATURE;

typedef struct TPMT_SIGNATURE {
    TPMI_ALG_SIG_SCHEME sigAlg;
    TPMU_SIGNATURE signature;
} TPMT_SIGNATURE;


/* Key/Secret Exchange */

typedef union TPMU_ENCRYPTED_SECRET {
    BYTE ecc[sizeof(TPMS_ECC_POINT)];     /* TPM_ALG_ECC */
    BYTE rsa[MAX_RSA_KEY_BYTES];          /* TPM_ALG_RSA */
    BYTE symmetric[sizeof(TPM2B_DIGEST)]; /* TPM_ALG_SYMCIPHER */
    BYTE keyedHash[sizeof(TPM2B_DIGEST)]; /* TPM_ALG_KEYEDHASH */
} TPMU_ENCRYPTED_SECRET;

typedef struct TPM2B_ENCRYPTED_SECRET {
    UINT16 size;
    BYTE secret[sizeof(TPMU_ENCRYPTED_SECRET)];
} TPM2B_ENCRYPTED_SECRET;


/* Key/Object Complex */

typedef TPM_ALG_ID TPMI_ALG_PUBLIC;

typedef union TPMU_PUBLIC_ID {
    TPM2B_DIGEST keyedHash;   /* TPM_ALG_KEYEDHASH */
    TPM2B_DIGEST sym;         /* TPM_ALG_SYMCIPHER */
    TPM2B_PUBLIC_KEY_RSA rsa; /* TPM_ALG_RSA */
    TPMS_ECC_POINT ecc;       /* TPM_ALG_ECC */
    TPMS_DERIVE derive;
} TPMU_PUBLIC_ID;

typedef struct TPMS_KEYEDHASH_PARMS {
    TPMT_KEYEDHASH_SCHEME scheme;
} TPMS_KEYEDHASH_PARMS;


typedef struct TPMS_ASYM_PARMS {
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_ASYM_SCHEME scheme;
} TPMS_ASYM_PARMS;

typedef struct TPMS_RSA_PARMS {
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_RSA_SCHEME scheme;
    TPMI_RSA_KEY_BITS keyBits;
    UINT32 exponent;
} TPMS_RSA_PARMS;

typedef struct TPMS_ECC_PARMS {
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_ECC_SCHEME scheme;
    TPMI_ECC_CURVE curveID;
    TPMT_KDF_SCHEME kdf;
} TPMS_ECC_PARMS;

typedef union TPMU_PUBLIC_PARMS {
    TPMS_KEYEDHASH_PARMS keyedHashDetail;
    TPMS_SYMCIPHER_PARMS symDetail;
    TPMS_RSA_PARMS rsaDetail;
    TPMS_ECC_PARMS eccDetail;
    TPMS_ASYM_PARMS asymDetail;
} TPMU_PUBLIC_PARMS;

typedef struct TPMT_PUBLIC_PARMS {
    TPMI_ALG_PUBLIC type;
    TPMU_PUBLIC_PARMS parameters;
} TPMT_PUBLIC_PARMS;


typedef struct TPMT_PUBLIC {
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    TPMA_OBJECT objectAttributes;
    TPM2B_DIGEST authPolicy;
    TPMU_PUBLIC_PARMS parameters;
    TPMU_PUBLIC_ID unique;
} TPMT_PUBLIC;

typedef struct TPM2B_PUBLIC {
    UINT16 size;
    TPMT_PUBLIC publicArea;
} TPM2B_PUBLIC;

typedef struct TPM2B_TEMPLATE {
    UINT16 size;
    BYTE buffer[sizeof(TPMT_PUBLIC)];
} TPM2B_TEMPLATE;


/* Private Structures */

typedef struct TPM2B_PRIVATE_VENDOR_SPECIFIC {
    UINT16 size;
    BYTE buffer[PRIVATE_VENDOR_SPECIFIC_BYTES];
} TPM2B_PRIVATE_VENDOR_SPECIFIC;

typedef union TPMU_SENSITIVE_COMPOSITE {
    TPM2B_PRIVATE_KEY_RSA rsa;  /* TPM_ALG_RSA */
    TPM2B_ECC_PARAMETER ecc;    /* TPM_ALG_ECC */
    TPM2B_SENSITIVE_DATA bits;  /* TPM_ALG_KEYEDHASH */
    TPM2B_SYM_KEY sym;          /* TPM_ALG_SYMCIPHER */
    TPM2B_PRIVATE_VENDOR_SPECIFIC any;
} TPMU_SENSITIVE_COMPOSITE;


typedef struct TPMT_SENSITIVE {
    TPMI_ALG_PUBLIC sensitiveType;
    TPM2B_AUTH authValue;
    TPM2B_DIGEST seedValue;
    TPMU_SENSITIVE_COMPOSITE sensitive;
} TPMT_SENSITIVE;

typedef struct TPM2B_SENSITIVE {
    UINT16 size;
    TPMT_SENSITIVE sensitiveArea;
} TPM2B_SENSITIVE;


typedef struct TPMT_PRIVATE {
    TPM2B_DIGEST integrityOuter;
    TPM2B_DIGEST integrityInner;
    TPM2B_SENSITIVE sensitive;
} TPMT_PRIVATE;

typedef struct TPM2B_PRIVATE {
    UINT16 size;
    BYTE buffer[sizeof(TPMT_PRIVATE)];
} TPM2B_PRIVATE;


/* Identity Object */

typedef struct TPMS_ID_OBJECT {
    TPM2B_DIGEST integrityHMAC;
    TPM2B_DIGEST encIdentity;
} TPMS_ID_OBJECT;

typedef struct TPM2B_ID_OBJECT {
    UINT16 size;
    BYTE buffer[sizeof(TPMS_ID_OBJECT)];
} TPM2B_ID_OBJECT;


/* NV Storage Structures */

typedef UINT32 TPM_NV_INDEX;
/* Using defines, not "enum TPM_NV_INDEX_mask" to avoid pedantic error:
 * "ISO C restricts enumerator values to range of 'int'"
 */
#define TPM_NV_INDEX_index 0x00FFFFFFUL
#define TPM_NV_INDEX_RH_NV 0xFF000000UL


typedef enum TPM_NT {
    TPM_NT_ORDINARY = 0x0,
    TPM_NT_COUNTER  = 0x1,
    TPM_NT_BITS     = 0x2,
    TPM_NT_EXTEND   = 0x4,
    TPM_NT_PIN_FAIL = 0x8,
    TPM_NT_PIN_PASS = 0x9,
} TPM_NT;


typedef struct TPMS_NV_PIN_COUNTER_PARAMETERS {
    UINT32 pinCount;
    UINT32 pinLimit;
} TPMS_NV_PIN_COUNTER_PARAMETERS;

typedef UINT32 TPMA_NV;
/* Using defines, not "enum TPMA_NV_mask" to avoid pedantic error:
 * "ISO C restricts enumerator values to range of 'int'"
 */
#define TPMA_NV_PPWRITE        0x00000001UL
#define TPMA_NV_OWNERWRITE     0x00000002UL
#define TPMA_NV_AUTHWRITE      0x00000004UL
#define TPMA_NV_POLICYWRITE    0x00000008UL
#define TPMA_NV_TPM_NT         0x000000F0UL
#define TPMA_NV_POLICY_DELETE  0x00000400UL
#define TPMA_NV_WRITELOCKED    0x00000800UL
#define TPMA_NV_WRITEALL       0x00001000UL
#define TPMA_NV_WRITEDEFINE    0x00002000UL
#define TPMA_NV_WRITE_STCLEAR  0x00004000UL
#define TPMA_NV_GLOBALLOCK     0x00008000UL
#define TPMA_NV_PPREAD         0x00010000UL
#define TPMA_NV_OWNERREAD      0x00020000UL
#define TPMA_NV_AUTHREAD       0x00040000UL
#define TPMA_NV_POLICYREAD     0x00080000UL
#define TPMA_NV_NO_DA          0x02000000UL
#define TPMA_NV_ORDERLY        0x04000000UL
#define TPMA_NV_CLEAR_STCLEAR  0x08000000UL
#define TPMA_NV_READLOCKED     0x10000000UL
#define TPMA_NV_WRITTEN        0x20000000UL
#define TPMA_NV_PLATFORMCREATE 0x40000000UL
#define TPMA_NV_READ_STCLEAR   0x80000000UL

typedef struct TPMS_NV_PUBLIC {
    TPMI_RH_NV_INDEX nvIndex;
    TPMI_ALG_HASH nameAlg;
    TPMA_NV attributes;
    TPM2B_DIGEST authPolicy;
    UINT16 dataSize;
} TPMS_NV_PUBLIC;

typedef struct TPM2B_NV_PUBLIC {
    UINT16 size;
    TPMS_NV_PUBLIC nvPublic;
} TPM2B_NV_PUBLIC;


/* Context Data */

typedef struct TPM2B_CONTEXT_SENSITIVE {
    UINT16 size;
    BYTE buffer[MAX_CONTEXT_SIZE];
} TPM2B_CONTEXT_SENSITIVE;

typedef struct TPMS_CONTEXT_DATA {
    TPM2B_DIGEST integrity;
    TPM2B_CONTEXT_SENSITIVE encrypted;
} TPMS_CONTEXT_DATA;

typedef struct TPM2B_CONTEXT_DATA {
    UINT16 size;
    BYTE buffer[sizeof(TPMS_CONTEXT_DATA)];
} TPM2B_CONTEXT_DATA;

typedef struct TPMS_CONTEXT {
    UINT64 sequence;
    TPMI_DH_CONTEXT savedHandle;
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_CONTEXT_DATA contextBlob;
} TPMS_CONTEXT;


typedef struct TPMS_CREATION_DATA {
    TPML_PCR_SELECTION pcrSelect;
    TPM2B_DIGEST pcrDigest;
    TPMA_LOCALITY locality;
    TPM_ALG_ID parentNameAlg;
    TPM2B_NAME parentName;
    TPM2B_NAME parentQualifiedName;
    TPM2B_DATA outsideInfo;
} TPMS_CREATION_DATA;

typedef struct TPM2B_CREATION_DATA {
    UINT16 size;
    TPMS_CREATION_DATA creationData;
} TPM2B_CREATION_DATA;


/* Authorization Structures */
typedef struct TPMS_AUTH_COMMAND {
    TPMI_SH_AUTH_SESSION sessionHandle;
    TPM2B_NONCE nonce; /* nonceCaller */
    TPMA_SESSION sessionAttributes;
    TPM2B_AUTH hmac;
} TPMS_AUTH_COMMAND;

typedef struct TPMS_AUTH_RESPONSE {
    TPM2B_NONCE nonce;
    TPMA_SESSION sessionAttributes;
    TPM2B_AUTH hmac;
} TPMS_AUTH_RESPONSE;

/* Implementation specific authorization session information */
typedef struct TPM2_AUTH_SESSION {
    /* BEGIN */
    /* This section should match TPMS_AUTH_COMMAND */
    TPMI_SH_AUTH_SESSION sessionHandle;
    TPM2B_NONCE nonceCaller;
    TPMA_SESSION sessionAttributes;
    TPM2B_AUTH auth;
    /* END */

    /* additional auth data required for implementation */
    TPM2B_NONCE nonceTPM;
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH authHash;
    TPM2B_NAME name;
} TPM2_AUTH_SESSION;

/* Macros to determine TPM 2.0 Session type */
#define TPM2_IS_PWD_SESSION(sessionHandle) ((sessionHandle) == TPM_RS_PW)
#define TPM2_IS_HMAC_SESSION(sessionHandle) ((sessionHandle & 0xFF000000) == HMAC_SESSION_FIRST)
#define TPM2_IS_POLICY_SESSION(sessionHandle) ((sessionHandle & 0xFF000000) == POLICY_SESSION_FIRST)

/* Predetermined TPM 2.0 Indexes */
#define TPM_20_TPM_MFG_NV_SPACE        ((TPM_HT_NV_INDEX << 24) | (0x00 << 22))
#define TPM_20_PLATFORM_MFG_NV_SPACE   ((TPM_HT_NV_INDEX << 24) | (0x01 << 22))
#define TPM_20_OWNER_NV_SPACE          ((TPM_HT_NV_INDEX << 24) | (0x02 << 22))
#define TPM_20_TCG_NV_SPACE            ((TPM_HT_NV_INDEX << 24) | (0x03 << 22))

#define TPM_20_NV_INDEX_EK_CERTIFICATE (TPM_20_PLATFORM_MFG_NV_SPACE + 2)
#define TPM_20_NV_INDEX_EK_NONCE       (TPM_20_PLATFORM_MFG_NV_SPACE + 3)
#define TPM_20_NV_INDEX_EK_TEMPLATE    (TPM_20_PLATFORM_MFG_NV_SPACE + 4)

/* Predetermined TPM 2.0 Endorsement policy auth template for SHA2-256 */
static const BYTE TPM_20_EK_AUTH_POLICY[] = {
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc,
    0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52,
    0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
};



/* HAL IO Callbacks */
struct TPM2_CTX;

#ifdef WOLFTPM_SWTPM
struct wolfTPM_tcpContext {
    int fd;
};
#endif /* WOLFTPM_SWTPM */

#ifdef WOLFTPM_WINAPI
#include <tbs.h>
#include <winerror.h>

struct wolfTPM_winContext {
  TBS_HCONTEXT tbs_context;
};
/* may be needed with msys */
#ifndef TPM_E_COMMAND_BLOCKED
#define TPM_E_COMMAND_BLOCKED (0x80280400)
#endif

#define WOLFTPM_IS_COMMAND_UNAVAILABLE(code) ((code) == (int)TPM_RC_COMMAND_CODE || (code) == (int)TPM_E_COMMAND_BLOCKED)
#else
#define WOLFTPM_IS_COMMAND_UNAVAILABLE(code) (code == (int)TPM_RC_COMMAND_CODE)
#endif /* WOLFTPM_WINAPI */

/* make sure advanced IO is enabled for I2C */
#ifdef WOLFTPM_I2C
    #undef  WOLFTPM_ADV_IO
    #define WOLFTPM_ADV_IO
#endif

#ifdef WOLFTPM_ADV_IO
typedef int (*TPM2HalIoCb)(struct TPM2_CTX*, INT32 isRead, UINT32 addr,
    BYTE* xferBuf, UINT16 xferSz, void* userCtx);
#else
typedef int (*TPM2HalIoCb)(struct TPM2_CTX*, const BYTE* txBuf, BYTE* rxBuf,
    UINT16 xferSz, void* userCtx);
#endif

#if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(WC_NO_RNG) && \
    !defined(WOLFTPM2_USE_HW_RNG)
    #define WOLFTPM2_USE_WOLF_RNG
#endif

#if MAX_RESPONSE_SIZE > MAX_COMMAND_SIZE
#define XFER_MAX_SIZE MAX_RESPONSE_SIZE
#else
#define XFER_MAX_SIZE MAX_COMMAND_SIZE
#endif

typedef struct TPM2_CTX {
    TPM2HalIoCb ioCb;
    void* userCtx;
#ifdef WOLFTPM_SWTPM
    struct wolfTPM_tcpContext tcpCtx;
#endif
#ifdef WOLFTPM_WINAPI
    struct wolfTPM_winContext winCtx;
#endif
#ifndef WOLFTPM2_NO_WOLFCRYPT
#ifndef WOLFTPM_NO_LOCK
    wolfSSL_Mutex hwLock;
    int lockCount;
#endif
    #ifdef WOLFTPM2_USE_WOLF_RNG
    WC_RNG rng;
    #endif
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

    /* TPM TIS Info */
    int locality;
    word32 caps;
    word32 did_vid;

    /* Pointer to current TPM auth sessions */
    TPM2_AUTH_SESSION* session;

    /* Command / Response Buffer */
    byte cmdBuf[XFER_MAX_SIZE];

    byte rid;
    /* Informational Bits - use unsigned int for best compiler compatibility */
#ifndef WOLFTPM2_NO_WOLFCRYPT
    #ifndef WOLFTPM_NO_LOCK
    unsigned int hwLockInit:1;
    #endif
    #ifndef WC_NO_RNG
    unsigned int rngInit:1;
    #endif
#endif
} TPM2_CTX;


/* TPM Specification Functions */
typedef struct {
    TPM_SU startupType;
} Startup_In;
WOLFTPM_API TPM_RC TPM2_Startup(Startup_In* in);

typedef struct {
    TPM_SU shutdownType;
} Shutdown_In;
WOLFTPM_API TPM_RC TPM2_Shutdown(Shutdown_In* in);


typedef struct {
    TPM_CAP capability;
    UINT32 property;
    UINT32 propertyCount;
} GetCapability_In;
typedef struct {
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;
} GetCapability_Out;
WOLFTPM_API TPM_RC TPM2_GetCapability(GetCapability_In* in,
    GetCapability_Out* out);


typedef struct {
    TPMI_YES_NO fullTest;
} SelfTest_In;
WOLFTPM_API TPM_RC TPM2_SelfTest(SelfTest_In* in);

typedef struct {
    TPML_ALG toTest;
} IncrementalSelfTest_In;
typedef struct {
    TPML_ALG toDoList;
} IncrementalSelfTest_Out;
WOLFTPM_API TPM_RC TPM2_IncrementalSelfTest(IncrementalSelfTest_In* in,
    IncrementalSelfTest_Out* out);

typedef struct {
    TPM2B_MAX_BUFFER outData;
    UINT16 testResult; /* TPM_RC */
} GetTestResult_Out;
WOLFTPM_API TPM_RC TPM2_GetTestResult(GetTestResult_Out* out);


typedef struct {
    UINT16 bytesRequested;
} GetRandom_In;
typedef struct {
    TPM2B_DIGEST randomBytes; /* hardware max is 32-bytes */
} GetRandom_Out;
WOLFTPM_API TPM_RC TPM2_GetRandom(GetRandom_In* in, GetRandom_Out* out);

typedef struct {
    TPM2B_SENSITIVE_DATA inData;
} StirRandom_In;
WOLFTPM_API TPM_RC TPM2_StirRandom(StirRandom_In* in);

typedef struct {
    TPML_PCR_SELECTION pcrSelectionIn;
} PCR_Read_In;
typedef struct {
    UINT32 pcrUpdateCounter;
    TPML_PCR_SELECTION pcrSelectionOut;
    TPML_DIGEST pcrValues;
} PCR_Read_Out;
WOLFTPM_API TPM_RC TPM2_PCR_Read(PCR_Read_In* in, PCR_Read_Out* out);


typedef struct {
    TPMI_DH_PCR pcrHandle;
    TPML_DIGEST_VALUES digests;
} PCR_Extend_In;
WOLFTPM_API TPM_RC TPM2_PCR_Extend(PCR_Extend_In* in);


typedef struct {
    TPMI_DH_OBJECT parentHandle;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
} Create_In;
typedef struct {
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
} Create_Out;
WOLFTPM_API TPM_RC TPM2_Create(Create_In* in, Create_Out* out);

typedef struct {
    TPMI_DH_OBJECT parentHandle;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
} CreateLoaded_In;
typedef struct {
    TPM_HANDLE objectHandle;
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_NAME name;
} CreateLoaded_Out;
WOLFTPM_API TPM_RC TPM2_CreateLoaded(CreateLoaded_In* in,
    CreateLoaded_Out* out);


typedef struct {
    TPMI_RH_HIERARCHY primaryHandle;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
} CreatePrimary_In;
typedef struct {
    TPM_HANDLE objectHandle;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME name;
} CreatePrimary_Out;
WOLFTPM_API TPM_RC TPM2_CreatePrimary(CreatePrimary_In* in,
    CreatePrimary_Out* out);

typedef struct {
    TPMI_DH_OBJECT parentHandle;
    TPM2B_PRIVATE inPrivate;
    TPM2B_PUBLIC inPublic;
} Load_In;
typedef struct {
    TPM_HANDLE objectHandle;
    TPM2B_NAME name;
} Load_Out;
WOLFTPM_API TPM_RC TPM2_Load(Load_In* in, Load_Out* out);


typedef struct {
    TPMI_DH_CONTEXT flushHandle;
} FlushContext_In;
WOLFTPM_API TPM_RC TPM2_FlushContext(FlushContext_In* in);


typedef struct {
    TPMI_DH_OBJECT itemHandle;
} Unseal_In;
typedef struct {
    TPM2B_SENSITIVE_DATA outData;
} Unseal_Out;
WOLFTPM_API TPM_RC TPM2_Unseal(Unseal_In* in, Unseal_Out* out);


typedef struct {
    TPMI_DH_OBJECT tpmKey;
    TPMI_DH_ENTITY bind;
    TPM2B_NONCE nonceCaller;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    TPM_SE sessionType;
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH authHash;
} StartAuthSession_In;
typedef struct {
    TPMI_SH_AUTH_SESSION sessionHandle;
    TPM2B_NONCE nonceTPM;
} StartAuthSession_Out;
WOLFTPM_API TPM_RC TPM2_StartAuthSession(StartAuthSession_In* in,
    StartAuthSession_Out* out);

typedef struct {
    TPMI_SH_POLICY sessionHandle;
} PolicyRestart_In;
WOLFTPM_API TPM_RC TPM2_PolicyRestart(PolicyRestart_In* in);


typedef struct {
    TPM2B_SENSITIVE inPrivate;
    TPM2B_PUBLIC inPublic;
    TPMI_RH_HIERARCHY hierarchy;
} LoadExternal_In;
typedef struct {
    TPM_HANDLE objectHandle;
    TPM2B_NAME name;
} LoadExternal_Out;
WOLFTPM_API TPM_RC TPM2_LoadExternal(LoadExternal_In* in,
    LoadExternal_Out* out);

typedef struct {
    TPMI_DH_OBJECT objectHandle;
} ReadPublic_In;
typedef struct {
    TPM2B_PUBLIC outPublic;
    TPM2B_NAME name;
    TPM2B_NAME qualifiedName;
} ReadPublic_Out;
WOLFTPM_API TPM_RC TPM2_ReadPublic(ReadPublic_In* in, ReadPublic_Out* out);

typedef struct {
    TPMI_DH_OBJECT activateHandle;
    TPMI_DH_OBJECT keyHandle;
    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;
} ActivateCredential_In;
typedef struct {
    TPM2B_DIGEST certInfo;
} ActivateCredential_Out;
WOLFTPM_API TPM_RC TPM2_ActivateCredential(ActivateCredential_In* in,
    ActivateCredential_Out* out);

typedef struct {
    TPMI_DH_OBJECT handle;
    TPM2B_DIGEST credential;
    TPM2B_NAME objectName;
} MakeCredential_In;
typedef struct {
    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;
} MakeCredential_Out;
WOLFTPM_API TPM_RC TPM2_MakeCredential(MakeCredential_In* in,
    MakeCredential_Out* out);

typedef struct {
    TPMI_DH_OBJECT objectHandle;
    TPMI_DH_OBJECT parentHandle;
    TPM2B_AUTH newAuth;
} ObjectChangeAuth_In;
typedef struct {
    TPM2B_PRIVATE outPrivate;
} ObjectChangeAuth_Out;
WOLFTPM_API TPM_RC TPM2_ObjectChangeAuth(ObjectChangeAuth_In* in,
    ObjectChangeAuth_Out* out);


typedef struct {
    TPMI_DH_OBJECT objectHandle;
    TPMI_DH_OBJECT newParentHandle;
    TPM2B_DATA encryptionKeyIn;
    TPMT_SYM_DEF_OBJECT symmetricAlg;
} Duplicate_In;
typedef struct {
    TPM2B_DATA encryptionKeyOut;
    TPM2B_PRIVATE duplicate;
    TPM2B_ENCRYPTED_SECRET outSymSeed;
} Duplicate_Out;
WOLFTPM_API TPM_RC TPM2_Duplicate(Duplicate_In* in, Duplicate_Out* out);

typedef struct {
    TPMI_DH_OBJECT oldParent;
    TPMI_DH_OBJECT newParent;
    TPM2B_PRIVATE inDuplicate;
    TPM2B_NAME name;
    TPM2B_ENCRYPTED_SECRET inSymSeed;
} Rewrap_In;
typedef struct {
    TPM2B_PRIVATE outDuplicate;
    TPM2B_ENCRYPTED_SECRET outSymSeed;
} Rewrap_Out;
WOLFTPM_API TPM_RC TPM2_Rewrap(Rewrap_In* in, Rewrap_Out* out);

typedef struct {
    TPMI_DH_OBJECT parentHandle;
    TPM2B_DATA encryptionKey;
    TPM2B_PUBLIC objectPublic;
    TPM2B_PRIVATE duplicate;
    TPM2B_ENCRYPTED_SECRET inSymSeed;
    TPMT_SYM_DEF_OBJECT symmetricAlg;
} Import_In;
typedef struct {
    TPM2B_PRIVATE outPrivate;
} Import_Out;
WOLFTPM_API TPM_RC TPM2_Import(Import_In* in, Import_Out* out);

typedef struct {
    TPMI_DH_OBJECT keyHandle;
    TPM2B_PUBLIC_KEY_RSA message;
    TPMT_RSA_DECRYPT inScheme;
    TPM2B_DATA label;
} RSA_Encrypt_In;
typedef struct {
    TPM2B_PUBLIC_KEY_RSA outData;
} RSA_Encrypt_Out;
WOLFTPM_API TPM_RC TPM2_RSA_Encrypt(RSA_Encrypt_In* in, RSA_Encrypt_Out* out);


typedef struct {
    TPMI_DH_OBJECT keyHandle;
    TPM2B_PUBLIC_KEY_RSA cipherText;
    TPMT_RSA_DECRYPT inScheme;
    TPM2B_DATA label;
} RSA_Decrypt_In;
typedef struct {
    TPM2B_PUBLIC_KEY_RSA message;
} RSA_Decrypt_Out;
WOLFTPM_API TPM_RC TPM2_RSA_Decrypt(RSA_Decrypt_In* in, RSA_Decrypt_Out* out);


typedef struct {
    TPMI_DH_OBJECT keyHandle;
} ECDH_KeyGen_In;
typedef struct {
    TPM2B_ECC_POINT zPoint;
    TPM2B_ECC_POINT pubPoint;
} ECDH_KeyGen_Out;
WOLFTPM_API TPM_RC TPM2_ECDH_KeyGen(ECDH_KeyGen_In* in, ECDH_KeyGen_Out* out);


typedef struct {
    TPMI_DH_OBJECT keyHandle;
    TPM2B_ECC_POINT inPoint;
} ECDH_ZGen_In;
typedef struct {
    TPM2B_ECC_POINT outPoint;
} ECDH_ZGen_Out;
WOLFTPM_API TPM_RC TPM2_ECDH_ZGen(ECDH_ZGen_In* in, ECDH_ZGen_Out* out);

typedef struct {
    TPMI_ECC_CURVE curveID;
} ECC_Parameters_In;
typedef struct {
    TPMS_ALGORITHM_DETAIL_ECC parameters;
} ECC_Parameters_Out;
WOLFTPM_API TPM_RC TPM2_ECC_Parameters(ECC_Parameters_In* in,
    ECC_Parameters_Out* out);

typedef struct {
    TPMI_DH_OBJECT keyA;
    TPM2B_ECC_POINT inQsB;
    TPM2B_ECC_POINT inQeB;
    TPMI_ECC_KEY_EXCHANGE inScheme;
    UINT16 counter;
} ZGen_2Phase_In;
typedef struct {
    TPM2B_ECC_POINT outZ1;
    TPM2B_ECC_POINT outZ2;
} ZGen_2Phase_Out;
WOLFTPM_API TPM_RC TPM2_ZGen_2Phase(ZGen_2Phase_In* in, ZGen_2Phase_Out* out);


typedef struct {
    TPMI_DH_OBJECT keyHandle;
    TPMI_YES_NO decrypt;
    TPMI_ALG_SYM_MODE mode;
    TPM2B_IV ivIn;
    TPM2B_MAX_BUFFER inData;
} EncryptDecrypt_In;
typedef struct {
    TPM2B_MAX_BUFFER outData;
    TPM2B_IV ivOut;
} EncryptDecrypt_Out;
WOLFTPM_API TPM_RC TPM2_EncryptDecrypt(EncryptDecrypt_In* in,
    EncryptDecrypt_Out* out);

typedef struct {
    TPMI_DH_OBJECT keyHandle;
    TPM2B_MAX_BUFFER inData;
    TPMI_YES_NO decrypt;
    TPMI_ALG_SYM_MODE mode;
    TPM2B_IV ivIn;
} EncryptDecrypt2_In;
typedef struct {
    TPM2B_MAX_BUFFER outData;
    TPM2B_IV ivOut;
} EncryptDecrypt2_Out;
WOLFTPM_API TPM_RC TPM2_EncryptDecrypt2(EncryptDecrypt2_In* in,
    EncryptDecrypt2_Out* out);


typedef struct {
    TPM2B_MAX_BUFFER data;
    TPMI_ALG_HASH hashAlg;
    TPMI_RH_HIERARCHY hierarchy;
} Hash_In;
typedef struct {
    TPM2B_DIGEST outHash;
    TPMT_TK_HASHCHECK validation;
} Hash_Out;
WOLFTPM_API TPM_RC TPM2_Hash(Hash_In* in, Hash_Out* out);

typedef struct {
    TPMI_DH_OBJECT handle;
    TPM2B_MAX_BUFFER buffer;
    TPMI_ALG_HASH hashAlg;
} HMAC_In;
typedef struct {
    TPM2B_DIGEST outHMAC;
} HMAC_Out;
WOLFTPM_API TPM_RC TPM2_HMAC(HMAC_In* in, HMAC_Out* out);


typedef struct {
    TPMI_DH_OBJECT handle;
    TPM2B_AUTH auth;
    TPMI_ALG_HASH hashAlg;
} HMAC_Start_In;
typedef struct {
    TPMI_DH_OBJECT sequenceHandle;
} HMAC_Start_Out;
WOLFTPM_API TPM_RC TPM2_HMAC_Start(HMAC_Start_In* in, HMAC_Start_Out* out);


typedef struct {
    TPM2B_AUTH auth;
    TPMI_ALG_HASH hashAlg;
} HashSequenceStart_In;
typedef struct {
    TPMI_DH_OBJECT sequenceHandle;
} HashSequenceStart_Out;
WOLFTPM_API TPM_RC TPM2_HashSequenceStart(HashSequenceStart_In* in,
    HashSequenceStart_Out* out);

typedef struct {
    TPMI_DH_OBJECT sequenceHandle;
    TPM2B_MAX_BUFFER buffer;
} SequenceUpdate_In;
WOLFTPM_API TPM_RC TPM2_SequenceUpdate(SequenceUpdate_In* in);

typedef struct {
    TPMI_DH_OBJECT sequenceHandle;
    TPM2B_MAX_BUFFER buffer;
    TPMI_RH_HIERARCHY hierarchy;
} SequenceComplete_In;
typedef struct {
    TPM2B_DIGEST result;
    TPMT_TK_HASHCHECK validation;
} SequenceComplete_Out;
WOLFTPM_API TPM_RC TPM2_SequenceComplete(SequenceComplete_In* in,
    SequenceComplete_Out* out);


typedef struct {
    TPMI_DH_PCR pcrHandle;
    TPMI_DH_OBJECT sequenceHandle;
    TPM2B_MAX_BUFFER buffer;
} EventSequenceComplete_In;
typedef struct {
    TPML_DIGEST_VALUES results;
} EventSequenceComplete_Out;
WOLFTPM_API TPM_RC TPM2_EventSequenceComplete(EventSequenceComplete_In* in,
    EventSequenceComplete_Out* out);


typedef struct {
    TPMI_DH_OBJECT objectHandle;
    TPMI_DH_OBJECT signHandle;
    TPM2B_DATA qualifyingData;
    TPMT_SIG_SCHEME inScheme;
} Certify_In;
typedef struct {
    TPM2B_ATTEST certifyInfo;
    TPMT_SIGNATURE signature;
} Certify_Out;
WOLFTPM_API TPM_RC TPM2_Certify(Certify_In* in, Certify_Out* out);


typedef struct {
    TPMI_DH_OBJECT signHandle;
    TPMI_DH_OBJECT objectHandle;
    TPM2B_DATA qualifyingData;
    TPM2B_DIGEST creationHash;
    TPMT_SIG_SCHEME inScheme;
    TPMT_TK_CREATION creationTicket;
} CertifyCreation_In;
typedef struct {
    TPM2B_ATTEST certifyInfo;
    TPMT_SIGNATURE signature;
} CertifyCreation_Out;
WOLFTPM_API TPM_RC TPM2_CertifyCreation(CertifyCreation_In* in, CertifyCreation_Out* out);


typedef struct {
    TPMI_DH_OBJECT signHandle;
    TPM2B_DATA qualifyingData;
    TPMT_SIG_SCHEME inScheme;
    TPML_PCR_SELECTION PCRselect;
} Quote_In;
typedef struct {
    TPM2B_ATTEST quoted;
    TPMT_SIGNATURE signature;
} Quote_Out;
WOLFTPM_API TPM_RC TPM2_Quote(Quote_In* in, Quote_Out* out);

typedef struct {
    TPMI_RH_ENDORSEMENT privacyAdminHandle;
    TPMI_DH_OBJECT signHandle;
    TPMI_SH_HMAC sessionHandle;
    TPM2B_DATA qualifyingData;
    TPMT_SIG_SCHEME inScheme;
} GetSessionAuditDigest_In;
typedef struct {
    TPM2B_ATTEST auditInfo;
    TPMT_SIGNATURE signature;
} GetSessionAuditDigest_Out;
WOLFTPM_API TPM_RC TPM2_GetSessionAuditDigest(GetSessionAuditDigest_In* in,
    GetSessionAuditDigest_Out* out);

typedef struct {
    TPMI_RH_ENDORSEMENT privacyHandle;
    TPMI_DH_OBJECT signHandle;
    TPM2B_DATA qualifyingData;
    TPMT_SIG_SCHEME inScheme;
} GetCommandAuditDigest_In;
typedef struct {
    TPM2B_ATTEST auditInfo;
    TPMT_SIGNATURE signature;
} GetCommandAuditDigest_Out;
WOLFTPM_API TPM_RC TPM2_GetCommandAuditDigest(GetCommandAuditDigest_In* in,
    GetCommandAuditDigest_Out* out);

typedef struct {
    TPMI_RH_ENDORSEMENT privacyAdminHandle;
    TPMI_DH_OBJECT signHandle;
    TPM2B_DATA qualifyingData;
    TPMT_SIG_SCHEME inScheme;
} GetTime_In;
typedef struct {
    TPM2B_ATTEST timeInfo;
    TPMT_SIGNATURE signature;
} GetTime_Out;
WOLFTPM_API TPM_RC TPM2_GetTime(GetTime_In* in, GetTime_Out* out);

typedef struct {
    TPMI_DH_OBJECT signHandle;
    TPM2B_ECC_POINT P1;
    TPM2B_SENSITIVE_DATA s2;
    TPM2B_ECC_PARAMETER y2;
} Commit_In;
typedef struct {
    TPM2B_ECC_POINT K;
    TPM2B_ECC_POINT L;
    TPM2B_ECC_POINT E;
    UINT16 counter;
} Commit_Out;
WOLFTPM_API TPM_RC TPM2_Commit(Commit_In* in, Commit_Out* out);


typedef struct {
    TPMI_ECC_CURVE curveID;
} EC_Ephemeral_In;
typedef struct {
    TPM2B_ECC_POINT Q;
    UINT16 counter;
} EC_Ephemeral_Out;
WOLFTPM_API TPM_RC TPM2_EC_Ephemeral(EC_Ephemeral_In* in,
    EC_Ephemeral_Out* out);

typedef struct {
    TPMI_DH_OBJECT keyHandle;
    TPM2B_DIGEST digest;
    TPMT_SIGNATURE signature;
} VerifySignature_In;
typedef struct {
    TPMT_TK_VERIFIED validation;
} VerifySignature_Out;
WOLFTPM_API TPM_RC TPM2_VerifySignature(VerifySignature_In* in,
    VerifySignature_Out* out);


typedef struct {
    TPMI_DH_OBJECT keyHandle;
    TPM2B_DIGEST digest;
    TPMT_SIG_SCHEME inScheme;
    TPMT_TK_HASHCHECK validation;
} Sign_In;
typedef struct {
    TPMT_SIGNATURE signature;
} Sign_Out;
WOLFTPM_API TPM_RC TPM2_Sign(Sign_In* in, Sign_Out* out);


typedef struct {
    TPMI_RH_PROVISION auth;
    TPMI_ALG_HASH auditAlg;
    TPML_CC setList;
    TPML_CC clearList;
} SetCommandCodeAuditStatus_In;
WOLFTPM_API TPM_RC TPM2_SetCommandCodeAuditStatus(
    SetCommandCodeAuditStatus_In* in);


typedef struct {
    TPMI_DH_PCR pcrHandle;
    TPM2B_EVENT eventData;
} PCR_Event_In;
typedef struct {
    TPML_DIGEST_VALUES digests;
} PCR_Event_Out;
WOLFTPM_API TPM_RC TPM2_PCR_Event(PCR_Event_In* in, PCR_Event_Out* out);


typedef struct {
    TPMI_RH_PLATFORM authHandle;
    TPML_PCR_SELECTION pcrAllocation;
} PCR_Allocate_In;
typedef struct {
    TPMI_YES_NO allocationSuccess;
    UINT32 maxPCR;
    UINT32 sizeNeeded;
    UINT32 sizeAvailable;
} PCR_Allocate_Out;
WOLFTPM_API TPM_RC TPM2_PCR_Allocate(PCR_Allocate_In* in,
    PCR_Allocate_Out* out);

typedef struct {
    TPMI_RH_PLATFORM authHandle;
    TPM2B_DIGEST authPolicy;
    TPMI_ALG_HASH hashAlg;
    TPMI_DH_PCR pcrNum;
} PCR_SetAuthPolicy_In;
WOLFTPM_API TPM_RC TPM2_PCR_SetAuthPolicy(PCR_SetAuthPolicy_In* in);

typedef struct {
    TPMI_DH_PCR pcrHandle;
    TPM2B_DIGEST auth;
} PCR_SetAuthValue_In;
WOLFTPM_API TPM_RC TPM2_PCR_SetAuthValue(PCR_SetAuthValue_In* in);

typedef struct {
    TPMI_DH_PCR pcrHandle;
} PCR_Reset_In;
WOLFTPM_API TPM_RC TPM2_PCR_Reset(PCR_Reset_In* in);


typedef struct {
    TPMI_DH_OBJECT authObject;
    TPMI_SH_POLICY policySession;
    TPM2B_NONCE nonceTPM;
    TPM2B_DIGEST cpHashA;
    TPM2B_NONCE policyRef;
    INT32 expiration;
    TPMT_SIGNATURE auth;
} PolicySigned_In;
typedef struct {
    TPM2B_TIMEOUT timeout;
    TPMT_TK_AUTH policyTicket;
} PolicySigned_Out;
WOLFTPM_API TPM_RC TPM2_PolicySigned(PolicySigned_In* in,
    PolicySigned_Out* out);

typedef struct {
    TPMI_DH_ENTITY authHandle;
    TPMI_SH_POLICY policySession;
    TPM2B_NONCE nonceTPM;
    TPM2B_DIGEST cpHashA;
    TPM2B_NONCE policyRef;
    INT32 expiration;
} PolicySecret_In;
typedef struct {
    TPM2B_TIMEOUT timeout;
    TPMT_TK_AUTH policyTicket;
} PolicySecret_Out;
WOLFTPM_API TPM_RC TPM2_PolicySecret(PolicySecret_In* in,
    PolicySecret_Out* out);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPM2B_TIMEOUT timeout;
    TPM2B_DIGEST cpHashA;
    TPM2B_NONCE policyRef;
    TPM2B_NAME authName;
    TPMT_TK_AUTH ticket;
} PolicyTicket_In;
WOLFTPM_API TPM_RC TPM2_PolicyTicket(PolicyTicket_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPML_DIGEST pHashList;
} PolicyOR_In;
WOLFTPM_API TPM_RC TPM2_PolicyOR(PolicyOR_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPM2B_DIGEST pcrDigest;
    TPML_PCR_SELECTION pcrs;
} PolicyPCR_In;
WOLFTPM_API TPM_RC TPM2_PolicyPCR(PolicyPCR_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPMA_LOCALITY locality;
} PolicyLocality_In;
WOLFTPM_API TPM_RC TPM2_PolicyLocality(PolicyLocality_In* in);

typedef struct {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    TPMI_SH_POLICY policySession;
    TPM2B_OPERAND operandB;
    UINT16 offset;
    TPM_EO operation;
} PolicyNV_In;
WOLFTPM_API TPM_RC TPM2_PolicyNV(PolicyNV_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPM2B_OPERAND operandB;
    UINT16 offset;
    TPM_EO operation;
} PolicyCounterTimer_In;
WOLFTPM_API TPM_RC TPM2_PolicyCounterTimer(PolicyCounterTimer_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPM_CC code;
} PolicyCommandCode_In;
WOLFTPM_API TPM_RC TPM2_PolicyCommandCode(PolicyCommandCode_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
} PolicyPhysicalPresence_In;
WOLFTPM_API TPM_RC TPM2_PolicyPhysicalPresence(PolicyPhysicalPresence_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPM2B_DIGEST cpHashA;
} PolicyCpHash_In;
WOLFTPM_API TPM_RC TPM2_PolicyCpHash(PolicyCpHash_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPM2B_DIGEST nameHash;
} PolicyNameHash_In;
WOLFTPM_API TPM_RC TPM2_PolicyNameHash(PolicyNameHash_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPM2B_NAME objectName;
    TPM2B_NAME newParentName;
    TPMI_YES_NO includeObject;
} PolicyDuplicationSelect_In;
WOLFTPM_API TPM_RC TPM2_PolicyDuplicationSelect(PolicyDuplicationSelect_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPM2B_DIGEST approvedPolicy;
    TPM2B_NONCE policyRef;
    TPM2B_NAME keySign;
    TPMT_TK_VERIFIED checkTicket;
} PolicyAuthorize_In;
WOLFTPM_API TPM_RC TPM2_PolicyAuthorize(PolicyAuthorize_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
} PolicyAuthValue_In;
WOLFTPM_API TPM_RC TPM2_PolicyAuthValue(PolicyAuthValue_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
} PolicyPassword_In;
WOLFTPM_API TPM_RC TPM2_PolicyPassword(PolicyPassword_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
} PolicyGetDigest_In;
typedef struct {
    TPM2B_DIGEST policyDigest;
} PolicyGetDigest_Out;
WOLFTPM_API TPM_RC TPM2_PolicyGetDigest(PolicyGetDigest_In* in, PolicyGetDigest_Out* out);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPMI_YES_NO writtenSet;
} PolicyNvWritten_In;
WOLFTPM_API TPM_RC TPM2_PolicyNvWritten(PolicyNvWritten_In* in);

typedef struct {
    TPMI_SH_POLICY policySession;
    TPM2B_DIGEST templateHash;
} PolicyTemplate_In;
WOLFTPM_API TPM_RC TPM2_PolicyTemplate(PolicyTemplate_In* in);

typedef struct {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    TPMI_SH_POLICY policySession;
} PolicyAuthorizeNV_In;
WOLFTPM_API TPM_RC TPM2_PolicyAuthorizeNV(PolicyAuthorizeNV_In* in);



WOLFTPM_API void _TPM_Hash_Start(void);
WOLFTPM_API void _TPM_Hash_Data(UINT32 dataSize, BYTE *data);
WOLFTPM_API void _TPM_Hash_End(void);


typedef struct {
    TPMI_RH_HIERARCHY authHandle;
    TPMI_RH_ENABLES enable;
    TPMI_YES_NO state;
} HierarchyControl_In;
WOLFTPM_API TPM_RC TPM2_HierarchyControl(HierarchyControl_In* in);

typedef struct {
    TPMI_RH_HIERARCHY_AUTH authHandle;
    TPM2B_DIGEST authPolicy;
    TPMI_ALG_HASH hashAlg;
} SetPrimaryPolicy_In;
WOLFTPM_API TPM_RC TPM2_SetPrimaryPolicy(SetPrimaryPolicy_In* in);

typedef struct {
    TPMI_RH_PLATFORM authHandle;
} ChangeSeed_In;

typedef ChangeSeed_In ChangePPS_In;
WOLFTPM_API TPM_RC TPM2_ChangePPS(ChangePPS_In* in);

typedef ChangeSeed_In ChangeEPS_In;
WOLFTPM_API TPM_RC TPM2_ChangeEPS(ChangeEPS_In* in);


typedef struct {
    TPMI_RH_CLEAR authHandle;
} Clear_In;
WOLFTPM_API TPM_RC TPM2_Clear(Clear_In* in);

typedef struct {
    TPMI_RH_CLEAR auth;
    TPMI_YES_NO disable;
} ClearControl_In;
WOLFTPM_API TPM_RC TPM2_ClearControl(ClearControl_In* in);

typedef struct {
    TPMI_RH_HIERARCHY_AUTH authHandle;
    TPM2B_AUTH newAuth;
} HierarchyChangeAuth_In;
WOLFTPM_API TPM_RC TPM2_HierarchyChangeAuth(HierarchyChangeAuth_In* in);

typedef struct {
    TPMI_RH_LOCKOUT lockHandle;
} DictionaryAttackLockReset_In;
WOLFTPM_API TPM_RC TPM2_DictionaryAttackLockReset(DictionaryAttackLockReset_In* in);

typedef struct {
    TPMI_RH_LOCKOUT lockHandle;
    UINT32 newMaxTries;
    UINT32 newRecoveryTime;
    UINT32 lockoutRecovery;
} DictionaryAttackParameters_In;
WOLFTPM_API TPM_RC TPM2_DictionaryAttackParameters(DictionaryAttackParameters_In* in);


typedef struct {
    TPMI_RH_PLATFORM auth;
    TPML_CC setList;
    TPML_CC clearList;
} PP_Commands_In;
WOLFTPM_API TPM_RC TPM2_PP_Commands(PP_Commands_In* in);

typedef struct {
    TPMI_RH_PLATFORM authHandle;
    UINT32 algorithmSet;
} SetAlgorithmSet_In;
WOLFTPM_API TPM_RC TPM2_SetAlgorithmSet(SetAlgorithmSet_In* in);

typedef struct {
    TPMI_RH_PLATFORM authorization;
    TPMI_DH_OBJECT keyHandle;
    TPM2B_DIGEST fuDigest;
    TPMT_SIGNATURE manifestSignature;
} FieldUpgradeStart_In;
WOLFTPM_API TPM_RC TPM2_FieldUpgradeStart(FieldUpgradeStart_In* in);

typedef struct {
    TPM2B_MAX_BUFFER fuData;
} FieldUpgradeData_In;
typedef struct {
    TPMT_HA nextDigest;
    TPMT_HA firstDigest;
} FieldUpgradeData_Out;
WOLFTPM_API TPM_RC TPM2_FieldUpgradeData(FieldUpgradeData_In* in,
    FieldUpgradeData_Out* out);

typedef struct {
    UINT32 sequenceNumber;
} FirmwareRead_In;
typedef struct {
    TPM2B_MAX_BUFFER fuData;
} FirmwareRead_Out;
WOLFTPM_API TPM_RC TPM2_FirmwareRead(FirmwareRead_In* in, FirmwareRead_Out* out);


typedef struct {
    TPMI_DH_CONTEXT saveHandle;
} ContextSave_In;
typedef struct {
    TPMS_CONTEXT context;
} ContextSave_Out;
WOLFTPM_API TPM_RC TPM2_ContextSave(ContextSave_In* in, ContextSave_Out* out);

typedef struct {
    TPMS_CONTEXT context;
} ContextLoad_In;
typedef struct {
    TPMI_DH_CONTEXT loadedHandle;
} ContextLoad_Out;
WOLFTPM_API TPM_RC TPM2_ContextLoad(ContextLoad_In* in, ContextLoad_Out* out);


typedef struct {
    TPMI_RH_PROVISION auth;
    TPMI_DH_OBJECT objectHandle;
    TPMI_DH_PERSISTENT persistentHandle;
} EvictControl_In;
WOLFTPM_API TPM_RC TPM2_EvictControl(EvictControl_In* in);


typedef struct {
    TPMS_TIME_INFO currentTime;
} ReadClock_Out;
WOLFTPM_API TPM_RC TPM2_ReadClock(ReadClock_Out* out);

typedef struct {
    TPMI_RH_PROVISION auth;
    UINT64 newTime;
} ClockSet_In;
WOLFTPM_API TPM_RC TPM2_ClockSet(ClockSet_In* in);

typedef struct {
    TPMI_RH_PROVISION auth;
    TPM_CLOCK_ADJUST rateAdjust;
} ClockRateAdjust_In;
WOLFTPM_API TPM_RC TPM2_ClockRateAdjust(ClockRateAdjust_In* in);


typedef struct {
    TPMT_PUBLIC_PARMS parameters;
} TestParms_In;
WOLFTPM_API TPM_RC TPM2_TestParms(TestParms_In* in);


typedef struct {
    TPMI_RH_PROVISION authHandle;
    TPM2B_AUTH auth;
    TPM2B_NV_PUBLIC publicInfo;
} NV_DefineSpace_In;
WOLFTPM_API TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In* in);

typedef struct {
    TPMI_RH_PROVISION authHandle;
    TPMI_RH_NV_INDEX nvIndex;
} NV_UndefineSpace_In;
WOLFTPM_API TPM_RC TPM2_NV_UndefineSpace(NV_UndefineSpace_In* in);

typedef struct {
    TPMI_RH_NV_INDEX nvIndex;
    TPMI_RH_PLATFORM platform;
} NV_UndefineSpaceSpecial_In;
WOLFTPM_API TPM_RC TPM2_NV_UndefineSpaceSpecial(NV_UndefineSpaceSpecial_In* in);

typedef struct {
    TPMI_RH_NV_INDEX nvIndex;
} NV_ReadPublic_In;
typedef struct {
    TPM2B_NV_PUBLIC nvPublic;
    TPM2B_NAME nvName;
} NV_ReadPublic_Out;
WOLFTPM_API TPM_RC TPM2_NV_ReadPublic(NV_ReadPublic_In* in, NV_ReadPublic_Out* out);

typedef struct {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    TPM2B_MAX_NV_BUFFER data;
    UINT16 offset;
} NV_Write_In;
WOLFTPM_API TPM_RC TPM2_NV_Write(NV_Write_In* in);

typedef struct {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
} NV_Increment_In;
WOLFTPM_API TPM_RC TPM2_NV_Increment(NV_Increment_In* in);

typedef struct {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    TPM2B_MAX_NV_BUFFER data;
} NV_Extend_In;
WOLFTPM_API TPM_RC TPM2_NV_Extend(NV_Extend_In* in);

typedef struct {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    UINT64 bits;
} NV_SetBits_In;
WOLFTPM_API TPM_RC TPM2_NV_SetBits(NV_SetBits_In* in);

typedef struct {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
} NV_WriteLock_In;
WOLFTPM_API TPM_RC TPM2_NV_WriteLock(NV_WriteLock_In* in);

typedef struct {
    TPMI_RH_PROVISION authHandle;
} NV_GlobalWriteLock_In;
WOLFTPM_API TPM_RC TPM2_NV_GlobalWriteLock(NV_GlobalWriteLock_In* in);

typedef struct {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    UINT16 size;
    UINT16 offset;
} NV_Read_In;
typedef struct {
    TPM2B_MAX_NV_BUFFER data;
} NV_Read_Out;
WOLFTPM_API TPM_RC TPM2_NV_Read(NV_Read_In* in, NV_Read_Out* out);

typedef struct {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
} NV_ReadLock_In;
WOLFTPM_API TPM_RC TPM2_NV_ReadLock(NV_ReadLock_In* in);

typedef struct {
    TPMI_RH_NV_INDEX nvIndex;
    TPM2B_AUTH newAuth;
} NV_ChangeAuth_In;
WOLFTPM_API TPM_RC TPM2_NV_ChangeAuth(NV_ChangeAuth_In* in);

typedef struct {
    TPMI_DH_OBJECT signHandle;
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    TPM2B_DATA qualifyingData;
    TPMT_SIG_SCHEME inScheme;
    UINT16 size;
    UINT16 offset;
} NV_Certify_In;
typedef struct {
    TPM2B_ATTEST certifyInfo;
    TPMT_SIGNATURE signature;
} NV_Certify_Out;
WOLFTPM_API TPM_RC TPM2_NV_Certify(NV_Certify_In* in, NV_Certify_Out* out);


/* Vendor Specific API's */
#if defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)
    /* Enable command code vendor API */
    typedef struct {
        TPMI_RH_HIERARCHY authHandle;
        TPM_CC commandCode;
        UINT32 enableFlag;
        UINT32 lockFlag;
    } SetCommandSet_In;
    WOLFTPM_API int TPM2_SetCommandSet(SetCommandSet_In* in);

    enum {
        TPMLib_2 = 0x01,
        TPMFips = 0x02,
        TPMLowPowerOff = 0x00,
        TPMLowPowerByRegister = 0x04,
        TPMLowPowerByGpio = 0x08,
        TPMLowPowerAuto = 0x0C,
    };
    typedef struct TPM_MODE_SET {
        BYTE CmdToLowPower;
        BYTE BootToLowPower;
        BYTE modeLock;
        BYTE mode;
    } TPM_MODE_SET;
    typedef struct {
        TPMI_RH_HIERARCHY authHandle;
        TPM_MODE_SET modeSet;
    } SetMode_In;
    WOLFTPM_API int TPM2_SetMode(SetMode_In* in);

    /* The TPM2_GetRandom2 command does not require any authorization */
    typedef GetRandom_In GetRandom2_In; /* same input */
    typedef struct {
        TPM2B_MAX_BUFFER randomBytes;
    } GetRandom2_Out;
    /* If bytesRequested is longer than TPM2B_MAX_BUFFER can accommodate, no
     * error is returned, but the TPM returns as much data as a TPM2B_DATA
     * buffer can contain. */
    WOLFTPM_API TPM_RC TPM2_GetRandom2(GetRandom2_In* in, GetRandom2_Out* out);

    WOLFTPM_API TPM_RC TPM2_GetProductInfo(uint8_t* info, uint16_t size);
#endif /* ST33 Vendor Specific */


#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673) || \
    defined(WOLFTPM_AUTODETECT)

#ifdef WOLFTPM_FIRMWARE_UPGRADE
WOLFTPM_API int TPM2_IFX_FieldUpgradeStart(TPM_HANDLE sessionHandle,
    uint8_t* data, uint32_t size);
WOLFTPM_API int TPM2_IFX_FieldUpgradeCommand(TPM_CC cc, uint8_t* data, uint32_t size);
#endif /* WOLFTPM_FIRMWARE_UPGRADE */

#endif /* Infineon SLB Vendor Specific */


/* Vendor Specific GPIO */
#ifdef WOLFTPM_ST33

    #ifdef WOLFTPM_I2C
        #define MAX_GPIO_COUNT 4
    #else /* SPI variant */
        #define MAX_GPIO_COUNT 2
    #endif

    /* ST33 variants can have different count of GPIO available:
     * - SPI variant - 0, 1 or 2
     * - I2C variant - 0, 1, 2, 3 or 4
     * The user can configure this option at build or use default value. */
    #ifndef TPM_GPIO_COUNT
        #define TPM_GPIO_COUNT MAX_GPIO_COUNT
    #endif

    #define TPM_GPIO_NUM_MIN (TPM_GPIO_A)
    #define TPM_GPIO_NUM_MAX (TPM_GPIO_A + TPM_GPIO_COUNT - 1)

    /* GPIO configuration uses specific range of NV space */
    #define TPM_NV_GPIO_SPACE     0x01C40000

    typedef enum {
        TPM_GPIO_PP = 0x00000000, /* GPIO A by default is a Physical Presence pin */
        TPM_GPIO_LP = 0x00000001, /* GPIO B can only be used as an input */
    #ifdef WOLFTPM_I2C
        /* Only the I2C variant of ST33 has GPIO C and D */
        TPM_GPIO_C  = 0x00000002,
        TPM_GPIO_D  = 0x00000003,
    #endif
    } TPMI_GPIO_NAME_T;
    typedef UINT32 TPMI_GPIO_NAME;

    /* For portability and readability in code */
    #define TPM_GPIO_A TPM_GPIO_PP
    #define TPM_GPIO_B TPM_GPIO_LP

    typedef enum {
        TPM_GPIO_MODE_STANDARD   = 0x00000000,
        TPM_GPIO_MODE_FLOATING   = 0x00000001,
        TPM_GPIO_MODE_PULLUP     = 0x00000002,
        TPM_GPIO_MODE_PULLDOWN   = 0x00000003,
        TPM_GPIO_MODE_OPENDRAIN  = 0x00000004,
        TPM_GPIO_MODE_PUSHPULL   = 0x00000005,
        TPM_GPIO_MODE_UNCONFIG   = 0x00000006,
        TPM_GPIO_MODE_DEFAULT    = TPM_GPIO_MODE_PULLDOWN,
        TPM_GPIO_MODE_MAX        = TPM_GPIO_MODE_UNCONFIG,
        TPM_GPIO_MODE_INPUT_MIN  = TPM_GPIO_MODE_FLOATING,
        TPM_GPIO_MODE_INPUT_MAX  = TPM_GPIO_MODE_PULLDOWN
    } TPMI_GPIO_MODE_T;
    typedef UINT32 TPMI_GPIO_MODE;

    typedef struct TPMS_GPIO_CONFIG {
        TPMI_GPIO_NAME name;
        TPMI_RH_NV_INDEX index;
        TPMI_GPIO_MODE mode;
    } TPMS_GPIO_CONFIG;

    typedef struct TPML_GPIO_CONFIG {
        UINT32 count;
        TPMS_GPIO_CONFIG gpio[MAX_GPIO_COUNT];
    } TPML_GPIO_CONFIG;

    typedef struct {
        TPMI_RH_PLATFORM authHandle;
        TPML_GPIO_CONFIG config;
    } GpioConfig_In;
    WOLFTPM_API int TPM2_GPIO_Config(GpioConfig_In* in);

#elif defined(WOLFTPM_NUVOTON)

    #define MAX_GPIO_COUNT 2

    /* NPCT7XX supports a maximum of 2 GPIO for user control */
    /* Added in FW-US version 7.2.3.0 or later */
    #ifndef TPM_GPIO_COUNT
    #define TPM_GPIO_COUNT MAX_GPIO_COUNT
    #endif

    /* For portability */
    #undef  TPM_GPIO_A
    #define TPM_GPIO_A 3 /* NPCT75xx GPIO start at number 3 */

    #define TPM_GPIO_NUM_MIN (TPM_GPIO_A)
    #define TPM_GPIO_NUM_MAX (TPM_GPIO_A + TPM_GPIO_COUNT - 1)

    /* GPIO configuration uses specific range of NV space */
    #define TPM_NV_GPIO_SPACE     0x01C40003

    /* Nuvoton GPIO Modes */
    typedef enum {
        TPM_GPIO_MODE_PUSHPULL   = 1,
        TPM_GPIO_MODE_OPENDRAIN  = 2,
        TPM_GPIO_MODE_PULLUP     = 3,
        TPM_GPIO_MODE_UNCONFIG   = 4,
        TPM_GPIO_MODE_DEFAULT    = TPM_GPIO_MODE_PUSHPULL,
        TPM_GPIO_MODE_MAX        = TPM_GPIO_MODE_UNCONFIG,
        TPM_GPIO_MODE_INPUT_MIN  = TPM_GPIO_MODE_PULLUP,
        TPM_GPIO_MODE_INPUT_MAX  = TPM_GPIO_MODE_PULLUP
    } TPMI_GPIO_MODE_T;
    typedef UINT32 TPMI_GPIO_MODE;

    typedef struct {
        BYTE Base0;
        BYTE Base1;
        BYTE GpioAltCfg;
        BYTE GpioInitValue;
        BYTE GpioPullUp;
        BYTE GpioPushPull;
        BYTE Cfg_A;
        BYTE Cfg_B;
        BYTE Cfg_C;
        BYTE Cfg_D;
        BYTE Cfg_E;
        BYTE Cfg_F;
        BYTE Cfg_G;
        BYTE Cfg_H;
        BYTE Cfg_I;
        BYTE Cfg_J;
        BYTE isValid;
        BYTE isLocked;
    } CFG_STRUCT;

    typedef struct {
        TPMI_RH_PLATFORM authHandle;
        CFG_STRUCT preConfig;
    } NTC2_PreConfig_In;
    WOLFTPM_API int TPM2_NTC2_PreConfig(NTC2_PreConfig_In* in);

    typedef struct {
        CFG_STRUCT preConfig;
    } NTC2_GetConfig_Out;
    WOLFTPM_API int TPM2_NTC2_GetConfig(NTC2_GetConfig_Out* out);
#endif /* Vendor GPIO Commands */


/* Non-standard API's */

/** @defgroup TPM2_Proprietary TPM2 Proprietary
 *
 * This module describes TPM2 commands specific only to wolfTPM.
 *
 * Typically, these commands include helpers for handling TPM 2.0 data structures.
 *
 * There are also functions to help debugging and testing during development.
 *
 */

#define _TPM_Init TPM2_Init
/*!
    \ingroup TPM2_Proprietary
    \brief Initializes a TPM with HAL IO callback and user supplied context.
    When using wolfTPM with --enable-devtpm or --enable-swtpm configuration, the ioCb and userCtx are not used.
    \note TPM2_Init_minimal() calls TPM2_Init_ex() with both ioCb and userCtx set to NULL.
    In other modes, the ioCb shall be set in order to use TIS.
    Example ioCB for baremetal and RTOS applications are provided in hal/tpm_io.c

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: general error (possibly IO)
    \return BAD_FUNC_ARG check arguments provided

    \param ctx pointer to a TPM2_CTX struct
    \param ioCb pointer to TPM2HalIoCb (HAL IO) callback function
    \param userCtx pointer to the user's context that will be stored as a member of the ctx struct

    _Example_
    \code
    int rc;
    TPM2_CTX tpm2Ctx;

    rc = TPM2_Init(&tpm2Ctx, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        // TPM2_Init failed
    }
    \endcode

    \sa TPM2_Startup
    \sa TPM2_GetRCString
    \sa TPM2_Init_minimal
    \sa TPM2_Init_ex
    \sa wolfTPM2_Init
*/
WOLFTPM_API TPM_RC TPM2_Init(TPM2_CTX* ctx, TPM2HalIoCb ioCb, void* userCtx);

/*!
    \ingroup TPM2_Proprietary
    \brief Initializes a TPM with timeoutTries, HAL IO callback and user supplied context.
    \note It is recommended to use TPM2_Init instead of using TPM2_Init_ex directly.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: general error (possibly IO)
    \return BAD_FUNC_ARG check arguments provided

    \param ctx pointer to a TPM2_CTX struct
    \param ioCb pointer to TPM2HalIoCb (HAL IO) callback function
    \param userCtx pointer to the user's context that will be stored as a member of the ctx struct
    \param timeoutTries specifies the number of attempts to confirm that TPM2 startup has completed

    \sa TPM2_GetRCString
    \sa TPM2_Init_minimal
    \sa TPM2_Init
    \sa wolfTPM2_Init_ex
*/
WOLFTPM_API TPM_RC TPM2_Init_ex(TPM2_CTX* ctx, TPM2HalIoCb ioCb, void* userCtx,
    int timeoutTries);

/*!
    \ingroup TPM2_Proprietary
    \brief Initializes a TPM and sets the wolfTPM2 context that will be used.
    This function is typically used for rich operating systems, like Windows.
    \note It is recommended to use TPM2_Init instead of using TPM2_Init_minimal directly.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: general error (possibly IO)
    \return BAD_FUNC_ARG check arguments provided

    \param ctx pointer to a TPM2_CTX struct

    \sa TPM2_GetRCString
    \sa TPM2_Init
*/
WOLFTPM_API TPM_RC TPM2_Init_minimal(TPM2_CTX* ctx);

/*!
    \ingroup TPM2_Proprietary
    \brief Deinitializes a TPM and wolfcrypt (if it was initialized)

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: could not acquire the lock on the wolfTPM2 context
    \return BAD_FUNC_ARG: the TPM2 device structure is a NULL pointer

    \param ctx pointer to a TPM2_CTX struct

    _Example_
    \code
    int rc;
    TPM2_CTX tpm2Ctx;

    rc = TPM2_Cleanup(&tpm2Ctx->dev);
    if (rc != TPM_RC_SUCCESS) {
        // TPM2_Cleanup failed
    }
    \endcode

    \sa TPM2_GetRCString
    \sa TPM2_Init
    \sa wolfTPM2_Cleanup
*/
WOLFTPM_API TPM_RC TPM2_Cleanup(TPM2_CTX* ctx);

/* Other API's - Not in TPM Specification */

/*!
    \ingroup TPM2_Proprietary
    \brief Makes sure the TPM2 startup has completed and extracts the TPM device information
    \note This function is used in TPM2_Init_ex

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: general error (possibly IO)
    \return BAD_FUNC_ARG: check the provided arguments
    \return TPM_RC_TIMEOUT: timeout occurred

    \param ctx pointer to a TPM2_CTX struct
    \param timeoutTries specifies the number of attempts to check if TPM2 startup has completed

    \sa TPM2_GetRCString
    \sa TPM2_TIS_StartupWait
    \sa TPM2_TIS_RequestLocality
    \sa TPM2_TIS_GetInfo
    \sa TPM2_Init_ex
*/
WOLFTPM_API TPM_RC TPM2_ChipStartup(TPM2_CTX* ctx, int timeoutTries);

/*!
    \ingroup TPM2_Proprietary
    \brief Sets the user's context and IO callbacks needed for TPM communication
    \brief Typically, TPM2_Init or wolfTPM2_Init are used to set the HAL IO.
    \note SetHalIoCb will fail if built with devtpm or swtpm as the callback
    is not used for TPM. For other configuration builds, ioCb must be
    set to a non-NULL function pointer and userCtx is optional.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: could not acquire the lock on the wolfTPM2 context
    \return BAD_FUNC_ARG: the TPM2 device structure is a NULL pointer

    \param ctx pointer to a TPM2_CTX struct
    \param ioCb pointer to TPM2HalIoCb (HAL IO) callback function
    \param userCtx pointer to the user's context that will be stored as a member of the ctx struct

    \sa TPM2_GetRCString
    \sa TPM2_Init
    \sa wolfTPM2_Init
*/
WOLFTPM_API TPM_RC TPM2_SetHalIoCb(TPM2_CTX* ctx, TPM2HalIoCb ioCb, void* userCtx);

/*!
    \ingroup TPM2_Proprietary
    \brief Sets the structure holding the TPM Authorizations.
    \brief Rarely used, because TPM2_Init functions and wolfTPM2_Init perform this initialization as well
    TPM 2.0 Commands can have up to three authorization slots,
    therefore it is recommended to supply an array of size
    MAX_SESSION_NUM to TPM2_SetSessionAuth(see example below).

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: could not acquire the lock on the wolfTPM2 context
    \return BAD_FUNC_ARG: the TPM2 context structure is a NULL pointer

    \param session pointer to an array of type TPM2_AUTH_SESSION

    _Example_
    \code
    int rc;
    TPM2_AUTH_SESSION session[MAX_SESSION_NUM];

    XMEMSET(session, 0, sizeof(session));
    session[0].sessionHandle = TPM_RS_PW;

    rc = TPM2_SetSessionAuth(session);
    if (rc != TPM_RC_SUCCESS) {
        // TPM2_SetSessionAuth failed
    }
    \endcode

    \sa TPM2_GetRCString
    \sa TPM2_Init
    \sa wolfTPM2_Init
*/
WOLFTPM_API TPM_RC TPM2_SetSessionAuth(TPM2_AUTH_SESSION *session);

/*!
    \ingroup TPM2_Proprietary
    \brief Determine the number of currently set TPM Authorizations

    \return the number of active TPM Authorizations (between one and three)
    \return BAD_FUNC_ARG: check the arguments provided for a NULL pointer

    \param ctx pointer to a TPM2_CTX struct

    _Example_
    \code
    int authCount;
    TPM2_CTX tpm2Ctx;

    authCount = TPM2_GetSessionAuthCount(tpm2ctx);
    if (authCount == BAD_FUNC_ARG) {
        // TPM2_GetSessionAuthCount failed
    }
    \endcode

    \sa TPM2_CTX
    \sa TPM2_AUTH_SESSION
*/
WOLFTPM_API int    TPM2_GetSessionAuthCount(TPM2_CTX* ctx);

/*!
    \ingroup TPM2_Proprietary
    \brief Sets a new TPM2 context for use

    \param ctx pointer to a TPM2_CTX struct

    _Example_
    \code
    TPM2_CTX tpm2Ctx;

    TPM2_SetActiveCtx(tpm2ctx);
    \endcode

    \sa TPM2_CTX
    \sa TPM2_AUTH_SESSION
*/
WOLFTPM_API void      TPM2_SetActiveCtx(TPM2_CTX* ctx);

/*!
    \ingroup TPM2_Proprietary
    \brief Provides a pointer to the TPM2 context in use

    \return ctx pointer to a TPM2_CTX struct

    _Example_
    \code
    TPM2_CTX *tpm2Ctx;

    tpm2Ctx = TPM2_GetActiveCtx();
    \endcode

    \sa TPM2_CTX
    \sa TPM2_AUTH_SESSION
*/
WOLFTPM_API TPM2_CTX* TPM2_GetActiveCtx(void);

/*!
    \ingroup TPM2_Proprietary
    \brief Determine the size in bytes of a TPM 2.0 hash digest

    \return the size of a TPM 2.0 hash digest as number of bytes
    \return 0 if hash type is invalid

    \param hashAlg a valid TPM 2.0 hash type

    _Example_
    \code
    int digestSize = 0;
    TPMI_ALG_HASH hashAlg = TPM_ALG_SHA256;

    digestSize = TPM2_GetHashDigestSize(hashAlg);
    if (digestSize > 0) {
        //digestSize contains a valid value
    }
    \endcode
*/
WOLFTPM_API int TPM2_GetHashDigestSize(TPMI_ALG_HASH hashAlg);

/*!
    \ingroup TPM2_Proprietary
    \brief Translate a TPM2 hash type to its corresponding wolfcrypt hash type

    \return a value specifying a hash type to use with wolfcrypt
    \return 0 if hash type is invalid

    \param hashAlg a valid TPM 2.0 hash type

    _Example_
    \code
    int wc_hashType;
    TPMI_ALG_HASH hashAlg = TPM_ALG_SHA256;

    wc_hashType = TPM2_GetHashDigestSize(hashAlg);
    if (wc_hashType > 0) {
        //wc_hashType contains a valid wolfcrypt hash type
    }
    \endcode
*/
WOLFTPM_API int TPM2_GetHashType(TPMI_ALG_HASH hashAlg);

/*!
    \ingroup TPM2_Proprietary
    \brief Generate a fresh nonce of random numbers
    \note Can use the TPM random number generator if WOLFTPM2_USE_HW_RNG is defined

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (TPM IO issue or wolfcrypt configuration)
    \return BAD_FUNC_ARG: check the provided arguments

    \param nonceBuf pointer to a BYTE buffer
    \param nonceSz size of the nonce in bytes

    _Example_
    \code
    int rc, nonceSize = 32;
    BYTE freshNonce[32];

    rc = TPM2_GetNonce(&freshNonce, nonceSize);
    if (rc != TPM_RC_SUCCESS) {
        //TPM2_GetNonce failed
    }
    \endcode
*/
WOLFTPM_API int TPM2_GetNonce(byte* nonceBuf, int nonceSz);

/*!
    \ingroup TPM2_Proprietary
    \brief Helper function to prepare a correct PCR selection
            For example, when preparing to create a TPM2_Quote

    \param pcr pointer to a structure of type TPML_PCR_SELECTION
    \param alg value of type TPM_ALG_ID specifying the type of hash algorithm used
    \param pcrIndex value between 0 and 23 specifying the PCR register for use

    _Example_
    \code
    int pcrIndex = 16; // This is a PCR register for DEBUG & testing purposes
    PCR_Read_In pcrRead;

    TPM2_SetupPCRSel(&pcrRead.pcrSelectionIn, TPM_ALG_SHA256, pcrIndex);
    \endcode

    \sa TPM2_PCR_Read
    \sa TPM2_PCR_Extend
    \sa TPM2_PCR_Reset
    \sa TPM2_Quote
*/
WOLFTPM_API void TPM2_SetupPCRSel(TPML_PCR_SELECTION* pcr, TPM_ALG_ID alg,
    int pcrIndex);

/*!
    \ingroup TPM2_Proprietary
    \brief Helper function to prepare a correct PCR selection with multiple indices
            For example, when preparing to create a TPM2_Quote

    \param pcr pointer to a structure of type TPML_PCR_SELECTION
    \param alg value of type TPM_ALG_ID specifying the type of hash algorithm used
    \param pcrArray array of values between 0 and 23 specifying the PCR register for use
    \param pcrArrayLen length of the pcrArray

    _Example_
    \code
    int pcrIndex = 16; // This is a PCR register for DEBUG & testing purposes
    PCR_Read_In pcrRead;

    TPM2_SetupPCRSel(&pcrRead.pcrSelectionIn, TPM_ALG_SHA256, pcrIndex);
    \endcode

    \sa TPM2_PCR_Read
    \sa TPM2_PCR_Extend
    \sa TPM2_PCR_Reset
    \sa TPM2_Quote
*/
WOLFTPM_API void TPM2_SetupPCRSelArray(TPML_PCR_SELECTION* pcr, TPM_ALG_ID alg,
    byte* pcrArray, word32 pcrArrayLen);

/*!
    \ingroup TPM2_Proprietary
    \brief Get a human readable string for any TPM 2.0 return code

    \return pointer to a string constant

    \param rc integer value representing a TPM return code

    _Example_
    \code
    int rc;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    \endcode
*/
WOLFTPM_API const char* TPM2_GetRCString(int rc);

/*!
    \ingroup TPM2_Proprietary
    \brief Get a human readable string for any TPM 2.0 algorithm

    \return pointer to a string constant

    \param alg value of type TPM_ALG_ID specifying a valid TPM 2.0 algorithm

    _Example_
    \code
    int paramEncAlg = TPM_ALG_CFB;

    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));
    \endcode
*/
WOLFTPM_API const char* TPM2_GetAlgName(TPM_ALG_ID alg);

/*!
    \ingroup TPM2_Proprietary
    \brief Determine the size in bytes of any TPM ECC Curve

    \return 0 in case of invalid curve type
    \return integer value representing the number of bytes

    \param curveID value of type TPM_ECC_CURVE

    _Example_
    \code
    int bytes;
    TPM_ECC_CURVE curve = TPM_ECC_NIST_P256;

    bytes = TPM2_GetCurveSize(curve);
    if (bytes == 0) {
        //TPM2_GetCurveSize failed
    }
    \endcode
*/
WOLFTPM_API int TPM2_GetCurveSize(TPM_ECC_CURVE curveID);

/*!
    \ingroup TPM2_Proprietary
    \brief Translate a wolfcrypt curve type to its corresponding TPM curve type

    \return integer value representing a wolfcrypt curve type
    \return ECC_CURVE_OID_E in case of invalid curve type

    \param curveID pointer to a BYTE buffer

    _Example_
    \code
    int tpmCurve;
    int wc_curve = ECC_SECP256R1;

    tpmCurve = TPM2_GetTpmCurve(curve);
    \\in this case tpmCurve will be TPM_ECC_NIST_P256
    if (tpmCurve = ECC_CURVE_OID_E) {
        //TPM2_GetTpmCurve failed
    }
    \endcode

    \sa TPM2_GetWolfCurve
*/
WOLFTPM_API int TPM2_GetTpmCurve(int curveID);

/*!
    \ingroup TPM2_Proprietary
    \brief Translate a TPM curve type to its corresponding wolfcrypt curve type

    \return integer value representing a TPM curve type
    \return -1 or ECC_CURVE_OID_E in case of invalid curve type

    \param curve_id pointer to a BYTE buffer

    _Example_
    \code
    int tpmCurve = TPM_ECC_NIST_P256;
    int wc_curve;

    wc_curve = TPM2_GetWolfCurve(tpmCurve);
    \\in this case tpmCurve will be ECC_SECP256R1
    if (wc_curve = ECC_CURVE_OID_E || wc_curve == -1) {
        //TPM2_GetWolfCurve failed
    }
    \endcode

    \sa TPM2_GetTpmCurve
*/
WOLFTPM_API int TPM2_GetWolfCurve(int curve_id);

/*!
    \ingroup TPM2_Proprietary
    \brief Parses TPM2B_ATTEST and populates the data in TPMS_ATTEST structure
    \note This is public API of the helper function TPM2_Packet_ParseAttest

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param in pointer to a structure of a TPM2B_ATTEST type
    \param out pointer to a structure of a TPMS_ATTEST type

    _Example_
    \code
    TPM2B_ATTEST in; //for example, as part of a TPM2_Quote
    TPMS_ATTEST out

    rc = TPM2_GetNonce(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        //TPM2_ParseAttest failed
    }
    \endcode
*/
WOLFTPM_API int TPM2_ParseAttest(const TPM2B_ATTEST* in, TPMS_ATTEST* out);

/*!
    \ingroup TPM2_Proprietary
    \brief Computes fresh NV Index name based on a nvPublic structure

    \return TPM_RC_SUCCESS: successful
    \return negative integer value in case of an error
    \return BAD_FUNC_ARG: check the provided arguments
    \return NOT_COMPILED_IN: check if wolfcrypt is enabled

    \param nvPublic
    \param buffer pointer to a structure of a TPMS_ATTEST type
    \param size pointer to a variable of UINT16 type to store the size of the nvIndex

    _Example_
    \code
    TPMS_NV_PUBLIC nvPublic;
    BYTE buffer[TPM_MAX_DIGEST_SIZE];
    UINT16 size;

    rc = TPM2_HashNvPublic(&nvPublic, &buffer, &size);
    if (rc != TPM_RC_SUCCESS) {
        //TPM2_HashNvPublic failed
    }
    \endcode
*/
WOLFTPM_API int TPM2_HashNvPublic(TPMS_NV_PUBLIC* nvPublic, byte* buffer, UINT16* size);

/*!
    \ingroup TPM2_Proprietary
    \brief Populates TPM2B_PUBLIC structure based on a user provided buffer
    \note Public API of the helper function TPM2_Packet_AppendPublic

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: insufficient buffer size
    \return BAD_FUNC_ARG: check the provided arguments

    \param buf pointer to a user buffer
    \param size integer value of word32 type, specifying the size of the user buffer
    \param sizeUsed pointer to an integer variable, stores the used size of pub->buffer
    \param pub pointer to an empty structure of TPM2B_PUBLIC type

    _Example_
    \code
    TPM2B_PUBLIC pub; //empty
    int sizeUsed, rc;
    BYTE buffer[sizeof(TPM2B_PUBLIC)];
    word32 size = sizeof(buffer);

    rc = TPM2_AppendPublic(&buffer, size, &sizeUsed, &pub);
    if (rc != TPM_RC_SUCCESS) {
        //TPM2_AppendPublic failed
    }
    \endcode

    \sa TPM2_ParsePublic
*/
WOLFTPM_API int TPM2_AppendPublic(byte* buf, word32 size, int* sizeUsed, TPM2B_PUBLIC* pub);

/*!
    \ingroup TPM2_Proprietary
    \brief Parses TPM2B_PUBLIC structure and stores in a user provided buffer
    \note Public API of the helper function TPM2_Packet_ParsePublic

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: insufficient buffer size
    \return BAD_FUNC_ARG: check the provided arguments

    \param pub pointer to a populated structure of TPM2B_PUBLIC type
    \param buf pointer to an empty user buffer
    \param size integer value of word32 type, specifying the available size of the user buffer
    \param sizeUsed pointer to an integer variable, stores the used size of the user buffer

    _Example_
    \code
    TPM2B_PUBLIC pub; //populated
    int sizeUsed, rc;
    BYTE buffer[sizeof(TPM2B_PUBLIC)];
    word32 size = sizeof(buffer);

    rc = TPM2_ParsePublic(&pub, buffer, size, &sizeUsed);
    if (rc != TPM_RC_SUCCESS) {
        //TPM2_ParsePublic failed
    }
    \endcode

    \sa TPM2_AppendPublic
*/
WOLFTPM_API int TPM2_ParsePublic(TPM2B_PUBLIC* pub, byte* buf, word32 size, int* sizeUsed);

/*!
    \ingroup TPM2_Proprietary
    \brief Provides the Name of a TPM object
    \note The object is reference by its TPM handle and session index

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param ctx pointer to a TPM2 context
    \param handleValue value of UINT32 type, specifying a valid TPM handle
    \param handleCnt total number of handles used in the current TPM command/session
    \param idx index value, between one and three, specifying a valid TPM Authorization session
    \param name pointer to an empty structure of TPM2B_NAME type

    _Example_
    \code
    int rc;
    UINT32 handleValue = TRANSIENT_FIRST;
    handleCount = 1;
    sessionIdx = 0;
    TPM2B_NAME name;

    rc = TPM2_GetName(ctx, handleValue, handleCount, sessionIdx, &name);
    if (rc != TPM_RC_SUCCESS) {
        //TPM2_GetName failed
    }
    \endcode
*/
WOLFTPM_LOCAL int TPM2_GetName(TPM2_CTX* ctx, UINT32 handleValue, int handleCnt, int idx, TPM2B_NAME* name);

#ifdef WOLFTPM2_USE_WOLF_RNG
WOLFTPM_API int TPM2_GetWolfRng(WC_RNG** rng);
#endif

typedef enum {
    TPM_VENDOR_UNKNOWN = 0,
    TPM_VENDOR_INFINEON = 0x15d1,
    TPM_VENDOR_STM = 0x104a,
    TPM_VENDOR_MCHP = 0x1114,
    TPM_VENDOR_NUVOTON = 0x1050,
    TPM_VENDOR_NATIONTECH = 0x1B4E,
} TPM_Vendor_t;


/*!
    \ingroup TPM2_Proprietary
    \brief Provides the vendorID of the active TPM2 context
    \note Depends on correctly read TPM device info during TPM Init

    \return integer value of UINT16 type, specifying the vendor ID
    \return 0 if TPM2 context is invalid or NULL

    _Example_
    \code
    TPM2_CTX *tpm2Ctx;

    tpm2Ctx = TPM2_GetActiveCtx();
    \endcode

    \sa TPM2_GetCapabilities
    \sa TPM2_Init
*/
WOLFTPM_API UINT16 TPM2_GetVendorID(void);


/* Internal helper API for ensuring memory is forcefully zero'd */
WOLFTPM_LOCAL void TPM2_ForceZero(void* mem, word32 len);


#ifdef DEBUG_WOLFTPM
/*!
    \ingroup TPM2_Proprietary
    \brief Helper function to print a binary buffer in a formatted way
    \note Requires DEBUG_WOLFTPM to be defined

    \param buffer pointer to a buffer of BYTE type
    \param length integer value of word32 type, containing the size of the buffer

    _Example_
    \code
    BYTE buffer[] = {0x01,0x02,0x03,0x04};
    length = sizeof(buffer);

    TPM2_PrintBin(&buffer, length);
    \endcode

    \sa TPM2_PrintAuth
    \sa TPM2_PrintPublicArea
*/
WOLFTPM_API void TPM2_PrintBin(const byte* buffer, word32 length);

/*!
    \ingroup TPM2_Proprietary
    \brief Helper function to print a structure of TPMS_AUTH_COMMAND type in a human readable way
    \note Requires DEBUG_WOLFTPM to be defined

    \param authCmd pointer to a populated structure of TPMS_AUTH_COMMAND type

    _Example_
    \code
    TPMS_AUTH_COMMAND authCmd; //for example, part of a TPM Authorization session

    TPM2_PrintAuthCmd(&authCmd);
    \endcode

    \sa TPM2_PrintBin
    \sa TPM2_PrintPublicArea
*/
WOLFTPM_API void TPM2_PrintAuth(const TPMS_AUTH_COMMAND* authCmd);

/*!
    \ingroup TPM2_Proprietary
    \brief Helper function to print a structure of TPM2B_PUBLIC type in a human readable way
    \note Requires DEBUG_WOLFTPM to be defined

    \param pub pointer to a populated structure of TPM2B_PUBLIC type

    _Example_
    \code
    TPM2B_PUBLIC pub; //for example, part of the output of a successful TPM2_Create

    TPM2_PrintPublicArea(&pub);
    \endcode

    \sa TPM2_PrintBin
    \sa TPM2_PrintAuth
    \sa TPM2_Create
    \sa TPM2_ReadPublic
*/
WOLFTPM_API void TPM2_PrintPublicArea(const TPM2B_PUBLIC* pub);
#else
#define TPM2_PrintBin(b, l)
#define TPM2_PrintAuth(b)
#define TPM2_PrintPublicArea(b)
#endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* __TPM2_H__ */
