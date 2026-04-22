/* fwtpm.h
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

#ifndef _FWTPM_H_
#define _FWTPM_H_

#ifdef WOLFTPM_FWTPM

/* WOLFTPM_SMALL_STACK requires heap allocation, incompatible with NO_HEAP */
#if defined(WOLFTPM_SMALL_STACK) && defined(WOLFTPM2_NO_HEAP)
    #error "WOLFTPM_SMALL_STACK and WOLFTPM2_NO_HEAP cannot be used together"
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#endif

#ifdef WOLFTPM_FWTPM_TIS
#include <wolftpm/fwtpm/fwtpm_tis.h>
#endif

/* Endian byte-array helpers - use shared TPM2_Packet helpers.
 * Note: argument order differs (Fw: buf,val; TPM2_Packet: val,buf) */
#define FwStoreU16BE(buf, val) TPM2_Packet_U16ToByteArray((val), (buf))
#define FwStoreU32BE(buf, val) TPM2_Packet_U32ToByteArray((val), (buf))
#define FwStoreU64BE(buf, val) TPM2_Packet_U64ToByteArray((val), (buf))
#define FwLoadU16BE(buf)       TPM2_Packet_ByteArrayToU16(buf)
#define FwLoadU32BE(buf)       TPM2_Packet_ByteArrayToU32(buf)
#define FwLoadU64BE(buf)       TPM2_Packet_ByteArrayToU64(buf)
#define FwStoreU16LE(buf, val) TPM2_Packet_U16ToByteArrayLE((val), (buf))
#define FwStoreU32LE(buf, val) TPM2_Packet_U32ToByteArrayLE((val), (buf))
#define FwLoadU16LE(buf)       TPM2_Packet_ByteArrayToU16LE(buf)
#define FwLoadU32LE(buf)       TPM2_Packet_ByteArrayToU32LE(buf)
#define FwStoreU64LE(buf, val) do { \
    FwStoreU32LE((buf), (UINT32)(val)); \
    FwStoreU32LE((buf) + 4, (UINT32)((UINT64)(val) >> 32)); \
} while (0)
#define FwLoadU64LE(buf) \
    ((UINT64)FwLoadU32LE(buf) | ((UINT64)FwLoadU32LE((buf) + 4) << 32))

#ifdef __cplusplus
    extern "C" {
#endif

/* fwTPM version */
#define FWTPM_VERSION_MAJOR    0
#define FWTPM_VERSION_MINOR    1
#define FWTPM_VERSION_PATCH    0
#define FWTPM_VERSION_STRING   "0.1.0"

/* Manufacturer identity for GetCapability */
#define FWTPM_MANUFACTURER     "WOLF"
#define FWTPM_VENDOR_STRING    "wolfTPM"
#define FWTPM_MODEL            "fwTPM"
#define FWTPM_FIRMWARE_V1      FWTPM_VERSION_MAJOR
#define FWTPM_FIRMWARE_V2      FWTPM_VERSION_MINOR

/* Default ports - socket transport only (not used in TIS mode) */
#ifndef WOLFTPM_FWTPM_TIS
    #ifndef FWTPM_CMD_PORT
    #define FWTPM_CMD_PORT     2321
    #endif
    #ifndef FWTPM_PLAT_PORT
    #define FWTPM_PLAT_PORT    2322
    #endif
#endif

/* Limits */
#ifndef FWTPM_MAX_COMMAND_SIZE
#define FWTPM_MAX_COMMAND_SIZE 4096
#endif

/* Maximum random bytes per GetRandom call */
#ifndef FWTPM_MAX_RANDOM_BYTES
#define FWTPM_MAX_RANDOM_BYTES 48
#endif

/* Maximum transient objects loaded at once (TPM 2.0 spec minimum: 3) */
#ifndef FWTPM_MAX_OBJECTS
#define FWTPM_MAX_OBJECTS      3
#endif

/* Maximum persistent objects (EvictControl) */
#ifndef FWTPM_MAX_PERSISTENT
#define FWTPM_MAX_PERSISTENT   8
#endif

/* Maximum private key DER size (RSA 2048 ~1193 bytes, ECC P384 ~167 bytes) */
#ifndef FWTPM_MAX_PRIVKEY_DER
    #ifdef NO_RSA
        #define FWTPM_MAX_PRIVKEY_DER  256
    #else
        #define FWTPM_MAX_PRIVKEY_DER  1280
    #endif
#endif

/* Maximum sensitive area buffer: private key DER + wire-format overhead
 * (sensitiveType(2) + authValue(2+64) + seedValue(2+48) + size(2) = ~120) */
#define FWTPM_MAX_SENSITIVE_SIZE  (FWTPM_MAX_PRIVKEY_DER + 128)

/* Maximum concurrent hash sequences */
#ifndef FWTPM_MAX_HASH_SEQ
#define FWTPM_MAX_HASH_SEQ     4
#endif

/* Maximum cached primary keys (one per hierarchy) */
#ifndef FWTPM_MAX_PRIMARY_CACHE
#define FWTPM_MAX_PRIMARY_CACHE 4
#endif

/* Maximum concurrent auth sessions */
#ifndef FWTPM_MAX_SESSIONS
#define FWTPM_MAX_SESSIONS     4
#endif

/* Maximum NV indices (user NV RAM slots) */
#ifndef FWTPM_MAX_NV_INDICES
#define FWTPM_MAX_NV_INDICES   16
#endif

/* Maximum data size for a single NV index (per spec 2048, NV_EXTEND = hashSz) */
#ifndef FWTPM_MAX_NV_DATA
#define FWTPM_MAX_NV_DATA      2048
#endif

/* Internal buffer sizes (compile-time overridable) */
#ifndef FWTPM_MAX_DATA_BUF
#define FWTPM_MAX_DATA_BUF     1024  /* HMAC, hash sequences, general data */
#endif
#ifndef FWTPM_MAX_PUB_BUF
#define FWTPM_MAX_PUB_BUF      512   /* Public area, signature, seed, OAEP */
#endif
#ifndef FWTPM_MAX_DER_SIG_BUF
#define FWTPM_MAX_DER_SIG_BUF  256   /* DER signature, ECC primes/points */
#endif
#ifndef FWTPM_MAX_ATTEST_BUF
#define FWTPM_MAX_ATTEST_BUF   1024  /* Attestation info marshaling */
#endif
#define FWTPM_MAX_CMD_AUTHS    3     /* Max auth sessions per command */

/* Symmetric key / HMAC buffer sizes */
#ifndef FWTPM_MAX_SYM_KEY_SIZE
#define FWTPM_MAX_SYM_KEY_SIZE     32  /* AES-256 key */
#endif
#ifndef FWTPM_MAX_HMAC_KEY_SIZE
#define FWTPM_MAX_HMAC_KEY_SIZE    64  /* SHA-512 block-size HMAC key */
#endif
#ifndef FWTPM_MAX_HMAC_DIGEST_SIZE
#define FWTPM_MAX_HMAC_DIGEST_SIZE 64  /* SHA-512 output */
#endif

/* fwTPM firmware revision (TPM_PT_REVISION hundredths) */
#ifndef FWTPM_REVISION
#define FWTPM_REVISION 159
#endif

/* Compile-time build date parsed from __DATE__ ("Mmm DD YYYY") */
#define FWTPM_BUILD_YEAR \
    (((__DATE__[7] - '0') * 1000) + ((__DATE__[8] - '0') * 100) + \
     ((__DATE__[9] - '0') *   10) +  (__DATE__[10] - '0'))

#define FWTPM_BUILD_MONTH ( \
    (__DATE__[0]=='J' && __DATE__[1]=='a' && __DATE__[2]=='n') ?  1 : \
    (__DATE__[0]=='F')                                         ?  2 : \
    (__DATE__[0]=='M' && __DATE__[2]=='r')                     ?  3 : \
    (__DATE__[0]=='A' && __DATE__[1]=='p')                     ?  4 : \
    (__DATE__[0]=='M')                                         ?  5 : \
    (__DATE__[0]=='J' && __DATE__[2]=='n')                     ?  6 : \
    (__DATE__[0]=='J')                                         ?  7 : \
    (__DATE__[0]=='A')                                         ?  8 : \
    (__DATE__[0]=='S')                                         ?  9 : \
    (__DATE__[0]=='O')                                         ? 10 : \
    (__DATE__[0]=='N')                                         ? 11 : 12)

#define FWTPM_BUILD_DAY \
    (((__DATE__[4] == ' ') ? 0 : (__DATE__[4] - '0')) * 10 + \
     (__DATE__[5] - '0'))

/* Day-of-year (non-leap; sufficient for TPM_PT_DAY_OF_YEAR) */
#define FWTPM_BUILD_DAY_OF_YEAR ( \
    FWTPM_BUILD_DAY + \
    ((FWTPM_BUILD_MONTH >  1) ? 31 : 0) + \
    ((FWTPM_BUILD_MONTH >  2) ? 28 : 0) + \
    ((FWTPM_BUILD_MONTH >  3) ? 31 : 0) + \
    ((FWTPM_BUILD_MONTH >  4) ? 30 : 0) + \
    ((FWTPM_BUILD_MONTH >  5) ? 31 : 0) + \
    ((FWTPM_BUILD_MONTH >  6) ? 30 : 0) + \
    ((FWTPM_BUILD_MONTH >  7) ? 31 : 0) + \
    ((FWTPM_BUILD_MONTH >  8) ? 31 : 0) + \
    ((FWTPM_BUILD_MONTH >  9) ? 30 : 0) + \
    ((FWTPM_BUILD_MONTH > 10) ? 31 : 0) + \
    ((FWTPM_BUILD_MONTH > 11) ? 30 : 0))

/* PCR banks: 0=SHA-256, 1=SHA-384 (if available) */
/* PCR bank slot assignments. SHA-256 is mandatory (first bank). SHA-1 and
 * SHA-384 are conditional on wolfCrypt build options. The bitmap order
 * matches: bit0=SHA256, bit1=SHA384, bit2=SHA1 — preserves the existing
 * default allocation value for backward compatibility with NV state v2. */
#define FWTPM_PCR_BANK_SHA256  0
#ifdef WOLFSSL_SHA384
    #define FWTPM_PCR_BANK_SHA384  1
    #ifndef NO_SHA
        #define FWTPM_PCR_BANK_SHA1    2
        #define FWTPM_PCR_BANKS        3
        /* SHA-256 + SHA-384; SHA-1 not allocated by default per TCG PC
         * Client guidance (legacy banks may be allocated explicitly). */
        #define FWTPM_PCR_ALLOC_DEFAULT  0x03
    #else
        #define FWTPM_PCR_BANKS        2
        #define FWTPM_PCR_ALLOC_DEFAULT  0x03
    #endif
#else
    #ifndef NO_SHA
        #define FWTPM_PCR_BANK_SHA1    1
        #define FWTPM_PCR_BANKS        2
        #define FWTPM_PCR_ALLOC_DEFAULT  0x01  /* SHA-256 only by default */
    #else
        #define FWTPM_PCR_BANKS        1
        #define FWTPM_PCR_ALLOC_DEFAULT  0x01  /* SHA-256 only */
    #endif
#endif

/* Max digest size we track (SHA-384 = 48 bytes) */
#ifndef TPM_MAX_DIGEST_SIZE
#define TPM_MAX_DIGEST_SIZE    64
#endif


/* --- WOLFTPM_SMALL_STACK helpers ---
 * When WOLFTPM_SMALL_STACK is defined, large stack variables are heap-allocated.
 * Follows the wolfSSL WC_DECLARE_VAR pattern:
 *   SMALL_STACK:  declares pointer, ALLOC does XMALLOC, FREE does XFREE
 *   Normal:       declares array[1], ALLOC/FREE are no-ops
 *
 * Usage for struct types (crypto objects, TPM structs):
 *   FWTPM_DECLARE_VAR(rsaKey, RsaKey);       // declaration
 *   FWTPM_ALLOC_VAR(rsaKey, RsaKey);         // sets rc=TPM_RC_MEMORY on fail
 *   wc_InitRsaKey(rsaKey, NULL);             // use as pointer (not &rsaKey)
 *   FWTPM_FREE_VAR(rsaKey);                  // cleanup (XFREE(NULL) is safe)
 *
 * Usage for byte arrays:
 *   FWTPM_DECLARE_BUF(buf, SIZE);            // declaration
 *   FWTPM_ALLOC_BUF(buf, SIZE);              // sets rc=TPM_RC_MEMORY on fail
 *   memcpy(buf, src, len);                   // use as pointer (unchanged)
 *   FWTPM_FREE_BUF(buf);                     // cleanup
 */
#ifdef WOLFTPM_SMALL_STACK
    #define FWTPM_DECLARE_VAR(name, type) \
        type* name = NULL
    #define FWTPM_ALLOC_VAR(name, type) \
        do { \
            (name) = (type*)XMALLOC(sizeof(type), NULL, \
                DYNAMIC_TYPE_TMP_BUFFER); \
            if ((name) == NULL) { rc = TPM_RC_MEMORY; } \
        } while (0)
    /* Allocate AND zero-initialize. Use this when the variable will be
     * written piecemeal (e.g. parsed from wire) — equivalent to
     * FWTPM_ALLOC_VAR followed by XMEMSET, but bundled to prevent forgetting
     * the memset and leaking stack data into the output. */
    #define FWTPM_CALLOC_VAR(name, type) \
        do { \
            (name) = (type*)XMALLOC(sizeof(type), NULL, \
                DYNAMIC_TYPE_TMP_BUFFER); \
            if ((name) == NULL) { rc = TPM_RC_MEMORY; } \
            else { XMEMSET((name), 0, sizeof(type)); } \
        } while (0)
    #define FWTPM_FREE_VAR(name) \
        XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER)

    #define FWTPM_DECLARE_BUF(name, sz) \
        byte* name = NULL
    /* Compile-time check: buffer size must be > 8 bytes.
     * Catches accidental sizeof(pointer) passed as sz. */
    #define FWTPM_ALLOC_BUF(name, sz) \
        do { \
            typedef char _fwtpm_bufchk_##name[((sz) > 8) ? 1 : -1]; \
            (void)sizeof(_fwtpm_bufchk_##name); \
            (name) = (byte*)XMALLOC((sz), NULL, \
                DYNAMIC_TYPE_TMP_BUFFER); \
            if ((name) == NULL) { rc = TPM_RC_MEMORY; } \
        } while (0)
    /* Allocate AND zero-initialize byte buffer. */
    #define FWTPM_CALLOC_BUF(name, sz) \
        do { \
            typedef char _fwtpm_bufchk_##name[((sz) > 8) ? 1 : -1]; \
            (void)sizeof(_fwtpm_bufchk_##name); \
            (name) = (byte*)XMALLOC((sz), NULL, \
                DYNAMIC_TYPE_TMP_BUFFER); \
            if ((name) == NULL) { rc = TPM_RC_MEMORY; } \
            else { XMEMSET((name), 0, (sz)); } \
        } while (0)
    #define FWTPM_FREE_BUF(name) \
        XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER)

    /* Use instead of sizeof(buf) — sizeof(pointer) is wrong under SMALL_STACK.
     * The sz argument must match the size passed to FWTPM_DECLARE_BUF. */
    #define FWTPM_SIZEOF_BUF(name, sz) (sz)
#else
    #define FWTPM_DECLARE_VAR(name, type) \
        type name[1]
    #define FWTPM_ALLOC_VAR(name, type) do { } while (0)
    #define FWTPM_CALLOC_VAR(name, type) \
        XMEMSET((name), 0, sizeof(type))
    #define FWTPM_FREE_VAR(name) do { } while (0)

    #define FWTPM_DECLARE_BUF(name, sz) \
        byte name[(sz)]
    #define FWTPM_ALLOC_BUF(name, sz) do { } while (0)
    #define FWTPM_CALLOC_BUF(name, sz) \
        XMEMSET((name), 0, (sz))
    #define FWTPM_FREE_BUF(name) do { } while (0)

    #define FWTPM_SIZEOF_BUF(name, sz) sizeof(name)
#endif

/* Transient object slot */
typedef struct FWTPM_Object {
    int used;
    TPM_HANDLE handle;              /* 0x80xxxxxx transient handle */
    TPMT_PUBLIC pub;                /* Public area */
    TPM2B_AUTH authValue;           /* Object auth */
    byte privKey[FWTPM_MAX_PRIVKEY_DER]; /* DER-encoded private key */
    int privKeySize;
    TPM2B_NAME name;                /* Object name = nameAlg || H(publicArea) */
} FWTPM_Object;

/* Hash sequence slot (for HashSequenceStart/SequenceUpdate/SequenceComplete) */
typedef struct FWTPM_HashSeq {
    int used;
    TPM_HANDLE handle;              /* Sequence handle (0x80xxxxxx) */
    TPMI_ALG_HASH hashAlg;         /* Hash algorithm for this sequence */
    int isHmac;                     /* 1 if HMAC sequence, 0 if plain hash */
    TPM2B_AUTH authValue;           /* Sequence auth (from HashSequenceStart) */
#ifndef WOLFTPM2_NO_WOLFCRYPT
    union {
        wc_HashAlg hash;            /* wolfCrypt hash context (isHmac == 0) */
        Hmac hmac;                  /* wolfCrypt HMAC context (isHmac == 1) */
    } ctx;
#endif
} FWTPM_HashSeq;

/* Auth session slot */
typedef struct FWTPM_Session {
    int used;
    TPM_HANDLE handle;              /* 0x02xxxxxx HMAC, 0x03xxxxxx Policy */
    TPM_SE sessionType;             /* TPM_SE_HMAC, TPM_SE_POLICY, TPM_SE_TRIAL */
    TPMI_ALG_HASH authHash;         /* Hash algorithm for this session */
    TPMT_SYM_DEF symmetric;         /* Symmetric alg for param encryption */
    TPM2B_NONCE nonceTPM;           /* TPM-generated nonce */
    TPM2B_NONCE nonceCaller;        /* Last caller nonce received */
    TPM2B_AUTH sessionKey;          /* Session HMAC key (from KDFa) */
    TPM2B_AUTH bindAuth;            /* Auth of bound entity */
    TPM2B_DIGEST policyDigest;      /* Running policy digest (policy sessions) */
    int isPasswordPolicy;           /* 1 if PolicyPassword was called */
    int isAuthValuePolicy;          /* 1 if PolicyAuthValue was called */
    TPM2B_DIGEST cpHashA;           /* PolicyCpHash: locked once set */
    TPM2B_DIGEST nameHash;          /* PolicyNameHash: locked once set */
    int isPPRequired;               /* PolicyPhysicalPresence flag */
} FWTPM_Session;

/* NV index slot (user NV RAM) */
typedef struct FWTPM_NvIndex {
    int inUse;
    TPMS_NV_PUBLIC nvPublic;            /* Public attributes and metadata */
    TPM2B_AUTH authValue;               /* NV index auth (password) */
    byte           data[FWTPM_MAX_NV_DATA]; /* NV data contents */
    int            written;             /* Has any data been written? */
} FWTPM_NvIndex;

/* Cached primary key (for seed-deterministic CreatePrimary behavior) */
typedef struct FWTPM_PrimaryCache {
    int used;
    TPM_HANDLE hierarchy;               /* Owner/Endorsement/Platform/Null */
    byte templateHash[WC_SHA256_DIGEST_SIZE]; /* SHA-256 of inPublic */
    TPMT_PUBLIC pub;                     /* Generated public area */
    byte privKey[FWTPM_MAX_PRIVKEY_DER]; /* DER-encoded private key */
    int privKeySize;
} FWTPM_PrimaryCache;

/* IO transport HAL callbacks — socket transport only (not used in TIS mode) */
#ifndef WOLFTPM_FWTPM_TIS
typedef struct FWTPM_IO_HAL_S {
    /* Send data to client. Returns 0 on success. */
    int (*send)(void* ctx, const void* buf, int sz);
    /* Receive data from client. Returns 0 on success. */
    int (*recv)(void* ctx, void* buf, int sz);
    /* Wait for connections/data. Returns bitmask:
     * 0x01 = command data ready, 0x02 = platform data ready,
     * 0x04 = new command connection, 0x08 = new platform connection.
     * Negative on error. */
    int (*wait)(void* ctx);
    /* Accept a new connection (for connection-oriented transports).
     * type: 0=command, 1=platform. Returns 0 on success. */
    int (*accept)(void* ctx, int type);
    /* Close a connection. type: 0=command, 1=platform. */
    void (*close_conn)(void* ctx, int type);
    /* User context (e.g., socket fds, SPI handle, etc.) */
    void* ctx;
} FWTPM_IO_HAL;

/* IO context for socket transport (default) */
#ifdef _WIN32
    #define FWTPM_INVALID_FD INVALID_SOCKET
#else
    #define FWTPM_INVALID_FD (-1)
#endif
typedef struct FWTPM_IO_CTX {
    SOCKET_T listenFd;       /* Listening socket for command port */
    SOCKET_T platListenFd;   /* Listening socket for platform port */
    SOCKET_T clientFd;       /* Accepted client connection */
    SOCKET_T platClientFd;   /* Accepted platform client connection */
} FWTPM_IO_CTX;
#endif /* !WOLFTPM_FWTPM_TIS */

/* fwTPM context - holds all TPM state */
typedef struct FWTPM_CTX {
    volatile int running;       /* Server running flag (volatile for signal handler) */

#ifndef WOLFTPM_FWTPM_TIS
    /* Socket transport configuration (not used in TIS mode) */
    int cmdPort;                /* Command port (default 2321) */
    int platPort;               /* Platform port (default 2322) */
    FWTPM_IO_HAL ioHal;        /* IO transport HAL callbacks */
    FWTPM_IO_CTX io;            /* Socket IO state */
#endif

    /* Command/Response buffers */
    byte cmdBuf[FWTPM_MAX_COMMAND_SIZE];
    byte rspBuf[FWTPM_MAX_COMMAND_SIZE];

    /* TPM state */
    int powerOn;
    int wasStarted;             /* Has TPM2_Startup been called */
    int pendingClear;           /* Deferred clear (after response auth) */
    int disableClear;           /* ClearControl: 1 = Clear is disabled */
    int globalNvWriteLock;      /* NV_GlobalWriteLock (reset on Startup CLEAR) */
#ifndef FWTPM_NO_DA
    /* Dictionary Attack protection state */
    UINT32 daFailedTries;       /* Current failed auth count (volatile) */
    UINT32 daMaxTries;          /* Threshold before lockout (default 32) */
    UINT32 daRecoveryTime;      /* Seconds to decrement failedTries */
    UINT32 daLockoutRecovery;   /* Seconds to fully recover. 0=reboot only */
#endif
    int activeLocality;
    UINT64 clockOffset;         /* Clock offset set by ClockSet */

    /* PCR state: [pcrIndex][bank][digest bytes] */
    byte pcrDigest[IMPLEMENTATION_PCR][FWTPM_PCR_BANKS][TPM_MAX_DIGEST_SIZE];
    UINT32 pcrUpdateCounter;

    /* Per-PCR auth values (set by PCR_SetAuthValue) */
    TPM2B_AUTH pcrAuth[IMPLEMENTATION_PCR];
    /* Per-PCR auth policies (set by PCR_SetAuthPolicy) */
    TPM2B_DIGEST pcrPolicy[IMPLEMENTATION_PCR];
    TPMI_ALG_HASH pcrPolicyAlg[IMPLEMENTATION_PCR];
    /* PCR bank allocation (bitmap: bit 0=SHA-256, bit 1=SHA-384) */
    UINT8 pcrAllocatedBanks; /* default: 0x03 = both banks */

    /* Transient object slots */
    FWTPM_Object objects[FWTPM_MAX_OBJECTS];

    /* Primary key cache: ensures CreatePrimary is deterministic per seed */
    FWTPM_PrimaryCache primaryCache[FWTPM_MAX_PRIMARY_CACHE];

    /* Persistent object slots (0x81xxxxxx handles via EvictControl) */
    FWTPM_Object persistent[FWTPM_MAX_PERSISTENT];

    /* NV index slots (0x01xxxxxx handles) */
    FWTPM_NvIndex nvIndices[FWTPM_MAX_NV_INDICES];

    /* Hash sequence slots */
    FWTPM_HashSeq hashSeq[FWTPM_MAX_HASH_SEQ];

    /* Auth session slots */
    FWTPM_Session sessions[FWTPM_MAX_SESSIONS];

    /* Hierarchy seeds (generated once, persisted in NV) */
    byte ownerSeed[TPM_SHA384_DIGEST_SIZE];
    byte endorsementSeed[TPM_SHA384_DIGEST_SIZE];
    byte platformSeed[TPM_SHA384_DIGEST_SIZE];
    byte nullSeed[TPM_SHA384_DIGEST_SIZE];

    /* Hierarchy auth values */
    TPM2B_AUTH ownerAuth;
    TPM2B_AUTH endorsementAuth;
    TPM2B_AUTH platformAuth;
    TPM2B_AUTH lockoutAuth;

    /* Hierarchy auth policies (set by SetPrimaryPolicy) */
    TPM2B_DIGEST ownerPolicy;
    TPMI_ALG_HASH ownerPolicyAlg;
    TPM2B_DIGEST endorsementPolicy;
    TPMI_ALG_HASH endorsementPolicyAlg;
    TPM2B_DIGEST platformPolicy;
    TPMI_ALG_HASH platformPolicyAlg;
    TPM2B_DIGEST lockoutPolicy;
    TPMI_ALG_HASH lockoutPolicyAlg;

    /* Per-boot context protection key (volatile only, never persisted).
     * Used by ContextSave/ContextLoad for HMAC + AES-CFB protection of
     * session context blobs per TPM 2.0 Part 1 §30. */
    byte ctxProtectKey[AES_256_KEY_SIZE];
    int  ctxProtectKeyValid;

    /* TIS transport state (when not using sockets) */
#ifdef WOLFTPM_FWTPM_TIS
    FWTPM_TIS_HAL  tisHal;      /* Transport HAL callbacks */
    FWTPM_TIS_REGS* tisRegs;    /* Pointer to register state */
#endif

    /* NV HAL callbacks */
    struct FWTPM_NV_HAL_S {
        int (*read)(void* ctx, word32 offset, byte* buf, word32 size);
        int (*write)(void* ctx, word32 offset, const byte* buf, word32 size);
        int (*erase)(void* ctx, word32 offset, word32 size); /* Optional */
        void* ctx;
        word32 maxSize;     /* Total NV region size */
    } nvHal;

    /* Clock HAL callbacks (optional - if not set, clockOffset used directly) */
    struct FWTPM_CLOCK_HAL_S {
        UINT64 (*get_ms)(void* ctx);  /* Return milliseconds since boot */
        void* ctx;
    } clockHal;

    /* NV journal write position (next append offset) */
    word32 nvWritePos;
    int nvCompacting;   /* Guard flag to prevent cyclic recursion during NV compaction */

    /* ContextSave sequence counter (monotonic, reset on init) */
    UINT64 contextSeqCounter;

#ifdef HAVE_ECC
    /* EC_Ephemeral commit counter and key storage (volatile) */
    UINT16 ecEphemeralCounter;
    byte ecEphemeralKey[FWTPM_MAX_PRIVKEY_DER];
    int ecEphemeralKeySz;
    UINT16 ecEphemeralCurve;
#endif

    /* wolfCrypt RNG */
#ifndef WOLFTPM2_NO_WOLFCRYPT
    WC_RNG rng;
#endif
} FWTPM_CTX;

/** @defgroup wolfTPM_fwTPM wolfTPM fwTPM (Firmware TPM)
 *
 * Public API for the wolfTPM firmware TPM (fwTPM) software TPM 2.0
 * implementation. fwTPM is a portable TPM server that speaks the
 * TCG TPM 2.0 command protocol and can run alongside or in place of
 * a hardware TPM. Transports are pluggable (sockets, TIS shared memory,
 * SPI/UART on embedded targets) via HAL callbacks. Storage (NV) and
 * clock are also pluggable so the same core can run on Linux and
 * bare-metal microcontrollers.
 */

/*!
    \ingroup wolfTPM_fwTPM
    \brief Initialize a fwTPM context. Seeds the RNG, clears TPM state,
    and prepares the context for FWTPM_NV_Init / FWTPM_IO_Init.

    \return 0 on success
    \return TPM_RC_MEMORY if RNG initialization fails

    \param ctx pointer to caller-allocated FWTPM_CTX (must be zeroed)

    \sa FWTPM_Cleanup
    \sa FWTPM_NV_SetHAL
    \sa FWTPM_Clock_SetHAL
*/
WOLFTPM_API int FWTPM_Init(FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM
    \brief Release resources held by a fwTPM context. Zeros all
    hierarchy seeds, session keys, and sensitive auth values before
    freeing. Safe to call on a partially-initialized context.

    \return 0 on success

    \param ctx pointer to an initialized FWTPM_CTX

    \sa FWTPM_Init
*/
WOLFTPM_API int FWTPM_Cleanup(FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM
    \brief Return a pointer to the compile-time fwTPM version string
    (e.g. "0.1.0").

    \return pointer to a static, null-terminated version string
*/
WOLFTPM_API const char* FWTPM_GetVersionString(void);

/*!
    \ingroup wolfTPM_fwTPM
    \brief Register a platform clock source for fwTPM. On embedded
    targets this allows the TPM clock (TPM2_ReadClock / TPM2_ClockSet)
    to advance from a hardware timer. When no HAL is registered,
    FWTPM_Clock_GetMs returns ctx->clockOffset only.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx is NULL

    \param ctx pointer to an initialized FWTPM_CTX
    \param get_ms callback returning milliseconds-since-boot; may be NULL
        to clear a previously registered HAL
    \param halCtx opaque context passed back to get_ms

    \sa FWTPM_Clock_GetMs
*/
WOLFTPM_API int FWTPM_Clock_SetHAL(FWTPM_CTX* ctx,
    UINT64 (*get_ms)(void* halCtx), void* halCtx);

/*!
    \ingroup wolfTPM_fwTPM
    \brief Get the current TPM clock value in milliseconds. Returns
    ctx->clockOffset plus (if registered) the value from the clock HAL.

    \return current clock value in milliseconds
    \return 0 if ctx is NULL

    \param ctx pointer to an initialized FWTPM_CTX

    \sa FWTPM_Clock_SetHAL
*/
WOLFTPM_API UINT64 FWTPM_Clock_GetMs(FWTPM_CTX* ctx);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFTPM_FWTPM */

#endif /* _FWTPM_H_ */
