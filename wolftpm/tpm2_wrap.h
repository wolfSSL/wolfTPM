/* tpm2_wrap.h
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

#ifndef __TPM2_WRAP_H__
#define __TPM2_WRAP_H__

#include <wolftpm/tpm2.h>

#ifdef __cplusplus
    extern "C" {
#endif


typedef struct WOLFTPM2_HANDLE {
    TPM_HANDLE      hndl;
    TPM2B_AUTH      auth;       /* Used if policyAuth is not set */
    TPMT_SYM_DEF    symmetric;
    TPM2B_NAME      name;
    int             policyAuth; /* Handle requires Policy, not password Auth */
    unsigned int    nameLoaded : 1; /* flag to indicate if "name" was loaded and computed */
} WOLFTPM2_HANDLE;

#define TPM_SES_PWD 0xFF /* Session type for Password that fits in one byte */

typedef struct WOLFTPM2_SESSION {
    TPM_ST          type;         /* Trial, Policy or HMAC; or TPM_SES_PWD */
    WOLFTPM2_HANDLE handle;       /* Session handle from StartAuthSession */
    TPM2B_NONCE     nonceTPM;     /* Value from StartAuthSession */
    TPM2B_NONCE     nonceCaller;  /* Fresh nonce at each command */
    TPM2B_DIGEST    salt;         /* User defined */
    TPMI_ALG_HASH   authHash;
    TPMA_SESSION    sessionAttributes;
} WOLFTPM2_SESSION;

typedef struct WOLFTPM2_DEV {
    TPM2_CTX ctx;
    TPM2_AUTH_SESSION session[MAX_SESSION_NUM];
} WOLFTPM2_DEV;

/* WOLFTPM2_KEYBLOB can be cast to WOLFTPM2_KEY.
 *   Both structures must have "handle" and "pub" as first members */
typedef struct WOLFTPM2_KEY {
    WOLFTPM2_HANDLE   handle;
    TPM2B_PUBLIC      pub;
} WOLFTPM2_KEY;

typedef struct WOLFTPM2_KEYBLOB {
    WOLFTPM2_HANDLE   handle;
    TPM2B_PUBLIC      pub;
    TPM2B_PRIVATE     priv;
    /* Note: Member "name" moved to "handle.name" */
} WOLFTPM2_KEYBLOB;

typedef struct WOLFTPM2_HASH {
    WOLFTPM2_HANDLE handle;
} WOLFTPM2_HASH;

typedef struct WOLFTPM2_NV {
    WOLFTPM2_HANDLE handle;
} WOLFTPM2_NV;

typedef struct WOLFTPM2_HMAC {
    WOLFTPM2_HASH   hash;
    WOLFTPM2_KEY    key;

    /* option bits */
    word16 hmacKeyLoaded:1;
    word16 hmacKeyKeep:1;
} WOLFTPM2_HMAC;

#ifdef WOLFTPM2_CERT_GEN
typedef struct WOLFTPM2_CSR {
    Cert req;
} WOLFTPM2_CSR;
#endif

#ifndef WOLFTPM2_MAX_BUFFER
    #define WOLFTPM2_MAX_BUFFER 2048
#endif

typedef struct WOLFTPM2_BUFFER {
    int size;
    byte buffer[WOLFTPM2_MAX_BUFFER];
} WOLFTPM2_BUFFER;

typedef enum WOLFTPM2_MFG {
    TPM_MFG_UNKNOWN = 0,
    TPM_MFG_INFINEON,
    TPM_MFG_STM,
    TPM_MFG_MCHP,
    TPM_MFG_NUVOTON,
    TPM_MFG_NATIONTECH,
} WOLFTPM2_MFG;

typedef struct WOLFTPM2_CAPS {
    WOLFTPM2_MFG mfg;
    char mfgStr[4 + 1];
    char vendorStr[(4 * 4) + 1];
    word32 tpmType;
    word16 fwVerMajor;
    word16 fwVerMinor;
    word32 fwVerVendor;
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
    word32 keyGroupId;
    word16 fwCounter;
    word16 fwCounterSame;
    byte   opMode;
#endif

    /* bits */
    word16 fips140_2 : 1; /* using FIPS mode */
    word16 cc_eal4   : 1; /* Common Criteria EAL4+ */
    word16 req_wait_state : 1; /* requires SPI wait state */
} WOLFTPM2_CAPS;

/* NV Handles */
#define TPM2_NV_RSA_EK_CERT 0x01C00002
#define TPM2_NV_ECC_EK_CERT 0x01C0000A


/* Wrapper API's to simplify TPM use */

/** @defgroup wolfTPM2_Wrappers wolfTPM2 Wrappers
 *
 * This module describes the rich API of wolfTPM called wrappers.
 *
 * wolfTPM wrappers are used in two main cases:
 * * Perform common TPM 2.0 tasks, like key generation and storage
 * * Perform complex TPM 2.0 tasks, like attestation and parameter encryption
 *
 * wolfTPM enables quick and rapid use of TPM 2.0 thanks to its many wrapper functions.
 *
 */

/* For devtpm and swtpm builds, the ioCb and userCtx are not used and should be set to NULL */

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Test initialization of a TPM and optionally the TPM capabilities can be received

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param ioCb function pointer to a IO callback (see hal/tpm_io.h)
    \param userCtx pointer to a user context (can be NULL)
    \param caps to a structure of WOLFTPM2_CAPS type for returning the TPM capabilities (can be NULL)

    \sa wolfTPM2_Init
    \sa TPM2_Init
*/
WOLFTPM_API int wolfTPM2_Test(TPM2HalIoCb ioCb, void* userCtx, WOLFTPM2_CAPS* caps);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Complete initialization of a TPM

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to an empty structure of WOLFTPM2_DEV type
    \param ioCb function pointer to a IO callback (see hal/tpm_io.h)
    \param userCtx pointer to a user context (can be NULL)

    _Example_
    \code
    int rc;
    WOLFTPM2_DEV dev;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        //wolfTPM2_Init failed
        goto exit;
    }
    \endcode

    \sa wolfTPM2_OpenExisting
    \sa wolfTPM2_Test
    \sa TPM2_Init
*/
WOLFTPM_API int wolfTPM2_Init(WOLFTPM2_DEV* dev, TPM2HalIoCb ioCb, void* userCtx);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Use an already initialized TPM, in its current TPM locality

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to an empty structure of WOLFTPM2_DEV type
    \param ioCb function pointer to a IO callback (see hal/tpm_io.h)
    \param userCtx pointer to a user context (can be NULL)

    \sa wolfTPM2_Init
    \sa wolfTPM2_Cleanup
    \sa TPM2_Init
*/
WOLFTPM_API int wolfTPM2_OpenExisting(WOLFTPM2_DEV* dev, TPM2HalIoCb ioCb, void* userCtx);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Easy to use TPM and wolfcrypt deinitialization
    \note Calls wolfTPM2_Cleanup_ex with appropriate doShutdown parameter

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a populated structure of WOLFTPM2_DEV type

    _Example_
    \code
    int rc;

    rc = wolfTPM2_Cleanup(&dev);
    if (rc != TPM_RC_SUCCESS) {
        //wolfTPM2_Cleanup failed
        goto exit;
    }
    \endcode

    \sa wolfTPM2_OpenExisting
    \sa wolfTPM2_Test
    \sa TPM2_Init
*/
WOLFTPM_API int wolfTPM2_Cleanup(WOLFTPM2_DEV* dev);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Deinitialization of a TPM (and wolfcrypt if it was used)

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a populated structure of WOLFTPM2_DEV type
    \param doShutdown flag value, if true a TPM2_Shutdown command will be executed

    _Example_
    \code
    int rc;

    //perform TPM2_Shutdown after deinitialization
    rc = wolfTPM2_Cleanup_ex(&dev, 1);
    if (rc != TPM_RC_SUCCESS) {
        //wolfTPM2_Cleanup_ex failed
        goto exit;
    }
    \endcode

    \sa wolfTPM2_OpenExisting
    \sa wolfTPM2_Test
    \sa TPM2_Init
*/
WOLFTPM_API int wolfTPM2_Cleanup_ex(WOLFTPM2_DEV* dev, int doShutdown);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Provides the device ID of a TPM

    \return an integer value of a valid TPM device ID
    \return or INVALID_DEVID if the TPM initialization could not extract DevID

    \param dev pointer to an populated structure of WOLFTPM2_DEV type

    _Example_
    \code
    int tpmDevId;

    tpmDevId = wolfTPM2_GetTpmDevId(&dev);
    if (tpmDevId != INVALID_DEVID) {
        //wolfTPM2_Cleanup_ex failed
        goto exit;
    }
    \endcode

    \sa wolfTPM2_GetCapabilities
    \sa wolfTPM2_Init
*/
WOLFTPM_API int wolfTPM2_GetTpmDevId(WOLFTPM2_DEV* dev);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Asks the TPM to perform its self test

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a populated structure of WOLFTPM2_DEV type

    _Example_
    \code
    int rc;

    //perform TPM2_Shutdown after deinitialization
    rc = wolfTPM2_SelfTest(&dev);
    if (rc != TPM_RC_SUCCESS) {
        //wolfTPM2_SelfTest failed
        goto exit;
    }
    \endcode

    \sa wolfTPM2_OpenExisting
    \sa wolfTPM2_Test
    \sa TPM2_Init
*/
WOLFTPM_API int wolfTPM2_SelfTest(WOLFTPM2_DEV* dev);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Reports the available TPM capabilities

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a populated structure of WOLFTPM2_DEV type
    \param caps pointer to an empty structure of WOLFTPM2_CAPS type to store the capabilities

    _Example_
    \code
    int rc;
    WOLFTPM2_CAPS caps;

    //perform TPM2_Shutdown after deinitialization
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    if (rc != TPM_RC_SUCCESS) {
        //wolfTPM2_GetCapabilities failed
        goto exit;
    }
    \endcode

    \sa wolfTPM2_GetTpmDevId
    \sa wolfTPM2_SelfTest
    \sa wolfTPM2_Init
*/
WOLFTPM_API int wolfTPM2_GetCapabilities(WOLFTPM2_DEV* dev, WOLFTPM2_CAPS* caps);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Gets a list of handles

    \return 0 or greater: successful, count of handles
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param handle handle to start from (example: PCR_FIRST, NV_INDEX_FIRST, HMAC_SESSION_FIRST, POLICY_SESSION_FIRST, PERMANENT_FIRST, TRANSIENT_FIRST or PERSISTENT_FIRST)
    \param handles pointer to TPML_HANDLE to return handle results (optional)

    _Example_
    \code
    int persistent_handle_count;

    // get count of persistent handles
    persistent_handle_count = wolfTPM2_GetHandles(PERSISTENT_FIRST, NULL);
    \endcode

    \sa wolfTPM2_GetCapabilities
*/
WOLFTPM_API int wolfTPM2_GetHandles(TPM_HANDLE handle, TPML_HANDLE* handles);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Clears one of the TPM Authorization slots, pointed by its index number

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: unable to get lock on the TPM2 Context
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three

    \sa wolfTPM2_SetAuth
    \sa wolfTPM2_SetAuthPassword
    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_SetAuthSession
*/
WOLFTPM_API int wolfTPM2_UnsetAuth(WOLFTPM2_DEV* dev, int index);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Clears one of the TPM Authorization session slots, pointed by its index
    number and saves the nonce from the TPM so the session can continue to be used
    again with wolfTPM2_SetAuthSession

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: unable to get lock on the TPM2 Context
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param session pointer to a WOLFTPM2_SESSION struct used with wolfTPM2_StartSession and wolfTPM2_SetAuthSession

    \sa wolfTPM2_StartSession
    \sa wolfTPM2_SetAuthSession
*/
WOLFTPM_API int wolfTPM2_UnsetAuthSession(WOLFTPM2_DEV* dev, int index, WOLFTPM2_SESSION* session);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Sets a TPM Authorization slot using the provided index, session handle, attributes and auth
    \note It is recommended to use one of the other wolfTPM2 wrappers, like wolfTPM2_SetAuthPassword.
    Because the wolfTPM2_SetAuth wrapper provides complete control over the TPM Authorization slot for
    advanced use cases. In most scenarios, wolfTPM2_SetAuthHandle and SetAuthPassword are used.

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param sessionHandle integer value of TPM_HANDLE type
    \param auth pointer to a structure of type TPM2B_AUTH containing one TPM Authorization
    \param sessionAttributes integer value of type TPMA_SESSION, selecting one or more attributes for the Session
    \param name pointer to a TPM2B_NAME structure

    \sa wolfTPM2_SetAuthPassword
    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_SetAuthSession
*/
WOLFTPM_API int wolfTPM2_SetAuth(WOLFTPM2_DEV* dev, int index,
    TPM_HANDLE sessionHandle, const TPM2B_AUTH* auth, TPMA_SESSION sessionAttributes,
    const TPM2B_NAME* name);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Sets a TPM Authorization slot using the provided user auth, typically a password
    \note Often used for authorizing the loading and use of TPM keys, including Primary Keys

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param auth pointer to a structure of type TPM2B_AUTH, typically containing a TPM Key Auth

    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_SetAuthSession
    \sa wolfTPM2_SetAuth
*/
WOLFTPM_API int wolfTPM2_SetAuthPassword(WOLFTPM2_DEV* dev, int index, const TPM2B_AUTH* auth);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Sets a TPM Authorization slot using the user auth associated with a wolfTPM2 Handle
    \note This wrapper is especially useful when using a TPM key for multiple operations and TPM Authorization is required again.

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param handle pointer to a populated structure of WOLFTPM2_HANDLE type

    \sa wolfTPM2_SetAuth
    \sa wolfTPM2_SetAuthPassword
    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_SetAuthSession
*/
WOLFTPM_API int wolfTPM2_SetAuthHandle(WOLFTPM2_DEV* dev, int index, const WOLFTPM2_HANDLE* handle);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Sets a TPM Authorization slot using the provided TPM session handle, index and session attributes
    \note This wrapper is useful for configuring TPM sessions, e.g. session for parameter encryption

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param tpmSession sessionHandle integer value of TPM_HANDLE type
    \param sessionAttributes integer value of type TPMA_SESSION, selecting one or more attributes for the Session

    \sa wolfTPM2_SetAuth
    \sa wolfTPM2_SetAuthPassword
    \sa wolfTPM2_SetAuthHandle
*/
WOLFTPM_API int wolfTPM2_SetAuthSession(WOLFTPM2_DEV* dev, int index,
    WOLFTPM2_SESSION* tpmSession, TPMA_SESSION sessionAttributes);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Updates the Name used in a TPM Session with the Name associated with wolfTPM2 Handle
    \note Typically, this wrapper is used from another wrappers and in very specific use cases. For example, wolfTPM2_NVWriteAuth

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param handle pointer to a populated structure of WOLFTPM2_HANDLE type

    \sa wolfTPM2_SetAuth
    \sa wolfTPM2_SetAuthPassword
    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_SetAuthSession
*/
WOLFTPM_API int wolfTPM2_SetAuthHandleName(WOLFTPM2_DEV* dev, int index, const WOLFTPM2_HANDLE* handle);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Create a TPM session, Policy, HMAC or Trial
    \note This wrapper can also be used to start TPM session for parameter encryption, see wolfTPM nvram or keygen example

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param session pointer to an empty WOLFTPM2_SESSION struct
    \param tpmKey pointer to a WOLFTPM2_KEY that will be used as a salt for the session
    \param bind pointer to a WOLFTPM2_HANDLE that will be used to make the session bounded
    \param sesType byte value, the session type (HMAC, Policy or Trial)
    \param encDecAlg integer value, specifying the algorithm in case of parameter encryption (TPM_ALG_CFB or TPM_ALG_XOR). Any value not CFB or XOR is considered NULL and parameter encryption is disabled.

    \sa wolfTPM2_SetAuthSession
*/
WOLFTPM_API int wolfTPM2_StartSession(WOLFTPM2_DEV* dev,
    WOLFTPM2_SESSION* session, WOLFTPM2_KEY* tpmKey,
    WOLFTPM2_HANDLE* bind, TPM_SE sesType, int encDecAlg);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Creates a TPM session with Policy Secret to satisfy the default EK policy
    \note This wrapper can be used only if the EK authorization is not changed from default

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments
    \return TPM_RC_FAILURE: check TPM return code, check available handles, check TPM IO

    \param dev pointer to a TPM2_DEV struct
    \param tpmSession pointer to an empty WOLFTPM2_SESSION struct

    \sa wolfTPM2_SetAuthSession
    \sa wolfTPM2_StartSession
*/
WOLFTPM_API int wolfTPM2_CreateAuthSession_EkPolicy(WOLFTPM2_DEV* dev,
                                                    WOLFTPM2_SESSION* tpmSession);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Single function to prepare and create a TPM 2.0 Primary Key
    \note TPM 2.0 allows only asymmetric RSA or ECC primary keys. Afterwards, both symmetric and asymmetric keys can be created under a TPM 2.0 Primary Key
    Typically, Primary Keys are used to create Hierarchies of TPM 2.0 Keys.
    The TPM uses a Primary Key to wrap the other keys, signing or decrypting.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param primaryHandle integer value, specifying one of four TPM 2.0 Primary Seeds: TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM or TPM_RH_NULL
    \param publicTemplate pointer to a TPMT_PUBLIC structure populated manually or using one of the wolfTPM2_GetKeyTemplate_... wrappers
    \param auth pointer to a string constant, specifying the password authorization for the Primary Key
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_CreateKey
    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_ECC
*/
WOLFTPM_API int wolfTPM2_CreatePrimaryKey(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* key, TPM_HANDLE primaryHandle, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Change the authorization secret of a TPM 2.0 key
    \note TPM does not allow the authorization secret of a Primary Key to be changed.
    Instead, use wolfTPM2_CreatePrimary to create the same PrimaryKey with a new auth.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param parent pointer to a struct of WOLFTPM2_HANDLE type, specifying a TPM 2.0 Primary Key to be used as the parent(Storage Key)
    \param auth pointer to a string constant, specifying the password authorization of the TPM 2.0 key
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_CreatePrimaryKey
    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_UnloadHandle
*/
WOLFTPM_API int wolfTPM2_ChangeAuthKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    WOLFTPM2_HANDLE* parent, const byte* auth, int authSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Single function to prepare and create a TPM 2.0 Key
    \note This function only creates the key material and stores it into the keyblob argument. To load the key use wolfTPM2_LoadKey

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param keyBlob pointer to an empty struct of WOLFTPM2_KEYBLOB type
    \param parent pointer to a struct of WOLFTPM2_HANDLE type, specifying the a 2.0 Primary Key to be used as the parent(Storage Key)
    \param publicTemplate pointer to a TPMT_PUBLIC structure populated manually or using one of the wolfTPM2_GetKeyTemplate_... wrappers
    \param auth pointer to a string constant, specifying the password authorization for the TPM 2.0 Key
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_LoadKey
    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_ECC
    \sa wolfTPM2_CreatePrimaryKey
*/
WOLFTPM_API int wolfTPM2_CreateKey(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEYBLOB* keyBlob, WOLFTPM2_HANDLE* parent,
    TPMT_PUBLIC* publicTemplate, const byte* auth, int authSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Single function to load a TPM 2.0 key
    \note To load a TPM 2.0 key its parent(Primary Key) should also be loaded prior to this operation. Primary Keys are loaded when they are created.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param keyBlob pointer to a struct of WOLFTPM2_KEYBLOB type
    \param parent pointer to a struct of WOLFTPM2_HANDLE type, specifying a TPM 2.0 Primary Key to be used as the parent(Storage Key)

    \sa wolfTPM2_CreateKey
    \sa wolfTPM2_CreatePrimaryKey
    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_ECC
*/
WOLFTPM_API int wolfTPM2_LoadKey(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEYBLOB* keyBlob, WOLFTPM2_HANDLE* parent);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Single function to create and load a TPM 2.0 Key in one step

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param parent pointer to a struct of WOLFTPM2_HANDLE type, specifying a TPM 2.0 Primary Key to be used as the parent(Storage Key)
    \param publicTemplate pointer to a TPMT_PUBLIC structure populated manually or using one of the wolfTPM2_GetKeyTemplate_... wrappers
    \param auth pointer to a string constant, specifying the password authorization of the TPM 2.0 key
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_CreateKey
    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_ECC
*/
WOLFTPM_API int wolfTPM2_CreateAndLoadKey(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* key, WOLFTPM2_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Creates and loads a key using single TPM 2.0 operation, and stores encrypted private key material

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param keyBlob pointer to an empty struct of WOLFTPM2_KEYBLOB type, contains private key material as encrypted data
    \param parent pointer to a struct of WOLFTPM2_HANDLE type, specifying a TPM 2.0 Primary Key to be used as the parent(Storage Key)
    \param publicTemplate pointer to a TPMT_PUBLIC structure populated manually or using one of the wolfTPM2_GetKeyTemplate_... wrappers
    \param auth pointer to a string constant, specifying the password authorization of the TPM 2.0 key
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_CreateAndLoadKey
    \sa wolfTPM2_CreateKey
    \sa wolfTPM2_LoadKey
*/
WOLFTPM_API int wolfTPM2_CreateLoadedKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEYBLOB* keyBlob,
    WOLFTPM2_HANDLE* parent, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Wrapper to load the public part of an external key
    \note The key must be formatted to the format expected by the TPM, see the 'pub' argument and the alternative wrappers.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param pub pointer to a populated structure of TPM2B_PUBLIC type

    \sa wolfTPM2_LoadRsaPublicKey
    \sa wolfTPM2_LoadEccPublicKey
    \sa wolfTPM2_wolfTPM2_LoadPrivateKey
*/
WOLFTPM_API int wolfTPM2_LoadPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM2B_PUBLIC* pub);

/* Same as wolfTPM2_LoadPublicKey, but adds hierarchy option (default is owner) */
WOLFTPM_API int wolfTPM2_LoadPublicKey_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM2B_PUBLIC* pub, TPM_HANDLE hierarchy);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Single function to import an external private key and load it into the TPM in one step
    \note The private key material needs to be prepared in a format that the TPM expects, see the 'sens' argument

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a struct of WOLFTPM2_HANDLE type (can be NULL for external keys)
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param pub pointer to a populated structure of TPM2B_PUBLIC type
    \param sens pointer to a populated structure of TPM2B_SENSITIVE type

    \sa wolfTPM2_CreateKey
    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_ECC
*/
WOLFTPM_API int wolfTPM2_LoadPrivateKey(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEY* key, const TPM2B_PUBLIC* pub,
    TPM2B_SENSITIVE* sens);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Single function to import an external private key and load it into the TPM in one step
    \note The primary key material needs to be prepared in a format that the TPM expects, see the 'sens' argument

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a struct of WOLFTPM2_HANDLE type (can be NULL for external keys)
    \param keyBlob pointer to an empty struct of WOLFTPM2_KEYBLOB type
    \param pub pointer to a populated structure of TPM2B_PUBLIC type
    \param sens pointer to a populated structure of TPM2B_SENSITIVE type

    \sa wolfTPM2_ImportRsaPrivateKey
    \sa wolfTPM2_ImportEccPrivateKey
*/
WOLFTPM_API int wolfTPM2_ImportPrivateKey(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEYBLOB* keyBlob, const TPM2B_PUBLIC* pub,
    TPM2B_SENSITIVE* sens);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to import the public part of an external RSA key
    \note Recommended for use, because it does not require TPM format of the public part

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param rsaPub pointer to a byte buffer containing the public key material
    \param rsaPubSz integer value of word32 type, specifying the buffer size
    \param exponent integer value of word32 type, specifying the RSA exponent

    \sa wolfTPM2_LoadRsaPublicKey_ex
    \sa wolfTPM2_LoadPublicKey
    \sa wolfTPM2_LoadEccPublicKey
    \sa wolfTPM2_ReadPublicKey
*/
WOLFTPM_API int wolfTPM2_LoadRsaPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* rsaPub, word32 rsaPubSz, word32 exponent);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Advanced helper function to import the public part of an external RSA key
    \note Allows the developer to specify TPM hashing algorithm and RSA scheme

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param rsaPub pointer to a byte buffer containing the public key material
    \param rsaPubSz integer value of word32 type, specifying the buffer size
    \param exponent integer value of word32 type, specifying the RSA exponent
    \param scheme value of TPMI_ALG_RSA_SCHEME type, specifying the RSA scheme
    \param hashAlg value of TPMI_ALG_HASH type, specifying the TPM hashing algorithm

    \sa wolfTPM2_LoadRsaPublicKey
    \sa wolfTPM2_LoadPublicKey
    \sa wolfTPM2_LoadEccPublicKey
    \sa wolfTPM2_ReadPublicKey
*/
WOLFTPM_API int wolfTPM2_LoadRsaPublicKey_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* rsaPub, word32 rsaPubSz, word32 exponent,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Import an external RSA private key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments
    \return BUFFER_E: arguments size is larger than what the TPM buffers allow

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a struct of WOLFTPM2_HANDLE type (can be NULL for external keys and the key will be imported under the OWNER hierarchy)
    \param keyBlob pointer to an empty struct of WOLFTPM2_KEYBLOB type
    \param rsaPub pointer to a byte buffer, containing the public part of the RSA key
    \param rsaPubSz integer value of word32 type, specifying the public part buffer size
    \param exponent integer value of word32 type, specifying the RSA exponent
    \param rsaPriv pointer to a byte buffer, containing the private material of the RSA key
    \param rsaPrivSz integer value of word32 type, specifying the private material buffer size
    \param scheme value of TPMI_ALG_RSA_SCHEME type, specifying the RSA scheme
    \param hashAlg integer value of TPMI_ALG_HASH type, specifying a supported TPM 2.0 hash algorithm

    \sa wolfTPM2_ImportRsaPrivateKeySeed
    \sa wolfTPM2_LoadRsaPrivateKey
    \sa wolfTPM2_LoadRsaPrivateKey_ex
    \sa wolfTPM2_LoadPrivateKey
*/
WOLFTPM_API int wolfTPM2_ImportRsaPrivateKey(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEYBLOB* keyBlob,
    const byte* rsaPub, word32 rsaPubSz, word32 exponent,
    const byte* rsaPriv, word32 rsaPrivSz,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Import an external RSA private key with custom seed

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments
    \return BUFFER_E: arguments size is larger than what the TPM buffers allow

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a struct of WOLFTPM2_HANDLE type (can be NULL for external keys and the key will be imported under the OWNER hierarchy)
    \param keyBlob pointer to an empty struct of WOLFTPM2_KEYBLOB type
    \param rsaPub pointer to a byte buffer, containing the public part of the RSA key
    \param rsaPubSz integer value of word32 type, specifying the public part buffer size
    \param exponent integer value of word32 type, specifying the RSA exponent
    \param rsaPriv pointer to a byte buffer, containing the private material of the RSA key
    \param rsaPrivSz integer value of word32 type, specifying the private material buffer size
    \param scheme value of TPMI_ALG_RSA_SCHEME type, specifying the RSA scheme
    \param hashAlg integer value of TPMI_ALG_HASH type, specifying a supported TPM 2.0 hash algorithm
    \param attributes integer value of TPMA_OBJECT type, can contain one or more attributes, e.g. TPMA_OBJECT_fixedTPM (or 0 to automatically populate)
    \param seedSz Optional (use NULL) or supply a custom seed for KDF
    \param seed Size of the seed (use 32 bytes for SHA2-256)

    \sa wolfTPM2_ImportRsaPrivateKey
    \sa wolfTPM2_LoadRsaPrivateKey
    \sa wolfTPM2_LoadRsaPrivateKey_ex
    \sa wolfTPM2_LoadPrivateKey
*/
WOLFTPM_API int wolfTPM2_ImportRsaPrivateKeySeed(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEYBLOB* keyBlob,
    const byte* rsaPub, word32 rsaPubSz, word32 exponent,
    const byte* rsaPriv, word32 rsaPrivSz,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg,
    TPMA_OBJECT attributes, byte* seed, word32 seedSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to import and load an external RSA private key in one step

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a struct of WOLFTPM2_HANDLE type (can be NULL for external keys and the key will be imported under the OWNER hierarchy)
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param rsaPub pointer to a byte buffer, containing the public part of the RSA key
    \param rsaPubSz integer value of word32 type, specifying the public part buffer size
    \param exponent integer value of word32 type, specifying the RSA exponent
    \param rsaPriv pointer to a byte buffer, containing the private material of the RSA key
    \param rsaPrivSz integer value of word32 type, specifying the private material buffer size

    \sa wolfTPM2_ImportRsaPrivateKey
    \sa wolfTPM2_LoadRsaPrivateKey_ex
    \sa wolfTPM2_LoadPrivateKey
*/
WOLFTPM_API int wolfTPM2_LoadRsaPrivateKey(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEY* key,
    const byte* rsaPub, word32 rsaPubSz, word32 exponent,
    const byte* rsaPriv, word32 rsaPrivSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Advanced helper function to import and load an external RSA private key in one step

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a struct of WOLFTPM2_HANDLE type (can be NULL for external keys and the key will be imported under the OWNER hierarchy)
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param rsaPub pointer to a byte buffer, containing the public part of the RSA key
    \param rsaPubSz integer value of word32 type, specifying the public part buffer size
    \param exponent integer value of word32 type, specifying the RSA exponent
    \param rsaPriv pointer to a byte buffer, containing the private material of the RSA key
    \param rsaPrivSz integer value of word32 type, specifying the private material buffer size
    \param scheme value of TPMI_ALG_RSA_SCHEME type, specifying the RSA scheme
    \param hashAlg value of TPMI_ALG_HASH type, specifying the TPM hashing algorithm

    \sa wolfTPM2_LoadRsaPrivateKey
    \sa wolfTPM2_LoadPrivateKey
    \sa wolfTPM2_ImportRsaPrivateKey
    \sa wolfTPM2_LoadEccPrivateKey
*/
WOLFTPM_API int wolfTPM2_LoadRsaPrivateKey_ex(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEY* key,
    const byte* rsaPub, word32 rsaPubSz, word32 exponent,
    const byte* rsaPriv, word32 rsaPrivSz,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to import the public part of an external ECC key
    \note Recommended for use, because it does not require TPM format of the public part

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param curveId integer value, one of the accepted TPM_ECC_CURVE values
    \param eccPubX pointer to a byte buffer containing the public material of point X
    \param eccPubXSz integer value of word32 type, specifying the point X buffer size
    \param eccPubY pointer to a byte buffer containing the public material of point Y
    \param eccPubYSz integer value of word32 type, specifying the point Y buffer size

    \sa wolfTPM2_LoadPublicKey
    \sa wolfTPM2_LoadRsaPublicKey
    \sa wolfTPM2_ReadPublicKey
    \sa wolfTPM2_LoadEccPrivateKey
*/

WOLFTPM_API int wolfTPM2_LoadEccPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    int curveId, const byte* eccPubX, word32 eccPubXSz,
    const byte* eccPubY, word32 eccPubYSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to import the private material of an external ECC key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a struct of WOLFTPM2_HANDLE type (can be NULL for external keys and the key will be imported under the OWNER hierarchy)
    \param keyBlob pointer to an empty struct of WOLFTPM2_KEYBLOB type
    \param curveId integer value, one of the accepted TPM_ECC_CURVE values
    \param eccPubX pointer to a byte buffer containing the public material of point X
    \param eccPubXSz integer value of word32 type, specifying the point X buffer size
    \param eccPubY pointer to a byte buffer containing the public material of point Y
    \param eccPubYSz integer value of word32 type, specifying the point Y buffer size
    \param eccPriv pointer to a byte buffer containing the private material
    \param eccPrivSz integer value of word32 type, specifying the private material size

    \sa wolfTPM2_ImportEccPrivateKeySeed
    \sa wolfTPM2_LoadEccPrivateKey
    \sa wolfTPM2_LoadEccPrivateKey_ex
    \sa wolfTPM2_LoadPrivateKey
*/
WOLFTPM_API int wolfTPM2_ImportEccPrivateKey(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEYBLOB* keyBlob, int curveId,
    const byte* eccPubX, word32 eccPubXSz,
    const byte* eccPubY, word32 eccPubYSz,
    const byte* eccPriv, word32 eccPrivSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to import the private material of an external ECC key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a struct of WOLFTPM2_HANDLE type (can be NULL for external keys and the key will be imported under the OWNER hierarchy)
    \param keyBlob pointer to an empty struct of WOLFTPM2_KEYBLOB type
    \param curveId integer value, one of the accepted TPM_ECC_CURVE values
    \param eccPubX pointer to a byte buffer containing the public material of point X
    \param eccPubXSz integer value of word32 type, specifying the point X buffer size
    \param eccPubY pointer to a byte buffer containing the public material of point Y
    \param eccPubYSz integer value of word32 type, specifying the point Y buffer size
    \param eccPriv pointer to a byte buffer containing the private material
    \param eccPrivSz integer value of word32 type, specifying the private material size
    \param attributes integer value of TPMA_OBJECT type, can contain one or more attributes, e.g. TPMA_OBJECT_fixedTPM (or 0 to automatically populate)
    \param seedSz Optional (use NULL) or supply a custom seed for KDF
    \param seed Size of the seed (use 32 bytes for SHA2-256)

    \sa wolfTPM2_ImportEccPrivateKey
    \sa wolfTPM2_LoadEccPrivateKey
    \sa wolfTPM2_LoadEccPrivateKey_ex
    \sa wolfTPM2_LoadPrivateKey
*/
WOLFTPM_API int wolfTPM2_ImportEccPrivateKeySeed(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEYBLOB* keyBlob, int curveId,
    const byte* eccPubX, word32 eccPubXSz,
    const byte* eccPubY, word32 eccPubYSz,
    const byte* eccPriv, word32 eccPrivSz,
    TPMA_OBJECT attributes, byte* seed, word32 seedSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to import and load an external ECC private key in one step

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a struct of WOLFTPM2_HANDLE type (can be NULL for external keys and the key will be imported under the OWNER hierarchy)
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param curveId integer value, one of the accepted TPM_ECC_CURVE values
    \param eccPubX pointer to a byte buffer containing the public material of point X
    \param eccPubXSz integer value of word32 type, specifying the point X buffer size
    \param eccPubY pointer to a byte buffer containing the public material of point Y
    \param eccPubYSz integer value of word32 type, specifying the point Y buffer size
    \param eccPriv pointer to a byte buffer containing the private material
    \param eccPrivSz integer value of word32 type, specifying the private material size

    \sa wolfTPM2_ImportEccPrivateKey
    \sa wolfTPM2_LoadEccPublicKey
    \sa wolfTPM2_LoadPrivateKey
*/
WOLFTPM_API int wolfTPM2_LoadEccPrivateKey(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEY* key,
    int curveId, const byte* eccPubX, word32 eccPubXSz,
    const byte* eccPubY, word32 eccPubYSz,
    const byte* eccPriv, word32 eccPrivSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to receive the public part of a loaded TPM object using its handle
    \note The public part of a TPM symmetric keys contains just TPM meta data

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param handle integer value of TPM_HANDLE type, specifying handle of a loaded TPM object

    \sa wolfTPM2_LoadRsaPublicKey
    \sa wolfTPM2_LoadEccPublicKey
    \sa wolfTPM2_LoadPublicKey
*/
WOLFTPM_API int wolfTPM2_ReadPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM_HANDLE handle);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Using this wrapper a secret can be sealed inside a TPM 2.0 Key
    \note The secret size can not be larger than 128 bytes

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param keyBlob pointer to an empty struct of WOLFTPM2_KEYBLOB type
    \param parent pointer to a struct of WOLFTPM2_HANDLE type, specifying the a 2.0 Primary Key to be used as the parent(Storage Key)
    \param publicTemplate pointer to a TPMT_PUBLIC structure populated using one of the wolfTPM2_GetKeyTemplate_KeySeal
    \param auth pointer to a string constant, specifying the password authorization for the TPM 2.0 Key
    \param authSz integer value, specifying the size of the password authorization, in bytes
    \param sealData pointer to a byte buffer, containing the secret(user data) to be sealed
    \param sealSize integer value, specifying the size of the seal buffer, in bytes

    \sa wolfTPM2_GetKeyTemplate_KeySeal
    \sa TPM2_Unseal
    \sa wolfTPM2_CreatePrimary
*/
WOLFTPM_API int wolfTPM2_CreateKeySeal(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEYBLOB* keyBlob, WOLFTPM2_HANDLE* parent,
    TPMT_PUBLIC* publicTemplate, const byte* auth, int authSz,
    const byte* sealData, int sealSize);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Using this wrapper a secret can be sealed inside a TPM 2.0 Key with pcr selection
    \note The secret size can not be larger than 128 bytes

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a WOLFTPM2_DEV struct
    \param keyBlob pointer to an empty struct of WOLFTPM2_KEYBLOB type
    \param parent pointer to a struct of WOLFTPM2_HANDLE type, specifying the a 2.0 Primary Key to be used as the parent(Storage Key)
    \param publicTemplate pointer to a TPMT_PUBLIC structure populated using one of the wolfTPM2_GetKeyTemplate_KeySeal
    \param auth pointer to a string constant, specifying the password authorization for the TPM 2.0 Key
    \param authSz integer value, specifying the size of the password authorization, in bytes
    \param pcrAlg hash algorithm to use when calculating pcr digest
    \param pcrArray optional array of pcrs to be used when creating the tpm object
    \param pcrArraySz length of the pcrArray
    \param sealData pointer to a byte buffer, containing the secret(user data) to be sealed
    \param sealSize integer value, specifying the size of the seal buffer, in bytes

    \sa wolfTPM2_GetKeyTemplate_KeySeal
    \sa TPM2_Unseal
    \sa wolfTPM2_CreatePrimary
*/
WOLFTPM_API int wolfTPM2_CreateKeySeal_ex(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEYBLOB* keyBlob, WOLFTPM2_HANDLE* parent,
    TPMT_PUBLIC* publicTemplate, const byte* auth, int authSz,
    TPM_ALG_ID pcrAlg, byte* pcrArray, word32 pcrArraySz,
    const byte* sealData, int sealSize);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to generate a hash of the public area of an object in the format expected by the TPM
    \note Computed TPM name includes hash of the TPM_ALG_ID and the public are of the object

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param pub pointer to a populated structure of TPM2B_PUBLIC type, containing the public area of a TPM object
    \param out pointer to an empty struct of TPM2B_NAME type, to store the computed name

    \sa wolfTPM2_ImportPrivateKey
*/
WOLFTPM_API int wolfTPM2_ComputeName(const TPM2B_PUBLIC* pub, TPM2B_NAME* out);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to convert TPM2B_SENSITIVE to TPM2B_PRIVATE

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param sens pointer to a correctly populated structure of TPM2B_SENSITIVE type
    \param priv pointer to an empty struct of TPM2B_PRIVATE type
    \param nameAlg integer value of TPMI_ALG_HASH type, specifying a valid TPM2 hashing algorithm
    \param name pointer to a TPM2B_NAME structure
    \param parentKey pointer to a WOLFTPM2_KEY structure, specifying a parentKey, if it exists
    \param sym pointer to a structure of TPMT_SYM_DEF_OBJECT type
    \param symSeed pointer to a structure of derived secret (RSA=random, ECC=ECDHE)

    \sa wolfTPM2_ImportPrivateKey
*/
WOLFTPM_API int wolfTPM2_SensitiveToPrivate(TPM2B_SENSITIVE* sens, TPM2B_PRIVATE* priv,
    TPMI_ALG_HASH nameAlg, TPM2B_NAME* name, const WOLFTPM2_KEY* parentKey,
    TPMT_SYM_DEF_OBJECT* sym, TPM2B_DATA* symSeed);

#ifndef WOLFTPM2_NO_WOLFCRYPT
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to import PEM/DER or RSA/ECC private key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param keyType The type of key (TPM_ALG_RSA or TPM_ALG_ECC)
    \param parentKey pointer to a WOLFTPM2_KEY struct, pointing to a Primary Key or TPM Hierarchy
    \param keyBlob pointer to a struct of WOLFTPM2_KEYBLOB type, to import the private key to
    \param encodingType ENCODING_TYPE_PEM or ENCODING_TYPE_ASN1 (DER)
    \param input buffer holding the rsa pem
    \param inSz length of the input pem buffer
    \param pass optional password of the key
    \param objectAttributes integer value of TPMA_OBJECT type, can contain one or more attributes, e.g. TPMA_OBJECT_fixedTPM
    \param seedSz Optional (use NULL) or supply a custom seed for KDF
    \param seed Size of the seed (use 32 bytes for SHA2-256)
*/
WOLFTPM_API int wolfTPM2_ImportPrivateKeyBuffer(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, int keyType, WOLFTPM2_KEYBLOB* keyBlob,
    int encodingType, const char* input, word32 inSz, const char* pass,
    TPMA_OBJECT objectAttributes, byte* seed, word32 seedSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to import PEM/DER formatted RSA/ECC public key

    \return TPM_RC_SUCCESS: successful - populates key->pub
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param keyType The type of key (TPM_ALG_RSA or TPM_ALG_ECC)
    \param key pointer to a struct of WOLFTPM2_KEY type, to import the public key to
    \param encodingType ENCODING_TYPE_PEM or ENCODING_TYPE_ASN1 (DER)
    \param input buffer holding the rsa pem
    \param inSz length of the input pem buffer
    \param objectAttributes integer value of OR'd TPMA_OBJECT_* types
*/
WOLFTPM_API int wolfTPM2_ImportPublicKeyBuffer(WOLFTPM2_DEV* dev, int keyType,
    WOLFTPM2_KEY* key, int encodingType, const char* input, word32 inSz,
    TPMA_OBJECT objectAttributes);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to export a TPM RSA/ECC public key with PEM/DER formatting

    \return TPM_RC_SUCCESS: successful - populates key->pub
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BUFFER_E: insufficient space in provided buffer
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param tpmKey pointer to a WOLFTPM2_KEY with populated key
    \param encodingType ENCODING_TYPE_PEM or ENCODING_TYPE_ASN1 (DER)
    \param out buffer to export public key
    \param outSz pointer to length of the out buffer
*/
WOLFTPM_API int wolfTPM2_ExportPublicKeyBuffer(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    int encodingType, byte* out, word32* outSz);

#ifndef NO_RSA
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to import Der rsa key directly

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a WOLFTPM2_KEY struct, pointing to a Primary Key or TPM Hierarchy
    \param keyBlob pointer to a struct of WOLFTPM2_KEYBLOB type, to import the rsa key to
    \param input buffer holding the rsa der
    \param inSz length of the input der buffer
    \param scheme value of TPMI_ALG_RSA_SCHEME type, specifying the RSA scheme
    \param hashAlg value of TPMI_ALG_HASH type, specifying the TPM hashing algorithm
*/
WOLFTPM_API int wolfTPM2_RsaPrivateKeyImportDer(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEYBLOB* keyBlob, const byte* input,
    word32 inSz, TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to import Pem rsa key directly

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a WOLFTPM2_KEY struct, pointing to a Primary Key or TPM Hierarchy
    \param keyBlob pointer to a struct of WOLFTPM2_KEYBLOB type, to import the rsa key to
    \param input buffer holding the rsa pem
    \param inSz length of the input pem buffer
    \param pass optional password of the key
    \param scheme value of TPMI_ALG_RSA_SCHEME type, specifying the RSA scheme
    \param hashAlg value of TPMI_ALG_HASH type, specifying the TPM hashing algorithm
*/
WOLFTPM_API int wolfTPM2_RsaPrivateKeyImportPem(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, WOLFTPM2_KEYBLOB* keyBlob,
    const char* input, word32 inSz, char* pass,
    TPMI_ALG_RSA_SCHEME scheme, TPMI_ALG_HASH hashAlg);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Extract a RSA TPM key and convert it to a wolfcrypt key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param tpmKey pointer to a struct of WOLFTPM2_KEY type, holding a TPM key
    \param wolfKey pointer to an empty struct of RsaKey type, to store the converted key

    \sa wolfTPM2_RsaKey_WolfToTpm
    \sa wolfTPM2_RsaKey_WolfToTpm_ex
*/
WOLFTPM_API int wolfTPM2_RsaKey_TpmToWolf(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    RsaKey* wolfKey);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Convert a public RSA TPM key to PEM format public key.
    Note: This API is a wrapper around wolfTPM2_ExportPublicKeyBuffer

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param keyBlob pointer to a struct of WOLFTPM2_KEY type, holding a TPM key
    \param pem pointer to an array of byte type, used as temporary storage for PEM conversation
    \param pemSz pointer to integer variable, to store the used buffer size

    \sa wolfTPM2_ExportPublicKeyBuffer
    \sa wolfTPM2_RsaKey_TpmToWolf
    \sa wolfTPM2_RsaKey_WolfToTpm
*/
WOLFTPM_API int wolfTPM2_RsaKey_TpmToPemPub(WOLFTPM2_DEV* dev,
                                         WOLFTPM2_KEY* keyBlob,
                                         byte* pem, word32* pemSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Import a RSA wolfcrypt key into the TPM
    \note Allows the use of externally generated keys by wolfcrypt to be used with TPM 2.0

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param wolfKey pointer to a struct of RsaKey type, holding a wolfcrypt key
    \param tpmKey pointer to an empty struct of WOLFTPM2_KEY type, to hold the imported TPM key

    \sa wolfTPM2_RsaKey_TpmToWolf
*/
WOLFTPM_API int wolfTPM2_RsaKey_WolfToTpm(WOLFTPM2_DEV* dev, RsaKey* wolfKey,
    WOLFTPM2_KEY* tpmKey);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Import a RSA wolfcrypt key into the TPM under a specific Primary Key or Hierarchy
    \note Allows the use of wolfcrypt generated keys with wolfTPM

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a WOLFTPM2_KEY struct, pointing to a Primary Key or TPM Hierarchy
    \param wolfKey pointer to a struct of RsaKey type, holding a wolfcrypt key
    \param tpmKey pointer to an empty struct of WOLFTPM2_KEY type, to hold the imported TPM key

    \sa wolfTPM2_RsaKey_WolfToTpm
    \sa wolfTPM2_RsaKey_TpmToWolf
*/
WOLFTPM_API int wolfTPM2_RsaKey_WolfToTpm_ex(WOLFTPM2_DEV* dev,
    const WOLFTPM2_KEY* parentKey, RsaKey* wolfKey, WOLFTPM2_KEY* tpmKey);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Import a PEM format public key from a file into the TPM

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)

    \param dev pointer to a TPM2_DEV struct
    \param tpmKey pointer to an empty struct of WOLFTPM2_KEY type, to hold the imported TPM key
    \param pem pointer to an array of byte type, containing a PEM formatted public key material
    \param pemSz pointer to integer variable, specifying the size of PEM key data

    \sa wolfTPM2_RsaKey_WolfToTpm
    \sa wolfTPM2_RsaKey_TpmToPem
    \sa wolfTPM2_RsaKey_TpmToWolf
*/
WOLFTPM_API int wolfTPM2_RsaKey_PubPemToTpm(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* tpmKey, const byte* pem, word32 pemSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Import DER RSA private or public key into TPM public and sensitive structures. This does not make any calls to TPM hardware.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)

    \param der The der encoding of the content of the extension.
    \param derSz The size in bytes of the der encoding.
    \param pub pointer to a populated structure of TPM2B_PUBLIC type
    \param sens pointer to a populated structure of TPM2B_SENSITIVE type
    \param attributes integer value of TPMA_OBJECT type, can contain one or more attributes, e.g. TPMA_OBJECT_fixedTPM (or 0 to automatically populate)

    \sa wolfTPM2_ImportPublicKeyBuffer
    \sa wolfTPM2_ImportPrivateKeyBuffer
    \sa wolfTPM2_DecodeEccDer
*/
WOLFTPM_API int wolfTPM2_DecodeRsaDer(const byte* der, word32 derSz,
    TPM2B_PUBLIC* pub, TPM2B_SENSITIVE* sens, TPMA_OBJECT attributes);
#endif /* !NO_RSA */

#ifdef HAVE_ECC
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Extract a ECC TPM key and convert to to a wolfcrypt key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param tpmKey pointer to a struct of WOLFTPM2_KEY type, holding a TPM key
    \param wolfKey pointer to an empty struct of ecc_key type, to store the converted key

    \sa wolfTPM2_EccKey_WolfToTpm
    \sa wolfTPM2_EccKey_WolfToTpm_ex
*/
WOLFTPM_API int wolfTPM2_EccKey_TpmToWolf(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* tpmKey,
    ecc_key* wolfKey);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Import a ECC wolfcrypt key into the TPM
    \note Allows the use of externally generated keys by wolfcrypt to be used with TPM 2.0

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param wolfKey pointer to a struct of ecc_key type, holding a wolfcrypt key
    \param tpmKey pointer to an empty struct of WOLFTPM2_KEY type, to hold the imported TPM key

    \sa wolfTPM2_EccKey_TpmToWolf
*/
WOLFTPM_API int wolfTPM2_EccKey_WolfToTpm(WOLFTPM2_DEV* dev, ecc_key* wolfKey,
    WOLFTPM2_KEY* tpmKey);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Import ECC wolfcrypt key into the TPM under a specific Primary Key or Hierarchy
    \note Allows the use of wolfcrypt generated keys with wolfTPM

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a WOLFTPM2_KEY struct, pointing to a Primary Key or TPM Hierarchy
    \param wolfKey pointer to a struct of ecc_key type, holding a wolfcrypt key
    \param tpmKey pointer to an empty struct of WOLFTPM2_KEY type, to hold the imported TPM key

    \sa wolfTPM2_EccKey_WolfToTPM
    \sa wolfTPM2_EccKey_TpmToWolf
*/
WOLFTPM_API int wolfTPM2_EccKey_WolfToTpm_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* parentKey,
    ecc_key* wolfKey, WOLFTPM2_KEY* tpmKey);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Import a ECC public key generated from wolfcrypt key into the TPM
    \note Allows the use of externally generated public ECC key by wolfcrypt to be used with TPM 2.0

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param wolfKey pointer to a struct of ecc_key type, holding a wolfcrypt public ECC key
    \param pubPoint pointer to an empty struct of TPM2B_ECC_POINT type

    \sa wolfTPM2_EccKey_TpmToWolf
*/
WOLFTPM_API int wolfTPM2_EccKey_WolfToPubPoint(WOLFTPM2_DEV* dev, ecc_key* wolfKey,
    TPM2B_ECC_POINT* pubPoint);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Import DER ECC private or public key into TPM public and sensitive structures. This does not make any calls to TPM hardware.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)

    \param der The der encoding of the content of the extension.
    \param derSz The size in bytes of the der encoding.
    \param pub pointer to a populated structure of TPM2B_PUBLIC type
    \param sens pointer to a populated structure of TPM2B_SENSITIVE type
    \param attributes integer value of TPMA_OBJECT type, can contain one or more attributes, e.g. TPMA_OBJECT_fixedTPM (or 0 to automatically populate)

    \sa wolfTPM2_ImportPublicKeyBuffer
    \sa wolfTPM2_ImportPrivateKeyBuffer
    \sa wolfTPM2_DecodeRsaDer
*/
WOLFTPM_API int wolfTPM2_DecodeEccDer(const byte* der, word32 derSz,
    TPM2B_PUBLIC* pub, TPM2B_SENSITIVE* sens, TPMA_OBJECT attributes);
#endif /* HAVE_ECC */
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to sign arbitrary data using a TPM key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a struct of WOLFTPM2_KEY type, holding a TPM key material
    \param digest pointer to a byte buffer, containing the arbitrary data
    \param digestSz integer value, specifying the size of the digest buffer, in bytes
    \param sig pointer to a byte buffer, containing the generated signature
    \param sigSz integer value, specifying the size of the signature buffer, in bytes

    \sa wolfTPM2_VerifyHash
    \sa wolfTPM2_SignHashScheme
    \sa wolfTPM2_VerifyHashScheme
*/
WOLFTPM_API int wolfTPM2_SignHash(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* digest, int digestSz, byte* sig, int* sigSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Advanced helper function to sign arbitrary data using a TPM key, and specify the signature scheme and hashing algorithm

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a struct of WOLFTPM2_KEY type, holding a TPM key material
    \param digest pointer to a byte buffer, containing the arbitrary data
    \param digestSz integer value, specifying the size of the digest buffer, in bytes
    \param sig pointer to a byte buffer, containing the generated signature
    \param sigSz integer value, specifying the size of the signature buffer, in bytes
    \param sigAlg integer value of TPMI_ALG_SIG_SCHEME type, specifying a supported TPM 2.0 signature scheme
    \param hashAlg integer value of TPMI_ALG_HASH type, specifying a supported TPM 2.0 hash algorithm

    \sa wolfTPM2_SignHash
    \sa wolfTPM2_VerifyHash
    \sa wolfTPM2_VerifyHashScheme
*/
WOLFTPM_API int wolfTPM2_SignHashScheme(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* digest, int digestSz, byte* sig, int* sigSz,
    TPMI_ALG_SIG_SCHEME sigAlg, TPMI_ALG_HASH hashAlg);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to verify a TPM generated signature

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a struct of WOLFTPM2_KEY type, holding a TPM 2.0 key material
    \param sig pointer to a byte buffer, containing the generated signature
    \param sigSz integer value, specifying the size of the signature buffer, in bytes
    \param digest pointer to a byte buffer, containing the signed data
    \param digestSz integer value, specifying the size of the digest buffer, in bytes

    \sa wolfTPM2_SignHash
    \sa wolfTPM2_SignHashScheme
    \sa wolfTPM2_VerifyHashScheme
    \sa wolfTPM2_VerifyHash_ex
*/
WOLFTPM_API int wolfTPM2_VerifyHash(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to verify a TPM generated signature

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a struct of WOLFTPM2_KEY type, holding a TPM 2.0 key material
    \param sig pointer to a byte buffer, containing the generated signature
    \param sigSz integer value, specifying the size of the signature buffer, in bytes
    \param digest pointer to a byte buffer, containing the signed data
    \param digestSz integer value, specifying the size of the digest buffer, in bytes
    \param hashAlg hash algorithm used to sign

    \sa wolfTPM2_SignHash
    \sa wolfTPM2_SignHashScheme
    \sa wolfTPM2_VerifyHashScheme
*/
WOLFTPM_API int wolfTPM2_VerifyHash_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz,
    int hashAlg);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Advanced helper function to verify a TPM generated signature

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a struct of WOLFTPM2_KEY type, holding a TPM 2.0 key material
    \param sig pointer to a byte buffer, containing the generated signature
    \param sigSz integer value, specifying the size of the signature buffer, in bytes
    \param digest pointer to a byte buffer, containing the signed data
    \param digestSz integer value, specifying the size of the digest buffer, in bytes
    \param sigAlg integer value of TPMI_ALG_SIG_SCHEME type, specifying a supported TPM 2.0 signature scheme
    \param hashAlg integer value of TPMI_ALG_HASH type, specifying a supported TPM 2.0 hash algorithm

    \sa wolfTPM2_SignHash
    \sa wolfTPM2_SignHashScheme
    \sa wolfTPM2_VerifyHash
*/
WOLFTPM_API int wolfTPM2_VerifyHashScheme(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* sig, int sigSz, const byte* digest, int digestSz,
    TPMI_ALG_SIG_SCHEME sigAlg, TPMI_ALG_HASH hashAlg);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Advanced helper function to verify a TPM generated signature and return ticket

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a struct of WOLFTPM2_KEY type, holding a TPM 2.0 key material
    \param sig pointer to a byte buffer, containing the generated signature
    \param sigSz integer value, specifying the size of the signature buffer, in bytes
    \param digest pointer to a byte buffer, containing the signed data
    \param digestSz integer value, specifying the size of the digest buffer, in bytes
    \param sigAlg integer value of TPMI_ALG_SIG_SCHEME type, specifying a supported TPM 2.0 signature scheme
    \param hashAlg integer value of TPMI_ALG_HASH type, specifying a supported TPM 2.0 hash algorithm
    \param checkTicket returns the validation ticket proving the signature for digest was checked

    \sa wolfTPM2_VerifyHashScheme
    \sa wolfTPM2_VerifyHashTicket
    \sa wolfTPM2_VerifyHash
*/
WOLFTPM_API int wolfTPM2_VerifyHashTicket(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* key, const byte* sig, int sigSz, const byte* digest,
    int digestSz, TPMI_ALG_SIG_SCHEME sigAlg, TPMI_ALG_HASH hashAlg,
    TPMT_TK_VERIFIED* checkTicket);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Generates and then loads a ECC key-pair with NULL hierarchy for Diffie-Hellman exchange

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param ecdhKey pointer to an empty structure of WOLFTPM2_KEY type
    \param curve_id integer value, specifying a valid TPM_ECC_CURVE value
    \param auth pointer to a string constant, specifying the password authorization for the TPM 2.0 Key
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_ECDHGen
    \sa wolfTPM2_ECDHGenZ
    \sa wolfTPM2_ECDHEGenKey
    \sa wolfTPM2_ECDHEGenZ
*/
WOLFTPM_API int wolfTPM2_ECDHGenKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* ecdhKey,
    int curve_id, const byte* auth, int authSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Generates ephemeral key and computes Z (shared secret)
    \note One shot API using private key handle to generate key-pair and return public point and shared secret

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param privKey pointer to a structure of WOLFTPM2_KEY type
    \param pubPoint pointer to an empty structure of TPM2B_ECC_POINT type
    \param out pointer to a byte buffer, to store the generated shared secret
    \param outSz integer value, specifying the size of the shared secret, in bytes

    \sa wolfTPM2_ECDHGenZ
    \sa wolfTPM2_ECDHGenKey
    \sa wolfTPM2_ECDHEGenKey
    \sa wolfTPM2_ECDHEGenZ
*/
WOLFTPM_API int wolfTPM2_ECDHGen(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* privKey,
    TPM2B_ECC_POINT* pubPoint, byte* out, int* outSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Computes Z (shared secret) using pubPoint and loaded private ECC key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param privKey pointer to a structure of WOLFTPM2_KEY type, containing a valid TPM handle
    \param pubPoint pointer to a populated structure of TPM2B_ECC_POINT type
    \param out pointer to a byte buffer, to store the computed shared secret
    \param outSz integer value, specifying the size of the shared secret, in bytes

    \sa wolfTPM2_ECDHGen
    \sa wolfTPM2_ECDHGenKey
    \sa wolfTPM2_ECDHEGenKey
    \sa wolfTPM2_ECDHEGenZ
*/
WOLFTPM_API int wolfTPM2_ECDHGenZ(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* privKey,
    const TPM2B_ECC_POINT* pubPoint, byte* out, int* outSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Generates ephemeral ECC key and returns array index (2 phase method)
    \note One time use key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param ecdhKey pointer to an empty structure of WOLFTPM2_KEY type
    \param curve_id integer value, specifying a valid TPM_ECC_CURVE value

    \sa wolfTPM2_ECDHEGenZ
    \sa wolfTPM2_ECDHGen
    \sa wolfTPM2_ECDHGenKey
    \sa wolfTPM2_ECDHGenZ
*/
WOLFTPM_API int wolfTPM2_ECDHEGenKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* ecdhKey,
    int curve_id);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Computes Z (shared secret) using pubPoint and counter (2 phase method)
    \note The counter, array ID, can only be used one time

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parentKey pointer to a structure of WOLFTPM2_KEY type, containing a valid TPM handle of a primary key
    \param ecdhKey pointer to a structure of WOLFTPM2_KEY type, containing a valid TPM handle
    \param pubPoint pointer to an empty struct of TPM2B_ECC_POINT type
    \param out pointer to a byte buffer, to store the computed shared secret
    \param outSz integer value, specifying the size of the shared secret, in bytes

    \sa wolfTPM2_ECDHEGenKey
    \sa wolfTPM2_ECDHGen
    \sa wolfTPM2_ECDHGenKey
    \sa wolfTPM2_ECDHGenZ
*/
WOLFTPM_API int wolfTPM2_ECDHEGenZ(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* parentKey,
    WOLFTPM2_KEY* ecdhKey, const TPM2B_ECC_POINT* pubPoint,
    byte* out, int* outSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Perform RSA encryption using a TPM 2.0 key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a struct of WOLFTPM2_KEY type, holding a TPM key material
    \param padScheme integer value of TPM_ALG_ID type, specifying the padding scheme
    \param msg pointer to a byte buffer, containing the arbitrary data for encryption
    \param msgSz integer value, specifying the size of the arbitrary data buffer
    \param out pointer to a byte buffer, where the encrypted data will be stored
    \param outSz integer value, specifying the size of the encrypted data buffer

    \sa wolfTPM2_RsaDecrypt
*/
WOLFTPM_API int wolfTPM2_RsaEncrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_ALG_ID padScheme, const byte* msg, int msgSz, byte* out, int* outSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Perform RSA decryption using a TPM 2.0 key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a struct of WOLFTPM2_KEY type, holding a TPM key material
    \param padScheme integer value of TPM_ALG_ID type, specifying the padding scheme
    \param in pointer to a byte buffer, containing the encrypted data
    \param inSz integer value, specifying the size of the encrypted data buffer
    \param msg pointer to a byte buffer, containing the decrypted data
    \param[in,out] msgSz pointer to size of the encrypted data buffer, on return set actual size

    \sa wolfTPM2_RsaEncrypt
*/
WOLFTPM_API int wolfTPM2_RsaDecrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_ALG_ID padScheme, const byte* in, int inSz, byte* msg, int* msgSz);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Read the values of a specified TPM 2.0 Platform Configuration Registers(PCR)
    \note Make sure to specify the correct hashing algorithm, because there are two sets of PCR registers, one for SHA256 and the other for SHA1(deprecated, but still possible to be read)

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param pcrIndex integer value, specifying a valid PCR index, between 0 and 23 (TPM locality could have an impact on successful access)
    \param hashAlg integer value, specifying a TPM_ALG_SHA256 or TPM_ALG_SHA1 registers to be accessed
    \param digest pointer to a byte buffer, where the PCR values will be stored
    \param[in,out] pDigestLen pointer to an integer variable, where the size of the digest buffer will be stored

    \sa wolfTPM2_ExtendPCR
*/
WOLFTPM_API int wolfTPM2_ReadPCR(WOLFTPM2_DEV* dev,
    int pcrIndex, int hashAlg, byte* digest, int* pDigestLen);

WOLFTPM_API int wolfTPM2_ResetPCR(WOLFTPM2_DEV* dev, int pcrIndex);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Extend a PCR register with a user provided digest
    \note Make sure to specify the correct hashing algorithm

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param pcrIndex integer value, specifying a valid PCR index, between 0 and 23 (TPM locality could have an impact on successful access)
    \param hashAlg integer value, specifying a TPM_ALG_SHA256 or TPM_ALG_SHA1 registers to be accessed
    \param digest pointer to a byte buffer, containing the digest value to be extended into the PCR
    \param digestLen the size of the digest buffer

    \sa wolfTPM2_ReadPCR
*/
WOLFTPM_API int wolfTPM2_ExtendPCR(WOLFTPM2_DEV* dev, int pcrIndex, int hashAlg,
    const byte* digest, int digestLen);

/* Newer API's that use WOLFTPM2_NV context and support auth */

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Creates a new NV Index to be later used for storing data into the TPM's NVRAM
    \note This is a wolfTPM2 wrapper around TPM2_NV_DefineSpace

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parent pointer to a WOLFTPM2_HANDLE, specifying the TPM hierarchy for the new NV Index
    \param nv pointer to an empty structure of WOLFTPM2_NV type, to hold the new NV Index
    \param nvIndex integer value, holding the NV Index Handle given by the TPM upon success
    \param nvAttributes integer value, use wolfTPM2_GetNvAttributesTemplate to create correct value
    \param maxSize integer value, specifying the maximum number of bytes written at this NV Index
    \param auth pointer to a string constant, specifying the password authorization for this NV Index
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_NVWriteAuth
    \sa wolfTPM2_NVReadAuth
    \sa wolfTPM2_NVDeleteAuth
    \sa wolfTPM2_NVOpen
*/
WOLFTPM_API int wolfTPM2_NVCreateAuth(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* parent,
    WOLFTPM2_NV* nv, word32 nvIndex, word32 nvAttributes, word32 maxSize,
    const byte* auth, int authSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Stores user data to a NV Index, at a given offset
    \note User data size should be less or equal to the NV Index maxSize specified using wolfTPM2_CreateAuth

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param nv pointer to a populated structure of WOLFTPM2_NV type
    \param nvIndex integer value, holding an existing NV Index Handle value
    \param dataBuf pointer to a byte buffer, containing the user data to be written to the TPM's NVRAM
    \param dataSz integer value, specifying the size of the user data buffer, in bytes
    \param offset integer value of word32 type, specifying the offset from the NV Index memory start, can be zero

    \sa wolfTPM2_NVReadAuth
    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_NVDeleteAuth
*/
WOLFTPM_API int wolfTPM2_NVWriteAuth(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    word32 nvIndex, byte* dataBuf, word32 dataSz, word32 offset);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Reads user data from a NV Index, starting at the given offset
    \note User data size should be less or equal to the NV Index maxSize specified using wolfTPM2_CreateAuth

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param nv pointer to a populated structure of WOLFTPM2_NV type
    \param nvIndex integer value, holding an existing NV Index Handle value
    \param dataBuf pointer to an empty byte buffer, used to store the read data from the TPM's NVRAM
    \param pDataSz pointer to an integer variable, used to store the size of the data read from NVRAM, in bytes
    \param offset integer value of word32 type, specifying the offset from the NV Index memory start, can be zero

    \sa wolfTPM2_NVWriteAuth
    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_NVDeleteAuth
*/
WOLFTPM_API int wolfTPM2_NVReadAuth(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    word32 nvIndex, byte* dataBuf, word32* pDataSz, word32 offset);

WOLFTPM_API int wolfTPM2_NVReadCert(WOLFTPM2_DEV* dev, TPM_HANDLE handle,
    uint8_t* buffer, uint32_t* len);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Increments an NV one-way counter

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param nv pointer to a populated structure of WOLFTPM2_NV type

    \sa wolfTPM2_NVOpen
    \sa wolfTPM2_NVCreateAuth
*/
WOLFTPM_API int wolfTPM2_NVIncrement(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Open an NV and populate the required authentication and name hash.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param nv pointer to an empty structure of WOLFTPM2_NV type, to hold the new NV Index
    \param nvIndex integer value, holding the NV Index Handle given by the TPM upon success
    \param auth pointer to a string constant, specifying the password authorization for this NV Index
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_UnloadHandle
*/
WOLFTPM_API int wolfTPM2_NVOpen(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    word32 nvIndex, const byte* auth, word32 authSz);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Lock writes on the specified NV Index

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param nv pointer to an structure of WOLFTPM2_NV type loaded using wolfTPM2_NVOpen

    \sa wolfTPM2_NVOpen
    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_NVWriteAuth
    \sa wolfTPM2_NVReadAuth
*/
WOLFTPM_API int wolfTPM2_NVWriteLock(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Destroys an existing NV Index

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param parent pointer to a WOLFTPM2_HANDLE, specifying the TPM hierarchy for the new NV Index
    \param nvIndex integer value, holding the NV Index Handle given by the TPM upon success

    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_NVWriteAuth
    \sa wolfTPM2_NVReadAuth
*/
WOLFTPM_API int wolfTPM2_NVDeleteAuth(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* parent,
    word32 nvIndex);

/* older API's with improper auth support, kept only for backwards compatibility */
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Deprecated, use newer API

    \sa wolfTPM2_NVCreateAuth
*/
WOLFTPM_API int wolfTPM2_NVCreate(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, word32 nvAttributes, word32 maxSize, const byte* auth, int authSz);
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Deprecated, use newer API

    \sa wolfTPM2_NVWriteAuth
*/
WOLFTPM_API int wolfTPM2_NVWrite(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, byte* dataBuf, word32 dataSz, word32 offset);
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Deprecated, use newer API

    \sa wolfTPM2_NVReadAuth
*/
WOLFTPM_API int wolfTPM2_NVRead(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, byte* dataBuf, word32* dataSz, word32 offset);
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Deprecated, use newer API

    \sa wolfTPM2_NVDeleteAuth
*/
WOLFTPM_API int wolfTPM2_NVDelete(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Extracts the public information about an nvIndex, such as maximum size

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param nvIndex integer value, holding the NV Index Handle given by the TPM upon success
    \param nvPublic pointer to a TPMS_NV_PUBLIC, used to store the extracted nvIndex public information

    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_NVDeleteAuth
    \sa wolfTPM2_NVWriteAuth
    \sa wolfTPM2_NVReadAuth
*/
WOLFTPM_API int wolfTPM2_NVReadPublic(WOLFTPM2_DEV* dev, word32 nvIndex,
    TPMS_NV_PUBLIC* nvPublic);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to store a TPM 2.0 Key into the TPM's NVRAM

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param primaryHandle integer value, specifying a TPM 2.0 Hierarchy. typically TPM_RH_OWNER
    \param key pointer to a structure of WOLFTPM2_KEY type, containing the TPM 2.0 key for storing
    \param persistentHandle integer value, specifying an existing nvIndex

    \sa wolfTPM2_NVDeleteKey
    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_NVDeleteAuth
*/
WOLFTPM_API int wolfTPM2_NVStoreKey(WOLFTPM2_DEV* dev, TPM_HANDLE primaryHandle,
    WOLFTPM2_KEY* key, TPM_HANDLE persistentHandle);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to delete a TPM 2.0 Key from the TPM's NVRAM

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param primaryHandle integer value, specifying a TPM 2.0 Hierarchy. typically TPM_RH_OWNER
    \param key pointer to a structure of WOLFTPM2_KEY type, containing the nvIndex handle value

    \sa wolfTPM2_NVDeleteKey
    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_NVDeleteAuth
*/
WOLFTPM_API int wolfTPM2_NVDeleteKey(WOLFTPM2_DEV* dev, TPM_HANDLE primaryHandle,
    WOLFTPM2_KEY* key);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Get the wolfcrypt RNG instance used for wolfTPM
    \note Only if wolfcrypt is enabled and configured for use instead of the TPM RNG

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct

    \sa wolfTPM2_GetRandom
*/
WOLFTPM_API struct WC_RNG* wolfTPM2_GetRng(WOLFTPM2_DEV* dev);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Get a set of random number, generated with the TPM RNG or wolfcrypt RNG
    \note Define WOLFTPM2_USE_HW_RNG to use the TPM RNG source

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param buf pointer to a byte buffer, used to store the generated random numbers
    \param len integer value of word32 type, used to store the size of the buffer, in bytes

    \sa wolfTPM2_GetRandom
*/
WOLFTPM_API int wolfTPM2_GetRandom(WOLFTPM2_DEV* dev, byte* buf, word32 len);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Use to discard any TPM loaded object

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param handle pointer to a structure of WOLFTPM2_HANDLE type, with a valid TPM 2.0 handle value

    \sa wolfTPM2_Clear
*/
WOLFTPM_API int wolfTPM2_UnloadHandle(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* handle);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Deinitializes wolfTPM and wolfcrypt(if enabled)

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct

    \sa wolfTPM2_Clear
*/
WOLFTPM_API int wolfTPM2_Clear(WOLFTPM2_DEV* dev);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to start a TPM generated hash

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param hash pointer to a WOLFTPM2_HASH structure
    \param hashAlg integer value, specifying a valid TPM 2.0 hash algorithm
    \param usageAuth pointer to a string constant, specifying the authorization for subsequent use of the hash
    \param usageAuthSz integer value, specifying the size of the authorization, in bytes

    \sa wolfTPM2_HashUpdate
    \sa wolfTPM2_HashFinish
*/
WOLFTPM_API int wolfTPM2_HashStart(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    TPMI_ALG_HASH hashAlg, const byte* usageAuth, word32 usageAuthSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Update a TPM generated hash with new user data
    \note Make sure the auth is correctly set

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param hash pointer to a WOLFTPM2_HASH structure
    \param data pointer to a byte buffer, containing the user data to be added to the hash
    \param dataSz integer value of word32 type, specifying the size of the user data, in bytes

    \sa wolfTPM2_HashStart
    \sa wolfTPM2_HashFinish
*/
WOLFTPM_API int wolfTPM2_HashUpdate(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    const byte* data, word32 dataSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Finalize a TPM generated hash and get the digest output in a user buffer
    \note Make sure the auth is correctly set

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param hash pointer to a WOLFTPM2_HASH structure
    \param digest pointer to a byte buffer, used to store the resulting digest
    \param[in,out] digestSz pointer to size of digest buffer, on return set to bytes stored in digest buffer

    \sa wolfTPM2_HashStart
    \sa wolfTPM2_HashUpdate
*/
WOLFTPM_API int wolfTPM2_HashFinish(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    byte* digest, word32* digestSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Creates and loads a new TPM key of KeyedHash type, typically used for HMAC operations
    \note To generate HMAC using the TPM it is recommended to use the wolfTPM2_Hmac wrappers

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty structure of WOLFTPM2_KEY type, to store the generated key
    \param parent pointer to a structure of WOLFTPM2_KEY type, containing a valid TPM handle of a primary key
    \param hashAlg integer value, specifying a valid TPM 2.0 hash algorithm
    \param keyBuf pointer to a byte array, containing derivation values for the new KeyedHash key
    \param keySz integer value, specifying the size of the derivation values stored in keyBuf, in bytes
    \param usageAuth pointer to a string constant, specifying the authorization of the new key
    \param usageAuthSz integer value, specifying the size of the authorization, in bytes

    \sa wolfTPM2_HmacStart
    \sa wolfTPM2_HmacUpdate
    \sa wolfTPM2_HmacFinish
*/
WOLFTPM_API int wolfTPM2_LoadKeyedHashKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    WOLFTPM2_HANDLE* parent, int hashAlg, const byte* keyBuf, word32 keySz,
    const byte* usageAuth, word32 usageAuthSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to start a TPM generated hmac

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param hmac pointer to a WOLFTPM2_HMAC structure
    \param parent pointer to a structure of WOLFTPM2_KEY type, containing a valid TPM handle of a primary key
    \param hashAlg integer value, specifying a valid TPM 2.0 hash algorithm
    \param keyBuf pointer to a byte array, containing derivation values for the new KeyedHash key
    \param keySz integer value, specifying the size of the derivation values stored in keyBuf, in bytes
    \param usageAuth pointer to a string constant, specifying the authorization for subsequent use of the hmac
    \param usageAuthSz integer value, specifying the size of the authorization, in bytes

    \sa wolfTPM2_HmacUpdate
    \sa wolfTPM2_HmacFinish
    \sa wolfTPM2_LoadKeyedHashKey
*/
WOLFTPM_API int wolfTPM2_HmacStart(WOLFTPM2_DEV* dev, WOLFTPM2_HMAC* hmac,
    WOLFTPM2_HANDLE* parent, TPMI_ALG_HASH hashAlg, const byte* keyBuf, word32 keySz,
    const byte* usageAuth, word32 usageAuthSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Update a TPM generated hmac with new user data
    \note Make sure the TPM authorization is correctly set

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param hmac pointer to a WOLFTPM2_HMAC structure
    \param data pointer to a byte buffer, containing the user data to be added to the hmac
    \param dataSz integer value of word32 type, specifying the size of the user data, in bytes

    \sa wolfTPM2_HmacStart
    \sa wolfTPM2_HMACFinish
*/
WOLFTPM_API int wolfTPM2_HmacUpdate(WOLFTPM2_DEV* dev, WOLFTPM2_HMAC* hmac,
    const byte* data, word32 dataSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Finalize a TPM generated hmac and get the digest output in a user buffer
    \note Make sure the TPM authorization is correctly set

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param hmac pointer to a WOLFTPM2_HMAC structure
    \param digest pointer to a byte buffer, used to store the resulting hmac digest
    \param digestSz integer value of word32 type, specifying the size of the digest, in bytes

    \sa wolfTPM2_HmacStart
    \sa wolfTPM2_HmacUpdate
*/
WOLFTPM_API int wolfTPM2_HmacFinish(WOLFTPM2_DEV* dev, WOLFTPM2_HMAC* hmac,
    byte* digest, word32* digestSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Loads an external symmetric key into the TPM

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty structure of WOLFTPM2_KEY type, to store the TPM handle and key information
    \param alg integer value, specifying a valid TPM 2.0 symmetric key algorithm, e.g. TPM_ALG_CFB for AES CFB
    \param keyBuf pointer to a byte array, containing private material of the symmetric key
    \param keySz integer value, specifying the size of the key material stored in keyBuf, in bytes

    \sa wolfTPM2_EncryptDecryptBlock
    \sa wolfTPM2_EncryptDecrypt
    \sa TPM2_EncryptDecrypt2
*/
WOLFTPM_API int wolfTPM2_LoadSymmetricKey(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* key, int alg, const byte* keyBuf, word32 keySz);

#define WOLFTPM2_ENCRYPT NO
#define WOLFTPM2_DECRYPT YES
WOLFTPM_API int wolfTPM2_EncryptDecryptBlock(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* in, byte* out, word32 inOutSz, byte* iv, word32 ivSz,
    int isDecrypt);
WOLFTPM_API int wolfTPM2_EncryptDecrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const byte* in, byte* out, word32 inOutSz,
    byte* iv, word32 ivSz, int isDecrypt);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Vendor specific TPM command, used to enable other restricted TPM commands

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param commandCode integer value, representing a valid vendor command
    \param enableFlag integer value, non-zero values represent "to enable"

    \sa TPM2_GPIO_Config
*/
WOLFTPM_API int wolfTPM2_SetCommand(WOLFTPM2_DEV* dev, TPM_CC commandCode,
    int enableFlag);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to shutdown or reset the TPM
    \note If doStartup is set, then TPM2_Startup is performed right after TPM2_Shutdown

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param doStartup integer value, non-zero values represent "perform Startup after Shutdown"

    \sa wolfTPM2_Init
*/
WOLFTPM_API int wolfTPM2_Shutdown(WOLFTPM2_DEV* dev, int doStartup);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief One-shot API to unload subsequent TPM handles

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param handleStart integer value of word32 type, specifying the value of the first TPM handle
    \param handleCount integer value of word32 type, specifying the number of handles

    \sa wolfTPM2_Init
*/
WOLFTPM_API int wolfTPM2_UnloadHandles(WOLFTPM2_DEV* dev, word32 handleStart,
    word32 handleCount);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief One-shot API to unload all transient TPM handles
    \note If there are Primary Keys as transient objects, they need to be recreated before TPM keys can be used

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct

    \sa wolfTPM2_UnloadHandles
    \sa wolfTPM2_CreatePrimary
*/
WOLFTPM_API int wolfTPM2_UnloadHandles_AllTransient(WOLFTPM2_DEV* dev);

/* Utility functions */

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for new RSA key based on user selected object attributes

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new RSA template
    \param objectAttributes integer value of TPMA_OBJECT type, can contain one or more attributes, e.g. TPMA_OBJECT_fixedTPM

    \sa wolfTPM2_GetKeyTemplate_RSA_ex
    \sa wolfTPM2_GetKeyTemplate_ECC
    \sa wolfTPM2_GetKeyTemplate_Symmetric
    \sa wolfTPM2_GetKeyTemplate_KeyedHash
    \sa wolfTPM2_GetKeyTemplate_KeySeal
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_RSA(TPMT_PUBLIC* publicTemplate,
    TPMA_OBJECT objectAttributes);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for new RSA key based on user selected object attributes

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new RSA template
    \param nameAlg integer value of TPM_ALG_ID type, specifying a TPM supported hashing algorithm, typically TPM_ALG_SHA256 for SHA 256
    \param objectAttributes integer value of TPMA_OBJECT type, can contain one or more attributes, e.g. TPMA_OBJECT_fixedTPM
    \param keyBits integer value, specifying the size of the symmetric key, typically 128 or 256 bits
    \param exponent integer value of word32 type, specifying the RSA exponent
    \param sigScheme integer value of TPM_ALG_ID type, specifying a TPM supported signature scheme
    \param sigHash integer value of TPM_ALG_ID type, specifying a TPM supported signature hash scheme

    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_ECC
    \sa wolfTPM2_GetKeyTemplate_ECC_ex
    \sa wolfTPM2_GetKeyTemplate_Symmetric
    \sa wolfTPM2_GetKeyTemplate_KeyedHash
    \sa wolfTPM2_GetKeyTemplate_KeySeal
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_RSA_ex(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, int keyBits, long exponent,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for new ECC key based on user selected object attributes

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new ECC key template
    \param objectAttributes integer value of TPMA_OBJECT type, can contain one or more attributes, e.g. TPMA_OBJECT_fixedTPM
    \param curve integer value of TPM_ECC_CURVE type, specifying a TPM supported ECC curve ID
    \param sigScheme integer value of TPM_ALG_ID type, specifying a TPM supported signature scheme

    \sa wolfTPM2_GetKeyTemplate_ECC_ex
    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_Symmetric
    \sa wolfTPM2_GetKeyTemplate_KeyedHash
    \sa wolfTPM2_GetKeyTemplate_KeySeal
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_ECC(TPMT_PUBLIC* publicTemplate,
    TPMA_OBJECT objectAttributes, TPM_ECC_CURVE curve, TPM_ALG_ID sigScheme);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for new ECC key based on user selected object attributes

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new ECC key template
    \param nameAlg integer value of TPM_ALG_ID type, specifying a TPM supported hashing algorithm, typically TPM_ALG_SHA256 for SHA 256
    \param objectAttributes integer value of TPMA_OBJECT type, can contain one or more attributes, e.g. TPMA_OBJECT_fixedTPM
    \param curve integer value of TPM_ECC_CURVE type, specifying a TPM supported ECC curve ID
    \param sigScheme integer value of TPM_ALG_ID type, specifying a TPM supported signature scheme
    \param sigHash integer value of TPM_ALG_ID type, specifying a TPM supported signature hash scheme

    \sa wolfTPM2_GetKeyTemplate_ECC
    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_Symmetric
    \sa wolfTPM2_GetKeyTemplate_KeyedHash
    \sa wolfTPM2_GetKeyTemplate_KeySeal
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_ECC_ex(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, TPM_ECC_CURVE curve,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for new Symmetric key

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new Symmetric key template
    \param keyBits integer value, specifying the size of the symmetric key, typically 128 or 256 bits
    \param algMode integer value of TPM_ALG_ID type, specifying a TPM supported symmetric algorithm, e.g. TPM_ALG_CFB for AES CFB
    \param isSign integer value, non-zero values represent "a signing key"
    \param isDecrypt integer value, non-zero values represent "a decryption key"

    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_ECC
    \sa wolfTPM2_GetKeyTemplate_KeyedHash
    \sa wolfTPM2_GetKeyTemplate_KeySeal
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_Symmetric(TPMT_PUBLIC* publicTemplate,
    int keyBits, TPM_ALG_ID algMode, int isSign, int isDecrypt);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for new KeyedHash key

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new template
    \param hashAlg integer value of TPM_ALG_ID type, specifying a TPM supported hashing algorithm, e.g. TPM_ALG_SHA256 for SHA 256
    \param isSign integer value, non-zero values represent "a signing key"
    \param isDecrypt integer value, non-zero values represent "a decryption key"

    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_ECC
    \sa wolfTPM2_GetKeyTemplate_Symmetric
    \sa wolfTPM2_GetKeyTemplate_KeySeal
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_KeyedHash(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID hashAlg, int isSign, int isDecrypt);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for new key for sealing secrets
    \note There are strict requirements for a Key Seal, therefore most of the key parameters are predetermined by the wrapper

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new template
    \param nameAlg integer value of TPM_ALG_ID type, specifying a TPM supported hashing algorithm, typically TPM_ALG_SHA256 for SHA 256

    \sa wolfTPM2_GetKeyTemplate_ECC
    \sa wolfTPM2_GetKeyTemplate_Symmetric
    \sa wolfTPM2_GetKeyTemplate_KeyedHash
    \sa wolfTPM2_GetKeyTemplate_KeySeal
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_KeySeal(TPMT_PUBLIC* publicTemplate, TPM_ALG_ID nameAlg);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for generating the TPM Endorsement Key of RSA type

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new template

    \sa wolfTPM2_GetKeyTemplate_ECC_EK
    \sa wolfTPM2_GetKeyTemplate_RSA_SRK
    \sa wolfTPM2_GetKeyTemplate_RSA_AIK
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_RSA_EK(TPMT_PUBLIC* publicTemplate);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for generating the TPM Endorsement Key of ECC type

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new template

    \sa wolfTPM2_GetKeyTemplate_RSA_EK
    \sa wolfTPM2_GetKeyTemplate_ECC_SRK
    \sa wolfTPM2_GetKeyTemplate_ECC_AIK
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_ECC_EK(TPMT_PUBLIC* publicTemplate);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for generating a new TPM Storage Key of RSA type

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new template

    \sa wolfTPM2_GetKeyTemplate_ECC_SRK
    \sa wolfTPM2_GetKeyTemplate_RSA_AIK
    \sa wolfTPM2_GetKeyTemplate_RSA_EK
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_RSA_SRK(TPMT_PUBLIC* publicTemplate);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for generating a new TPM Storage Key of ECC type

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new template

    \sa wolfTPM2_GetKeyTemplate_RSA_SRK
    \sa wolfTPM2_GetKeyTemplate_ECC_AIK
    \sa wolfTPM2_GetKeyTemplate_ECC_EK
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_ECC_SRK(TPMT_PUBLIC* publicTemplate);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for generating a new TPM Attestation Key of RSA type

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new template

    \sa wolfTPM2_GetKeyTemplate_ECC_AIK
    \sa wolfTPM2_GetKeyTemplate_RSA_SRK
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_RSA_AIK(TPMT_PUBLIC* publicTemplate);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for generating a new TPM Attestation Key of ECC type

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new template

    \sa wolfTPM2_GetKeyTemplate_RSA_AIK
    \sa wolfTPM2_GetKeyTemplate_ECC_SRK
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_ECC_AIK(TPMT_PUBLIC* publicTemplate);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Sets the unique area of a public template used by Create or CreatePrimary.
    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new template
    \param unique optional pointer to buffer to populate unique area of public template. If NULL, the buffer will be zeroized.
    \param uniqueSz size to fill the unique field. If zero the key size is used.

    \sa wolfTPM2_CreateKey
    \sa wolfTPM2_CreatePrimaryKey
*/
WOLFTPM_API int wolfTPM2_SetKeyTemplate_Unique(TPMT_PUBLIC* publicTemplate, const byte* unique, int uniqueSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM NV Index template

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param auth integer value, representing the TPM Hierarchy under which the new TPM NV index will be created
    \param nvAttributes pointer to an empty integer variable, to store the NV Attributes

    \sa wolfTPM2_CreateAuth
    \sa wolfTPM2_WriteAuth
    \sa wolfTPM2_ReadAuth
    \sa wolfTPM2_DeleteAuth
*/
WOLFTPM_API int wolfTPM2_GetNvAttributesTemplate(TPM_HANDLE auth, word32* nvAttributes);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Generates a new TPM Endorsement key, based on the user selected algorithm, RSA or ECC
    \note Although only RSA and ECC can be used for EK, symmetric keys can be created and used by the TPM

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param ekKey pointer to an empty WOLFTPM2_KEY structure, to store information about the new EK
    \param alg can be only TPM_ALG_RSA or TPM_ALG_ECC, see Note above

    \sa wolfTPM2_CreateSRK
    \sa wolfTPM2_GetKeyTemplate_RSA_EK
    \sa wolfTPM2_GetKeyTemplate_ECC_EK
*/
WOLFTPM_API int wolfTPM2_CreateEK(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* ekKey, TPM_ALG_ID alg);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Generates a new TPM Primary Key that will be used as a Storage Key for other TPM keys
    \note Although only RSA and ECC can be used for EK, symmetric keys can be created and used by the TPM

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param srkKey pointer to an empty WOLFTPM2_KEY structure, to store information about the new EK
    \param alg can be only TPM_ALG_RSA or TPM_ALG_ECC, see Note above
    \param auth pointer to a string constant, specifying the password authorization for the TPM 2.0 Key
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_CreateEK
    \sa wolfTPM2_CreateAndLoadAIK
    \sa wolfTPM2_GetKeyTemplate_RSA_SRK
    \sa wolfTPM2_GetKeyTemplate_ECC_SRK
*/
WOLFTPM_API int wolfTPM2_CreateSRK(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* srkKey, TPM_ALG_ID alg,
    const byte* auth, int authSz);
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Generates a new TPM Attestation Key under the provided Storage Key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param aikKey pointer to an empty WOLFTPM2_KEY structure, to store the newly generated TPM key
    \param alg can be only TPM_ALG_RSA or TPM_ALG_ECC
    \param srkKey pointer to a WOLFTPM2_KEY structure, pointing to valid TPM handle of a loaded Storage Key
    \param auth pointer to a string constant, specifying the password authorization for the TPM 2.0 Key
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_CreateSRK
    \sa wolfTPM2_GetKeyTemplate_RSA_AIK
    \sa wolfTPM2_GetKeyTemplate_ECC_AIK
*/
WOLFTPM_API int wolfTPM2_CreateAndLoadAIK(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* aikKey,
    TPM_ALG_ID alg, WOLFTPM2_KEY* srkKey, const byte* auth, int authSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief One-shot API to generate a TPM signed timestamp
    \note The attestation key must be generated and loaded prior to this call

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param aikKey pointer to a WOLFTPM2_KEY structure, containing valid TPM handle of a loaded attestation key
    \param getTimeOut pointer to an empty structure of GetTime_Out type, to store the output of the command

    \sa wolfTPM2_CreateSRK
    \sa wolfTPM2_GetKeyTemplate_RSA_EK
    \sa wolfTPM2_GetKeyTemplate_ECC_EK
*/
WOLFTPM_API int wolfTPM2_GetTime(WOLFTPM2_KEY* aikKey, GetTime_Out* getTimeOut);


#ifdef WOLFTPM2_CERT_GEN

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper for Certificate Signing Request (CSR) generation to set a
        custom request extension oid and value usage for a WOLFTPM2_CSR structure.

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct (not used)
    \param csr pointer to a WOLFTPM2_CSR structure
    \param critical If 0, the extension will not be marked critical, otherwise
     it will be marked critical.
    \param oid Dot separated oid as a string. For example "1.2.840.10045.3.1.7"
    \param der The der encoding of the content of the extension.
    \param derSz The size in bytes of the der encoding.

    \sa wolfTPM2_CSR_SetSubject
    \sa wolfTPM2_CSR_SetKeyUsage
    \sa wolfTPM2_CSR_MakeAndSign
    \sa wolfTPM2_CSR_MakeAndSign_ex
*/
WOLFTPM_API int wolfTPM2_CSR_SetCustomExt(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr,
    int critical, const char *oid, const byte *der, word32 derSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper for Certificate Signing Request (CSR) generation to set a
        extended key usage or key usage for a WOLFTPM2_CSR structure.
        Pass either extended key usage or key usage values.
        Mixed string types are not supported, however you can call `wolfTPM2_CSR_SetKeyUsage`
        twice (once for extended key usage strings and once for standard key usage strings).

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct (not used)
    \param csr pointer to a WOLFTPM2_CSR structure
    \param keyUsage string list of comma separated key usage attributes.
        Possible Extended Key Usage values: any, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping and OCSPSigning
        Possible Key Usage values: digitalSignature, nonRepudiation, contentCommitment, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly
        Default: "serverAuth,clientAuth,codeSigning"

    \sa wolfTPM2_CSR_SetSubject
    \sa wolfTPM2_CSR_SetCustomExt
    \sa wolfTPM2_CSR_MakeAndSign
    \sa wolfTPM2_CSR_MakeAndSign_ex
*/
WOLFTPM_API int wolfTPM2_CSR_SetKeyUsage(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr,
    const char* keyUsage);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper for Certificate Signing Request (CSR) generation to set a
        subject for a WOLFTPM2_CSR structure.

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct (not used)
    \param csr pointer to a WOLFTPM2_CSR structure
    \param subject distinguished name string using /CN= syntax.
        Example: "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"

    \sa wolfTPM2_CSR_SetKeyUsage
    \sa wolfTPM2_CSR_SetCustomExt
    \sa wolfTPM2_CSR_MakeAndSign
    \sa wolfTPM2_CSR_MakeAndSign_ex
*/
WOLFTPM_API int wolfTPM2_CSR_SetSubject(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr,
    const char* subject);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper for Certificate Signing Request (CSR) generation using a TPM based key (WOLFTPM2_KEY).
        Uses a provided WOLFTPM2_CSR structure with subject and key usage already set.

    \return Success: Positive integer (size of the output)
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param csr pointer to a WOLFTPM2_CSR structure
    \param key WOLFTPM2_KEY structure
    \param outFormat CTC_FILETYPE_ASN1 or CTC_FILETYPE_PEM
    \param out destination buffer for CSR as ASN.1/DER or PEM
    \param outSz destination buffer maximum size
    \param sigType Use 0 to automatically select SHA2-256 based on keyType (CTC_SHA256wRSA or CTC_SHA256wECDSA).
        See wolfCrypt "enum Ctc_SigType" for list of possible values.
    \param selfSignCert If set to 1 (non-zero) then result will be a self signed certificate.
        Zero (0) will generate a CSR (Certificate Signing Request) to be used by a CA.
    \param devId The device identifier used when registering the crypto callback. Use INVALID_DEVID (-2) to
        automatically register the required crypto callback.

    \sa wolfTPM2_CSR_SetSubject
    \sa wolfTPM2_CSR_SetKeyUsage
    \sa wolfTPM2_CSR_SetCustomExt
    \sa wolfTPM2_CSR_MakeAndSign
*/
WOLFTPM_API int wolfTPM2_CSR_MakeAndSign_ex(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr,
    WOLFTPM2_KEY* key, int outFormat, byte* out, int outSz,
    int sigType, int selfSignCert, int devId);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper for Certificate Signing Request (CSR) generation using a TPM based key (WOLFTPM2_KEY).
        Uses a provided WOLFTPM2_CSR structure with subject and key usage already set.

    \return Success: Positive integer (size of the output)
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param csr pointer to a WOLFTPM2_CSR structure
    \param key WOLFTPM2_KEY structure
    \param outFormat CTC_FILETYPE_ASN1 or CTC_FILETYPE_PEM
    \param out destination buffer for CSR as ASN.1/DER or PEM
    \param outSz destination buffer maximum size

    \sa wolfTPM2_CSR_SetSubject
    \sa wolfTPM2_CSR_SetKeyUsage
    \sa wolfTPM2_CSR_SetCustomExt
    \sa wolfTPM2_CSR_MakeAndSign_ex
*/
WOLFTPM_API int wolfTPM2_CSR_MakeAndSign(WOLFTPM2_DEV* dev, WOLFTPM2_CSR* csr,
    WOLFTPM2_KEY* key, int outFormat, byte* out, int outSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper for Certificate Signing Request (CSR) generation using a TPM based key (WOLFTPM2_KEY).
        Single shot API for outputting a CSR or self-signed cert based on TPM key.

    \return Success: Positive integer (size of the output)
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a loaded WOLFTPM2_KEY structure
    \param subject distinguished name string using /CN= syntax.
        Example: "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
    \param keyUsage string list of comma separated key usage attributes.
        Possible values: any, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping and OCSPSigning
        Default: "serverAuth,clientAuth,codeSigning"
    \param outFormat CTC_FILETYPE_ASN1 or CTC_FILETYPE_PEM
    \param out destination buffer for CSR as ASN.1/DER or PEM
    \param outSz destination buffer maximum size
    \param sigType Use 0 to automatically select SHA2-256 based on keyType (CTC_SHA256wRSA or CTC_SHA256wECDSA).
        See wolfCrypt "enum Ctc_SigType" for list of possible values.
    \param selfSignCert If set to 1 (non-zero) then result will be a self signed certificate.
        Zero (0) will generate a CSR (Certificate Signing Request) to be used by a CA.
    \param devId The device identifier used when registering the crypto callback. Use INVALID_DEVID (-2) to
        automatically register the required crypto callback.

    \sa wolfTPM2_SetCryptoDevCb
    \sa wolfTPM2_CSR_Generate
*/
WOLFTPM_API int wolfTPM2_CSR_Generate_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const char* subject, const char* keyUsage, int outFormat,
    byte* out, int outSz, int sigType, int selfSignCert, int devId);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper for Certificate Signing Request (CSR) generation using a TPM based key (WOLFTPM2_KEY).
        Single shot API for outputting a CSR or self-signed cert based on TPM key.

    \return Success: Positive integer (size of the output)
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a loaded WOLFTPM2_KEY structure
    \param subject distinguished name string using /CN= syntax.
        Example: "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
    \param keyUsage string list of comma separated key usage attributes.
        Possible values: any, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping and OCSPSigning
        Default: "serverAuth,clientAuth,codeSigning"
    \param outFormat CTC_FILETYPE_ASN1 or CTC_FILETYPE_PEM
    \param out destination buffer for CSR as ASN.1/DER or PEM
    \param outSz destination buffer maximum size

    \sa wolfTPM2_SetCryptoDevCb
    \sa wolfTPM2_CSR_Generate_ex
*/
WOLFTPM_API int wolfTPM2_CSR_Generate(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const char* subject, const char* keyUsage, int outFormat,
    byte* out, int outSz);

#endif /* WOLFTPM2_CERT_GEN */


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper to set the platform heirarchy authentication value to random.
        Setting the platform auth to random value is used to prevent application
        from being able to use platform hierarchy. This is defined in section 10
        of the TCG PC Client Platform specification.

    \return Success: Positive integer (size of the output)
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param session the current session, a session is required to protect the new platform auth

    \sa TPM2_HierarchyChangeAuth
*/
WOLFTPM_API int wolfTPM2_ChangePlatformAuth(WOLFTPM2_DEV* dev, WOLFTPM2_SESSION* session);



/* moved to tpm.h native code. macros here for backwards compatibility */
#define wolfTPM2_SetupPCRSel  TPM2_SetupPCRSel
#define wolfTPM2_GetAlgName   TPM2_GetAlgName
#define wolfTPM2_GetRCString  TPM2_GetRCString
#define wolfTPM2_GetCurveSize TPM2_GetCurveSize

/* for encrypting secrets (like salt) used in auth sessions and external key import */
WOLFTPM_LOCAL int wolfTPM2_EncryptSecret(WOLFTPM2_DEV* dev, const WOLFTPM2_KEY* tpmKey,
    TPM2B_DATA *secret, TPM2B_ENCRYPTED_SECRET *encSecret, const char* label);


#if defined(WOLFTPM_CRYPTOCB) || defined(HAVE_PK_CALLBACKS)
struct TpmCryptoDevCtx;

typedef struct TpmCryptoDevCtx {
    WOLFTPM2_DEV* dev;
#ifndef NO_RSA
    WOLFTPM2_KEY* rsaKey;  /* RSA */
    #ifdef WOLFSSL_KEY_GEN
    WOLFTPM2_KEYBLOB* rsaKeyGen;  /* RSA KeyGen */
    #endif
#endif
#ifdef HAVE_ECC
    WOLFTPM2_KEY* eccKey;  /* ECDSA */
    #ifndef WOLFTPM2_USE_SW_ECDHE
    WOLFTPM2_KEY* ecdhKey; /* ECDH */
    #endif
#endif
    WOLFTPM2_KEY* storageKey;
#ifdef WOLFTPM_USE_SYMMETRIC
    unsigned short useSymmetricOnTPM:1; /* if set indicates desire to use symmetric algorithms on TPM */
#endif
    unsigned short useFIPSMode:1; /* if set requires FIPS mode on TPM and no fallback to software algos */
} TpmCryptoDevCtx;

#endif /* WOLFTPM_CRYPTOCB || HAVE_PK_CALLBACKS */

#ifdef WOLFTPM_CRYPTOCB

/*!
    \ingroup wolfTPM2_Wrappers
    \brief A reference crypto callback API for using the TPM for crypto offload.
    This callback function is registered using wolfTPM2_SetCryptoDevCb or wc_CryptoDev_RegisterDevice

    \return TPM_RC_SUCCESS: successful
    \return CRYPTOCB_UNAVAILABLE: Do not use TPM hardware, fall-back to default software crypto.
    \return WC_HW_E: generic hardware failure

    \param devId The devId used when registering the callback. Any signed integer value besides INVALID_DEVID
    \param info point to wc_CryptoInfo structure with detailed information about crypto type and parameters
    \param ctx The user context supplied when callback was registered with wolfTPM2_SetCryptoDevCb

    \sa wolfTPM2_SetCryptoDevCb
    \sa wolfTPM2_ClearCryptoDevCb
*/
WOLFTPM_API int wolfTPM2_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Register a crypto callback function and return assigned devId.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param cb The wolfTPM2_CryptoDevCb API is a template, but you can also provide your own
    \param tpmCtx The user supplied context. For wolfTPM2_CryptoDevCb use TpmCryptoDevCtx, but can also be your own.
    \param pDevId Pointer to automatically assigned device ID.

    \sa wolfTPM2_CryptoDevCb
    \sa wolfTPM2_ClearCryptoDevCb
*/
WOLFTPM_API int wolfTPM2_SetCryptoDevCb(WOLFTPM2_DEV* dev, CryptoDevCallbackFunc cb,
    TpmCryptoDevCtx* tpmCtx, int* pDevId);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Clears the registered crypto callback

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param devId The devId used when registering the callback

    \sa wolfTPM2_CryptoDevCb
    \sa wolfTPM2_SetCryptoDevCb
*/
WOLFTPM_API int wolfTPM2_ClearCryptoDevCb(WOLFTPM2_DEV* dev, int devId);

#endif /* WOLFTPM_CRYPTOCB */

#if defined(HAVE_PK_CALLBACKS) && !defined(WOLFTPM2_NO_WRAPPER) && \
    !defined(WOLFCRYPT_ONLY)
#ifndef NO_RSA
WOLFTPM_API int wolfTPM2_PK_RsaSign(WOLFSSL* ssl,
    const unsigned char* in, unsigned int inSz,
    unsigned char* out, word32* outSz,
    const unsigned char* keyDer, unsigned int keySz,
    void* ctx);

WOLFTPM_API int wolfTPM2_PK_RsaSignCheck(WOLFSSL* ssl,
    unsigned char* sig, unsigned int sigSz,
    unsigned char** out,
    const unsigned char* keyDer, unsigned int keySz,
    void* ctx);

#ifdef WC_RSA_PSS
WOLFTPM_API int wolfTPM2_PK_RsaPssSign(WOLFSSL* ssl,
    const unsigned char* in, unsigned int inSz,
    unsigned char* out, unsigned int* outSz,
    int hash, int mgf,
    const unsigned char* keyDer, unsigned int keySz,
    void* ctx);

WOLFTPM_API int wolfTPM2_PK_RsaPssSignCheck(WOLFSSL* ssl,
    unsigned char* sig, unsigned int sigSz, unsigned char** out,
    int hash, int mgf,
    const unsigned char* keyDer, unsigned int keySz,
    void* ctx);
#endif /* WC_RSA_PSS */
#endif /* !NO_RSA */
#ifdef HAVE_ECC
WOLFTPM_API int wolfTPM2_PK_EccSign(WOLFSSL* ssl,
    const unsigned char* in, unsigned int inSz,
    unsigned char* out, word32* outSz,
    const unsigned char* keyDer, unsigned int keySz,
    void* ctx);
#endif

/* Helpers for setting generic PK callbacks */
WOLFTPM_API int wolfTPM_PK_SetCb(WOLFSSL_CTX* ctx);
WOLFTPM_API int wolfTPM_PK_SetCbCtx(WOLFSSL* ssl, void* userCtx);

#endif /* HAVE_PK_CALLBACKS */

#ifndef WOLFTPM2_NO_HEAP

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Allocate and initialize a WOLFTPM2_DEV

    \return pointer to new device struct
    \return NULL: on any error

    \sa wolfTPM2_Free
*/
WOLFTPM_API WOLFTPM2_DEV* wolfTPM2_New(void);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Cleanup and Free a WOLFTPM2_DEV that was allocated by wolfTPM2_New

    \return TPM_RC_SUCCESS: successful

    \param dev pointer to a TPM2_DEV struct

    \sa wolfTPM2_New
*/
WOLFTPM_API int wolfTPM2_Free(WOLFTPM2_DEV *dev);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Allocate and initialize a WOLFTPM2_KEYBLOB

    \return pointer to newly initialized WOLFTPM2_KEYBLOB
    \return NULL on any error

    \sa wolfTPM2_FreeKeyBlob
*/
WOLFTPM_API WOLFTPM2_KEYBLOB* wolfTPM2_NewKeyBlob(void);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Free a WOLFTPM2_KEYBLOB that was allocated with wolfTPM2_NewKeyBlob

    \return TPM_RC_SUCCESS: successful

    \param blob pointer to a WOLFTPM2_KEYBLOB that was allocated by wolfTPM2_NewKeyBlob

    \sa wolfTPM2_NewKeyBlob
*/
WOLFTPM_API int wolfTPM2_FreeKeyBlob(WOLFTPM2_KEYBLOB* blob);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Allocate and initialize a TPMT_PUBLIC

    \return pointer to newly initialized
    \return NULL on any error

    \sa wolfTPM2_FreePublicTemplate
*/
WOLFTPM_API TPMT_PUBLIC* wolfTPM2_NewPublicTemplate(void);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Free a TPMT_PUBLIC that was allocated with wolfTPM2_NewPublicTemplate

    \return TPM_RC_SUCCESS: successful

    \param PublicTemplate pointer to a TPMT_PUBLIC that was allocated with wolfTPM2_NewPublicTemplate

    \sa wolfTPM2_NewPublicTemplate
*/
WOLFTPM_API int wolfTPM2_FreePublicTemplate(TPMT_PUBLIC* PublicTemplate);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Allocate and initialize a WOLFTPM2_KEY

    \return pointer to newly initialized WOLFTPM2_KEY
    \return NULL on any error

    \sa wolfTPM2_FreeKey
*/
WOLFTPM_API WOLFTPM2_KEY* wolfTPM2_NewKey(void);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Free a WOLFTPM2_KEY that was allocated with wolfTPM2_NewKey

    \return TPM_RC_SUCCESS: successful

    \param key pointer to a WOLFTPM2_KEY that was allocated by wolfTPM2_NewKey

    \sa wolfTPM2_NewKey
*/
WOLFTPM_API int wolfTPM2_FreeKey(WOLFTPM2_KEY* key);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Allocate and initialize a WOLFTPM2_SESSION

    \return pointer to newly initialized WOLFTPM2_SESSION
    \return NULL on any error

    \sa wolfTPM2_FreeSession
*/
WOLFTPM_API WOLFTPM2_SESSION* wolfTPM2_NewSession(void);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Free a WOLFTPM2_SESSION that was allocated with wolfTPM2_NewSession

    \return TPM_RC_SUCCESS: successful

    \param session pointer to a WOLFTPM2_SESSION struct

    \sa wolfTPM2_NewSession
*/
WOLFTPM_API int wolfTPM2_FreeSession(WOLFTPM2_SESSION* session);

#ifdef WOLFTPM2_CERT_GEN
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Allocate and initialize a WOLFTPM2_CSR

    \return pointer to newly initialized WOLFTPM2_CSR
    \return NULL on any error

    \sa wolfTPM2_FreeCSR
*/
WOLFTPM_API WOLFTPM2_CSR* wolfTPM2_NewCSR(void);
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Free a WOLFTPM2_CSR that was allocated with wolfTPM2_NewCSR

    \return TPM_RC_SUCCESS: successful

    \param csr pointer to a WOLFTPM2_CSR that was allocated by wolfTPM2_NewCSR

    \sa wolfTPM2_NewCSR
*/
WOLFTPM_API int wolfTPM2_FreeCSR(WOLFTPM2_CSR* csr);
#endif
#endif /* !WOLFTPM2_NO_HEAP */

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Retrieve the WOLFTPM2_HANDLE from a WOLFTPM2_KEY

    \return pointer to handle in the key structure
    \return NULL if key pointer is NULL

    \param key pointer to a WOLFTPM2_KEY struct
*/
WOLFTPM_API WOLFTPM2_HANDLE* wolfTPM2_GetHandleRefFromKey(WOLFTPM2_KEY* key);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Retrieve the WOLFTPM2_HANDLE from a WOLFTPM2_KEYBLOB

    \return pointer to handle in the key blob structure
    \return NULL if key pointer is NULL

    \param keyBlob pointer to a WOLFTPM2_KEYBLOB struct
*/
WOLFTPM_API WOLFTPM2_HANDLE* wolfTPM2_GetHandleRefFromKeyBlob(WOLFTPM2_KEYBLOB* keyBlob);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Retrieve the WOLFTPM2_HANDLE from a WOLFTPM2_SESSION

    \return pointer to handle in the session structure
    \return NULL if key pointer is NULL

    \param session pointer to a WOLFTPM2_SESSION struct
*/
WOLFTPM_API WOLFTPM2_HANDLE* wolfTPM2_GetHandleRefFromSession(WOLFTPM2_SESSION* session);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Get the 32-bit handle value from the WOLFTPM2_HANDLE

    \return TPM_HANDLE value from TPM

    \param handle pointer to WOLFTPM2_HANDLE structure
*/
WOLFTPM_API TPM_HANDLE wolfTPM2_GetHandleValue(WOLFTPM2_HANDLE* handle);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Set the authentication data for a key

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param key pointer to wrapper key struct
    \param auth pointer to auth data
    \param authSz length in bytes of auth data
*/
WOLFTPM_API int wolfTPM2_SetKeyAuthPassword(WOLFTPM2_KEY *key, const byte* auth,
    int authSz);

/*!
    \ingroup wolfTPM2_Wrappers

    \brief Marshal data from a keyblob to a binary buffer. This can be
    stored to disk for loading in a separate process or after power
    cycling. If buffer is not provided then size only will be returned.

    \return Positive integer (size of the output)
    \return BUFFER_E: insufficient space in provided buffer
    \return BAD_FUNC_ARG: check the provided arguments

    \param buffer pointer to buffer in which to store marshaled keyblob
    \param bufferSz size of the above buffer
    \param key pointer to keyblob to marshal

    \sa wolfTPM2_SetKeyBlobFromBuffer
*/
WOLFTPM_API int wolfTPM2_GetKeyBlobAsBuffer(byte *buffer, word32 bufferSz,
    WOLFTPM2_KEYBLOB* key);

/*!
    \ingroup wolfTPM2_Wrappers

    \brief Marshal data from a keyblob to a binary buffer. This can be
    stored to disk for loading in a separate process or after power
    cycling. If either buffer is NULL then the size will be returned for
    each part.

    \return TPM_RC_SUCCESS: successful
    \return BUFFER_E: insufficient space in provided buffer
    \return BAD_FUNC_ARG: check the provided arguments
    \return LENGTH_ONLY_E: Returning length only (when either of the buffers is NULL)

    \param pubBuffer pointer to buffer in which to store the public part of the marshaled keyblob
    \param pubBufferSz pointer to the size of the above buffer
    \param privBuffer pointer to buffer in which to store the private part of the marshaled keyblob
    \param privBufferSz pointer to the size of the above buffer
    \param key pointer to keyblob to marshal

    \sa wolfTPM2_GetKeyBlobAsSeparateBuffers
*/
WOLFTPM_API int wolfTPM2_GetKeyBlobAsSeparateBuffers(byte* pubBuffer,
    word32* pubBufferSz, byte* privBuffer, word32* privBufferSz,
    WOLFTPM2_KEYBLOB* key);

/*!
    \ingroup wolfTPM2_Wrappers

    \brief Unmarshal data into a WOLFTPM2_KEYBLOB struct. This can be
    used to load a keyblob that was previously marshaled by
    wolfTPM2_GetKeyBlobAsBuffer

    \return TPM_RC_SUCCESS: successful
    \return BUFFER_E: buffer is too small or there is extra data remaining and not unmarshalled
    \return BAD_FUNC_ARG: check the provided arguments

    \param key pointer to keyblob to load and unmarshall data into
    \param buffer pointer to buffer containing marshalled keyblob to load from
    \param bufferSz size of the above buffer

    \sa wolfTPM2_GetKeyBlobAsBuffer
*/
WOLFTPM_API int wolfTPM2_SetKeyBlobFromBuffer(WOLFTPM2_KEYBLOB* key,
    byte *buffer, word32 bufferSz);


/*!
    \ingroup wolfTPM2_Wrappers

    \brief Restart the policy digest for a policy session

    \return TPM_RC_SUCCESS: successful
    \return INPUT_SIZE_E: policyDigestSz is too small to hold the returned digest
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param sessionHandle the handle of the current session, a session is required to use policy pcr

    \sa wolfTPM2_GetPolicyDigest
    \sa wolfTPM2_PolicyPCR
    \sa wolfTPM2_PolicyAuthorize
*/
WOLFTPM_API int wolfTPM2_PolicyRestart(WOLFTPM2_DEV* dev, TPM_HANDLE sessionHandle);

/*!
    \ingroup wolfTPM2_Wrappers

    \brief Get the policy digest of the session that was passed in
    wolfTPM2_GetPolicyDigest

    \return TPM_RC_SUCCESS: successful
    \return INPUT_SIZE_E: policyDigestSz is too small to hold the returned digest
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param sessionHandle the handle of the current session, a session is required to use policy pcr
    \param policyDigest output digest of the policy
    \param policyDigestSz pointer to the size of the policyDigest

    \sa wolfTPM2_PolicyPCR
    \sa wolfTPM2_PolicyAuthorize
    \sa wolfTPM2_PolicyRestart
*/
WOLFTPM_API int wolfTPM2_GetPolicyDigest(WOLFTPM2_DEV* dev, TPM_HANDLE sessionHandle,
    byte* policyDigest, word32* policyDigestSz);

/*!
    \ingroup wolfTPM2_Wrappers

    \brief Apply the PCR's to the policy digest for the policy session.

    \return TPM_RC_SUCCESS: successful
    \return INPUT_SIZE_E: policyDigestSz is too small to hold the returned digest
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param sessionHandle the handle of the current policy session, a session is required to use policy PCR
    \param pcrAlg the hash algorithm to use with PCR policy
    \param pcrArray array of PCR Indexes to use when creating the policy
    \param pcrArraySz the number of PCR Indexes in the pcrArray

    \sa wolfTPM2_GetPolicyDigest
    \sa wolfTPM2_PolicyPCR
    \sa wolfTPM2_PolicyAuthorize
    \sa wolfTPM2_PolicyRestart
*/
WOLFTPM_API int wolfTPM2_PolicyPCR(WOLFTPM2_DEV* dev, TPM_HANDLE sessionHandle,
    TPM_ALG_ID pcrAlg, byte* pcrArray, word32 pcrArraySz);

/*!
    \ingroup wolfTPM2_Wrappers

    \brief Apply the PCR's to the policy digest for the policy session.

    \return TPM_RC_SUCCESS: successful
    \return INPUT_SIZE_E: policyDigestSz is too small to hold the returned digest
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param sessionHandle the handle of the current policy session, a session is required to use policy PCR
    \param pub pointer to a populated structure of TPM2B_PUBLIC type
    \param checkTicket returns the validation ticket proving the signature for digest was checked
    \param pcrDigest digest for the PCR(s) collected with wolfTPM2_PCRGetDigest
    \param pcrDigestSz size of the PCR digest
    \param policyRef optional nonce
    \param policyRefSz optional nonce size

    \sa wolfTPM2_GetPolicyDigest
    \sa wolfTPM2_PolicyPCR
    \sa wolfTPM2_PolicyAuthorize
    \sa wolfTPM2_PolicyRestart
    \sa wolfTPM2_PCRGetDigest
*/
WOLFTPM_API int wolfTPM2_PolicyAuthorize(WOLFTPM2_DEV* dev, TPM_HANDLE sessionHandle,
    const TPM2B_PUBLIC* pub, const TPMT_TK_VERIFIED* checkTicket,
    const byte* pcrDigest, word32 pcrDigestSz,
    const byte* policyRef, word32 policyRefSz);

/*!
    \ingroup wolfTPM2_Wrappers

    \brief Get a cumulative digest of the PCR's specified

    \return TPM_RC_SUCCESS: successful
    \return INPUT_SIZE_E: policyDigestSz is too small to hold the returned digest
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param pcrAlg the hash algorithm to use with pcr policy
    \param pcrArray array of pcr Index to use when creating the policy
    \param pcrArraySz the number of Index in the pcrArray
    \param pcrDigest digest for the PCR(s) collected with wolfTPM2_PCRGetDigest
    \param pcrDigestSz size of the PCR digest

    \sa wolfTPM2_PolicyPCR
    \sa wolfTPM2_PolicyAuthorize
*/
WOLFTPM_API int wolfTPM2_PCRGetDigest(WOLFTPM2_DEV* dev, TPM_ALG_ID pcrAlg,
    byte* pcrArray, word32 pcrArraySz, byte* pcrDigest, word32* pcrDigestSz);

/*!
    \ingroup wolfTPM2_Wrappers

    \brief Utility for generating a policy ref digest. If no policy reference
        (nonce) used then just rehash the provided digest again (update -> final)

    \return TPM_RC_SUCCESS: successful
    \return INPUT_SIZE_E: policyDigestSz is too small to hold the returned digest
    \return BAD_FUNC_ARG: check the provided arguments

    \param pcrAlg the hash algorithm to use with pcr policy
    \param digest input/out digest
    \param digestSz input/out digest size
    \param policyRef optional nonce
    \param policyRefSz optional nonce size

    \sa wolfTPM2_PolicyPCRMake
    \sa wolfTPM2_PolicyAuthorizeMake
*/
WOLFTPM_API int wolfTPM2_PolicyRefMake(TPM_ALG_ID pcrAlg, byte* digest, word32* digestSz,
    const byte* policyRef, word32 policyRefSz);

/*!
    \ingroup wolfTPM2_Wrappers

    \brief Utility for generating a policy PCR digest.

    \return TPM_RC_SUCCESS: successful
    \return INPUT_SIZE_E: policyDigestSz is too small to hold the returned digest
    \return BAD_FUNC_ARG: check the provided arguments

    \param pcrAlg the hash algorithm to use with pcr policy
    \param pcrArray optional array of pcrs to be used when creating the tpm object
    \param pcrArraySz length of the pcrArray
    \param pcrDigest digest for the PCR(s) collected (can get using wolfTPM2_PCRGetDigest)
    \param pcrDigestSz size of the PCR digest
    \param digest input/out digest
    \param digestSz input/out digest size

    \sa wolfTPM2_PolicyPCRMake
    \sa wolfTPM2_PolicyAuthorizeMake
    \sa wolfTPM2_PCRGetDigest
*/
WOLFTPM_API int wolfTPM2_PolicyPCRMake(TPM_ALG_ID pcrAlg,
    byte* pcrArray, word32 pcrArraySz, const byte* pcrDigest, word32 pcrDigestSz,
    byte* digest, word32* digestSz);

/*!
    \ingroup wolfTPM2_Wrappers

    \brief Utility for generating a policy authorization digest based on a public key

    \return TPM_RC_SUCCESS: successful
    \return INPUT_SIZE_E: policyDigestSz is too small to hold the returned digest
    \return BAD_FUNC_ARG: check the provided arguments

    \param pcrAlg the hash algorithm to use with pcr policy
    \param pub pointer to a populated structure of TPM2B_PUBLIC type
    \param digest input/out digest
    \param digestSz input/out digest size
    \param policyRef optional nonce
    \param policyRefSz optional nonce size

    \sa wolfTPM2_PolicyPCRMake
    \sa wolfTPM2_PolicyPCRMake
*/
WOLFTPM_API int wolfTPM2_PolicyAuthorizeMake(TPM_ALG_ID pcrAlg,
    const TPM2B_PUBLIC* pub, byte* digest, word32* digestSz,
    const byte* policyRef, word32 policyRefSz);


/* pre-provisioned IAK and IDevID key/cert from TPM vendor */
#ifdef WOLFTPM_MFG_IDENTITY

/* Initial attestation key (IAK) and an initial device ID (IDevID) */
/* Default is: ECDSA SECP384P1, SHA2-384 */
#define TPM2_IAK_KEY_HANDLE     0x81080000
#define TPM2_IAK_CERT_HANDLE    0x1C20100

#define TPM2_IDEVID_KEY_HANDLE  0x81080001
#define TPM2_IDEVID_CERT_HANDLE 0x1C20101

WOLFTPM_API int wolfTPM2_SetIdentityAuth(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* handle,
    uint8_t* masterPassword, uint16_t masterPasswordSz);

#endif /* WOLFTPM_MFG_IDENTITY */


/* Internal API's */
WOLFTPM_LOCAL int GetKeyTemplateRSA(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, int keyBits, long exponent,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash);
WOLFTPM_LOCAL int GetKeyTemplateECC(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, TPM_ECC_CURVE curve,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash);


#ifdef WOLFTPM_FIRMWARE_UPGRADE
typedef int (*wolfTPM2FwDataCb)(
    uint8_t* data, uint32_t data_req_sz, uint32_t offset, void* cb_ctx);

WOLFTPM_API int wolfTPM2_FirmwareUpgrade(WOLFTPM2_DEV* dev,
    uint8_t* manifest, uint32_t manifest_sz,
    wolfTPM2FwDataCb cb, void* cb_ctx);
WOLFTPM_API int wolfTPM2_FirmwareUpgradeCancel(WOLFTPM2_DEV* dev);

#endif /* WOLFTPM_FIRMWARE_UPGRADE */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* __TPM2_WRAP_H__ */
