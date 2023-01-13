/* wolfTPM.cs
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

using System;
using System.Text;
using System.Runtime.InteropServices;

namespace wolfTPM
{
    [Serializable]
    public class WolfTpm2Exception : Exception
    {
        const string DLLNAME = "wolftpm";

        private string _Message;
        public int ErrorCode { get; }
        public override string Message
        {
            get { return _Message; }
        }

        [DllImport(DLLNAME, EntryPoint = "TPM2_GetRCString")]
        private static extern IntPtr TPM2_GetRCString(int rc);
        public string GetErrorString(int rc)
        {
            IntPtr err = TPM2_GetRCString(rc);
            return Marshal.PtrToStringAnsi(err);
        }

        public WolfTpm2Exception() { }

        public WolfTpm2Exception(string message)
            : base(message) { }

        public WolfTpm2Exception(string message, Exception inner)
            : base(message, inner) { }

        public WolfTpm2Exception(string message, int errorCode)
            : this(message)
        {
            ErrorCode = errorCode;
            _Message = message + " failure 0x" + errorCode.ToString("X8") +
                                 " (" + GetErrorString(errorCode) + ")";
        }
    }

    /* from TPM_RC_T and wolfCrypt error-crypt.h */
    public enum Status : int
    {
        TPM_RC_SUCCESS = 0,
        TPM_RC_HANDLE = 0x8B,
        TPM_RC_NV_UNAVAILABLE = 0x923,
        TPM_RC_SIGNATURE = 0x9B,
        BAD_FUNC_ARG = -173,
        NOT_COMPILED_IN = -174,
    }

    /* from TPMA_OBJECT_mask */
    public enum TPM2_Object : ulong
    {
        fixedTPM = 0x00000002,
        stClear = 0x00000004,
        fixedParent = 0x00000010,
        sensitiveDataOrigin = 0x00000020,
        userWithAuth = 0x00000040,
        adminWithPolicy = 0x00000080,
        derivedDataOrigin = 0x00000200,
        noDA = 0x00000400,
        encryptedDuplication = 0x00000800,
        restricted = 0x00010000,
        decrypt = 0x00020000,
        sign = 0x00040000,
    }

    /* from TPM_ALG_ID */
    public enum TPM2_Alg : uint
    {
        ERROR = 0x0000,
        RSA = 0x0001,
        SHA = 0x0004,
        SHA1 = SHA,
        HMAC = 0x0005,
        AES = 0x0006,
        MGF1 = 0x0007,
        KEYEDHASH = 0x0008,
        XOR = 0x000A,
        SHA256 = 0x000B,
        SHA384 = 0x000C,
        SHA512 = 0x000D,
        NULL = 0x0010,
        SM3_256 = 0x0012,
        SM4 = 0x0013,
        RSASSA = 0x0014,
        RSAES = 0x0015,
        RSAPSS = 0x0016,
        OAEP = 0x0017,
        ECDSA = 0x0018,
        ECDH = 0x0019,
        ECDAA = 0x001A,
        SM2 = 0x001B,
        ECSCHNORR = 0x001C,
        ECMQV = 0x001D,
        KDF1_SP800_56A = 0x0020,
        KDF2 = 0x0021,
        KDF1_SP800_108 = 0x0022,
        ECC = 0x0023,
        SYMCIPHER = 0x0025,
        CAMELLIA = 0x0026,
        CTR = 0x0040,
        OFB = 0x0041,
        CBC = 0x0042,
        CFB = 0x0043,
        ECB = 0x0044,
    }

    /* from TPM_ECC_CURVE_T */
    public enum TPM2_ECC : uint
    {
        NONE        = 0x0000,
        NIST_P192   = 0x0001,
        NIST_P224   = 0x0002,
        NIST_P256   = 0x0003,
        NIST_P384   = 0x0004,
        NIST_P521   = 0x0005,
        BN_P256     = 0x0010,
        BN_P638     = 0x0011,
        SM2_P256    = 0x0020,
    }

    /* from TPM_SE_T */
    public enum SE : byte
    {
        HMAC = 0x00,
        POLICY = 0x01,
        TRIAL = 0x03,
    }

    /* from TPMA_SESSION_mask */
    public enum SESSION_mask : byte
    {
        continueSession = 0x01,
        auditExclusive  = 0x02,
        auditReset      = 0x04,
        decrypt         = 0x20,
        encrypt         = 0x40,
        audit           = 0x80,
    }

    /* from TPM_RH_T */
    public enum TPM_RH : ulong
    {
        FIRST        = 0x40000000,
        SRK          = FIRST,
        OWNER        = 0x40000001,
        REVOKE       = 0x40000002,
        TRANSPORT    = 0x40000003,
        OPERATOR     = 0x40000004,
        ADMIN        = 0x40000005,
        EK           = 0x40000006,
        NULL         = 0x40000007,
        UNASSIGNED   = 0x40000008,
        PW           = 0x40000009,
        LOCKOUT      = 0x4000000A,
        ENDORSEMENT  = 0x4000000B,
        PLATFORM     = 0x4000000C,
        PLATFORM_NV  = 0x4000000D,
        AUTH_00      = 0x40000010,
        AUTH_FF      = 0x4000010F,
        LAST         = AUTH_FF,
    }

    /* from wolfSSL CTC_FILETYPE_ASN1 and CTC_FILETYPE_PEM */
    public enum X509_Format : int
    {
        PEM = 1,
        DER = 2,
    }

    public class KeyBlob : IDisposable
    {
        const string DLLNAME = "wolftpm";

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_NewKeyBlob")]
        private static extern IntPtr wolfTPM2_NewKeyBlob();

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_FreeKeyBlob")]
        private static extern int wolfTPM2_FreeKeyBlob(IntPtr blob);

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyBlobAsBuffer")]
        private static extern int wolfTPM2_GetKeyBlobAsBuffer(byte[] buffer,
                                                              int bufferSz, IntPtr key);

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_SetKeyBlobFromBuffer")]
        private static extern int wolfTPM2_SetKeyBlobFromBuffer(IntPtr key,
                                                                byte[] buffer, int bufferSz);


        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetHandleRefFromKeyBlob")]
        private static extern IntPtr wolfTPM2_GetHandleRefFromKeyBlob(IntPtr keyBlob);

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_SetKeyAuthPassword")]
        private static extern int wolfTPM2_SetKeyAuthPassword(
            IntPtr keyBlob, string auth, int authSz);

        internal IntPtr keyblob;

        public KeyBlob()
        {
            keyblob = wolfTPM2_NewKeyBlob();
        }
        ~KeyBlob() => Dispose(false);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        protected virtual void Dispose(bool disposing)
        {
            /* free un-managed objects */
            if (keyblob != IntPtr.Zero) {
                /* ignore return code */
                wolfTPM2_FreeKeyBlob(keyblob);
                keyblob = IntPtr.Zero;
            }
        }

        /// <summary>
        /// Marshal data from this KeyBlob class to a binary buffer. This can be
        /// stored to disk for loading in a separate process or after power
        /// cycling.
        /// </summary>
        /// <param name="buffer">buffer in which to store marshaled keyblob</param>
        /// <returns>Success: Positive integer (size of the output)</returns>
        public int GetKeyBlobAsBuffer(byte[] buffer)
        {
            int rc = wolfTPM2_GetKeyBlobAsBuffer(buffer, buffer.Length,
                                                 keyblob);
            /* positive return code is length of buffer filled */
            if (rc < 0) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetKeyBlobAsBuffer", rc);
            }
            return rc;
        }

        /// <summary>
        /// Unmarshal data into a this KeyBlob class. Used to load a keyblob
        /// buffer that was previously marshaled by GetKeyBlobAsBuffer
        /// </summary>
        /// <param name="buffer">buffer containing marshalled keyblob to load from</param>
        /// <returns>0: Success</returns>
        public int SetKeyBlobFromBuffer(byte[] buffer)
        {
            int rc = wolfTPM2_SetKeyBlobFromBuffer(keyblob,
                                                   buffer, buffer.Length);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_SetKeyBlobFromBuffer", rc);
            }
            return rc;
        }

        /// <summary>
        /// Retrieve the WOLFTPM2_HANDLE pointer from a this KeyBlob.
        /// </summary>
        public IntPtr GetHandle()
        {
            return wolfTPM2_GetHandleRefFromKeyBlob(keyblob);
        }

        /// <summary>
        /// Set the authentication data for a key
        /// </summary>
        /// <param name="auth">pointer to auth data</param>
        /// <returns>Success: 0</returns>
        public int SetKeyAuthPassword(string auth)
        {
            int rc = wolfTPM2_SetKeyAuthPassword(keyblob,
                                                 auth,
                                                 auth.Length);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_SetKeyAuthPassword", rc);
            }
            return rc;
        }
    }

    public class Key : IDisposable
    {
        const string DLLNAME = "wolftpm";

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_NewKey")]
        private static extern IntPtr wolfTPM2_NewKey();

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_FreeKey")]
        private static extern int wolfTPM2_FreeKey(IntPtr key);

        /* ================================================================== */
        /* Native Getters and Setters                                         */
        /* ================================================================== */

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_SetKeyAuthPassword")]
        private static extern int wolfTPM2_SetKeyAuthPassword(
            IntPtr key, string auth, int authSz);

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetHandleRefFromKey")]
        private static extern IntPtr wolfTPM2_GetHandleRefFromKey(IntPtr key);

        internal IntPtr key;

        public Key()
        {
            key = wolfTPM2_NewKey();
        }
        ~Key() => Dispose(false);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        protected virtual void Dispose(bool disposing)
        {
            /* free un-managed objects */
            if (key != IntPtr.Zero) {
                /* ignore return code */
                wolfTPM2_FreeKey(key);
                key = IntPtr.Zero;
            }
        }


        /// <summary>
        /// Retrieve the WOLFTPM2_HANDLE pointer from a this Key.
        /// </summary>
        public IntPtr GetHandle()
        {
            return wolfTPM2_GetHandleRefFromKey(key);
        }

        /// <summary>
        /// kept for backwards compatibility, use GetHandle
        /// </summary>
        [Obsolete("kept for backwards compatibility, use GetHandle")]
        public IntPtr GetHandleRefFromKey()
        {
            return wolfTPM2_GetHandleRefFromKey(key);
        }

        /// <summary>
        /// Set the authentication data for a key
        /// </summary>
        /// <param name="auth">pointer to auth data</param>
        /// <returns>Success: 0</returns>
        public int SetKeyAuthPassword(string auth)
        {
            int rc = wolfTPM2_SetKeyAuthPassword(key,
                                                 auth,
                                                 auth.Length);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_SetKeyAuthPassword", rc);
            }
            return rc;
        }
    }

    public class Template : IDisposable
    {
        const string DLLNAME = "wolftpm";

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_NewPublicTemplate")]
        private static extern IntPtr wolfTPM2_NewPublicTemplate();

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_FreePublicTemplate")]
        private static extern int wolfTPM2_FreePublicTemplate(IntPtr template);

        internal IntPtr template;
        public Template()
        {
            template = wolfTPM2_NewPublicTemplate();
        }
        ~Template() => Dispose(false);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        protected virtual void Dispose(bool disposing)
        {
            /* free un-managed objects */
            if (template != IntPtr.Zero) {
                /* ignore return code */
                wolfTPM2_FreePublicTemplate(template);
                template = IntPtr.Zero;
            }
        }


        /* non-device functions: template and auth */
        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_RSA")]
        private static extern int wolfTPM2_GetKeyTemplate_RSA(IntPtr publicTemplate,
                                                              ulong objectAttributes);
        /// <summary>
        /// Prepares a TPM public template for new RSA key based on user
        /// selected object attributes
        /// </summary>
        /// <param name="objectAttributes">Bit mask of TPM2_Object values to define the Key object attributes.</param>
        /// <returns>Success: 0</returns>
        public int GetKeyTemplate_RSA(ulong objectAttributes)
        {
            int rc = wolfTPM2_GetKeyTemplate_RSA(template,
                                                 objectAttributes);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetKeyTemplate_RSA", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_ECC")]
        private static extern int wolfTPM2_GetKeyTemplate_ECC(IntPtr publicTemplate,
                                                              ulong objectAttributes,
                                                              uint curve,
                                                              uint sigScheme);
        /// <summary>
        /// Prepares a TPM public template for new ECC key based on user
        /// selected object attributes
        /// </summary>
        /// <param name="objectAttributes">Bit mask of TPM2_Object values to define the Key object attributes.</param>
        /// <returns>Success: 0</returns>
        public int GetKeyTemplate_ECC(ulong objectAttributes, TPM2_ECC curve,
            TPM2_Alg sigScheme)
        {
            int rc = wolfTPM2_GetKeyTemplate_ECC(template,
                                                 objectAttributes,
                                                 (uint)curve,
                                                 (uint)sigScheme);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetKeyTemplate_ECC", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_Symmetric")]
        private static extern int wolfTPM2_GetKeyTemplate_Symmetric(
            IntPtr publicTemplate, int keyBits, uint algMode, int isSign,
            int isDecrypt);
        /// <summary>
        /// Prepares a TPM public template for new symmetric key based on user
        /// selected object attributes
        /// </summary>
        /// <param name="objectAttributes">Bit mask of TPM2_Object values to define the Key object attributes.</param>
        /// <returns>Success: 0</returns>
        public int GetKeyTemplate_Symmetric(int keyBits,
                                            TPM2_Alg algMode,
                                            bool isSign,
                                            bool isDecrypt)
        {
            int rc = wolfTPM2_GetKeyTemplate_Symmetric(template,
                                                       keyBits,
                                                       (uint)algMode,
                                                       isSign ? 1 : 0,
                                                       isDecrypt ? 1 : 0);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetKeyTemplate_Symmetric", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_RSA_EK")]
        private static extern int wolfTPM2_GetKeyTemplate_RSA_EK(IntPtr publicTemplate);
        /// <summary>
        /// Prepares a TPM public template for generating the TPM Endorsement Key of RSA type
        /// </summary>
        /// <returns>Success: 0</returns>
        public int GetKeyTemplate_RSA_EK()
        {
            int rc = wolfTPM2_GetKeyTemplate_RSA_EK(template);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetKeyTemplate_RSA_EK", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_ECC_EK")]
        private static extern int wolfTPM2_GetKeyTemplate_ECC_EK(IntPtr publicTemplate);
        /// <summary>
        /// Prepares a TPM public template for generating the TPM Endorsement Key of ECC type
        /// </summary>
        /// <returns>Success: 0</returns>
        public int GetKeyTemplate_ECC_EK()
        {
            int rc = wolfTPM2_GetKeyTemplate_ECC_EK(template);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetKeyTemplate_ECC_EK", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_RSA_SRK")]
        private static extern int wolfTPM2_GetKeyTemplate_RSA_SRK(IntPtr publicTemplate);
        /// <summary>
        /// Prepares a TPM public template for generating a new TPM Storage Key of RSA type
        /// </summary>
        /// <returns>Success: 0</returns>
        public int GetKeyTemplate_RSA_SRK()
        {
            int rc = wolfTPM2_GetKeyTemplate_RSA_SRK(template);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetKeyTemplate_RSA_SRK", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_ECC_SRK")]
        private static extern int wolfTPM2_GetKeyTemplate_ECC_SRK(IntPtr publicTemplate);
        /// <summary>
        /// Prepares a TPM public template for generating a new TPM Storage Key of ECC type
        /// </summary>
        /// <returns>Success: 0</returns>
        public int GetKeyTemplate_ECC_SRK()
        {
            int rc = wolfTPM2_GetKeyTemplate_ECC_SRK(template);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetKeyTemplate_ECC_SRK", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_RSA_AIK")]
        private static extern int wolfTPM2_GetKeyTemplate_RSA_AIK(IntPtr publicTemplate);
        /// <summary>
        /// Prepares a TPM public template for generating a new TPM Attestation Key of RSA type
        /// </summary>
        /// <returns>Success: 0</returns>
        public int GetKeyTemplate_RSA_AIK()
        {
            int rc = wolfTPM2_GetKeyTemplate_RSA_AIK(template);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetKeyTemplate_RSA_AIK", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_ECC_AIK")]
        private static extern int wolfTPM2_GetKeyTemplate_ECC_AIK(IntPtr publicTemplate);
        /// <summary>
        /// Prepares a TPM public template for generating a new TPM Attestation Key of ECC type
        /// </summary>
        /// <returns>Success: 0</returns>
        public int GetKeyTemplate_ECC_AIK()
        {
            int rc = wolfTPM2_GetKeyTemplate_ECC_AIK(template);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetKeyTemplate_ECC_AIK", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_SetKeyTemplate_Unique")]
        private static extern int wolfTPM2_SetKeyTemplate_Unique(IntPtr publicTemplate, string unique, int uniqueSz);

        /// <summary>
        /// Sets the unique area of a public template used by Create or CreatePrimary.
        /// </summary>
        /// <param name="unique">optional pointer to buffer to populate unique area of public template. If NULL, the buffer will be zeroized.</param>
        /// <returns>Success: 0</returns>
        public int SetKeyTemplate_Unique(string unique)
        {
            int rc = wolfTPM2_SetKeyTemplate_Unique(template,
                                                    unique, unique.Length);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetKeyTemplate_ECC_AIK", rc);
            }
            return rc;
        }
    }

    public class Session : IDisposable
    {
        const string DLLNAME = "wolftpm";

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_NewSession")]
        private static extern IntPtr wolfTPM2_NewSession();

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_FreeSession")]
        private static extern int wolfTPM2_FreeSession(IntPtr session);

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetHandleRefFromSession")]
        private static extern IntPtr wolfTPM2_GetHandleRefFromSession(IntPtr session);

        internal IntPtr session;
        internal int sessionIdx;

        public Session()
        {
            session = wolfTPM2_NewSession();
            sessionIdx = 1; /* for most commands the index is 1 */
        }
        public Session(int index)
        {
            session = wolfTPM2_NewSession();
            sessionIdx = index;
        }
        ~Session() => Dispose(false);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        protected virtual void Dispose(bool disposing)
        {
            /* free un-managed objects */
            if (session != IntPtr.Zero) {
                /* ignore return code */
                wolfTPM2_FreeSession(session);
                session = IntPtr.Zero;
            }
        }

        /// <summary>
        /// Retrieve the WOLFTPM2_HANDLE pointer from a this Session.
        /// </summary>
        public IntPtr GetHandle()
        {
            return wolfTPM2_GetHandleRefFromSession(session);
        }

        /// <summary>
        /// Start an authenticated session (salted / unbound) with parameter
        /// encryption and set session for authorization of the primary key.
        /// </summary>
        /// <param name="device">Reference to Device class reference</param>
        /// <param name="parentKey"></param>
        /// <param name="encDecAlg">The algorithm for parameter encryption (TPM2_Alg.NULL, TPM2_Alg.CFB or TPM2_Alg.XOR). Using NULL disables parameter encryption</param>
        /// <returns>Success: 0</returns>
        public int StartAuth(Device device, Key parentKey, TPM2_Alg encDecAlg)
        {
            int rc;

            /* Algorithm modes: With parameter encryption use CFB or XOR.
             * For HMAC only (no parameter encryption) use NULL. */
            if (encDecAlg != TPM2_Alg.NULL &&
                encDecAlg != TPM2_Alg.CFB &&
                encDecAlg != TPM2_Alg.XOR) {
                return (int)Status.BAD_FUNC_ARG;
            }

            /* Start an authenticated session (salted / unbound) with
             * parameter encryption */
            rc = device.StartSession(this, parentKey, IntPtr.Zero,
                (byte)SE.HMAC, (int)encDecAlg);
            if (rc == (int)Status.TPM_RC_SUCCESS) {
                /* Set session for authorization of the primary key */
                rc = device.SetAuthSession(this, this.sessionIdx,
                    (byte)(SESSION_mask.decrypt | SESSION_mask.encrypt |
                        SESSION_mask.continueSession));
            }

            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception("StartAuth", rc);
            }
            return rc;
        }

        /// <summary>
        /// Stop an authenticated session
        /// </summary>
        /// <param name="device">Reference to Device class reference</param>
        /// <returns>Success: 0</returns>
        public int StopAuth(Device device)
        {
            /* Clear the auth index, since the auth session is ending */
            device.ClearAuthSession(this, this.sessionIdx);

            /* Unload session */
            return device.UnloadHandle(this);
        }
    }

    public class Csr : IDisposable
    {
        const string DLLNAME = "wolftpm";

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_NewCSR")]
        private static extern IntPtr wolfTPM2_NewCSR();

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_FreeCSR")]
        private static extern int wolfTPM2_FreeCSR(IntPtr csr);

        internal IntPtr csr;

        public Csr()
        {
            csr = wolfTPM2_NewCSR();
        }
        ~Csr() => Dispose(false);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        protected virtual void Dispose(bool disposing)
        {
            /* free un-managed objects */
            if (csr != IntPtr.Zero) {
                /* ignore return code */
                wolfTPM2_FreeCSR(csr);
                csr = IntPtr.Zero;
            }
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CSR_SetCustomExt")]
        private static extern int wolfTPM2_CSR_SetCustomExt(IntPtr dev,
                                                            IntPtr csr,
                                                            int critical,
                                                            byte[] oid,
                                                            byte[] der,
                                                            uint derSz);

        /// <summary>
        /// Helper for Certificate Signing Request (CSR) generation to set a
        /// custom request extension oid and value usage for a Csr class.
        /// </summary>
        /// <param name="oid">Dot separated oid as a string.
        ///     For example "1.2.840.10045.3.1.7"</param>
        /// <param name="der">The der encoding of the content of the extension.</param>
        /// <param name="critical">If 0, the extension will not be marked critical,
        ///     otherwise it will be marked critical.</param>
        /// <returns>Success: 0</returns>
        public int SetCustomExtension(string oid, string der, int critical)
        {
            /* Allocate a buffer here for OID and DER, since the underlying
             * library wants to have the pointer available later. The garbage
             * collection at end of caller frees memory */
            byte[] oidBuf = Encoding.ASCII.GetBytes(oid);
            byte[] derBuf = Encoding.ASCII.GetBytes(der);
            int rc = wolfTPM2_CSR_SetCustomExt(IntPtr.Zero, csr, critical,
                                              oidBuf, derBuf, (uint)der.Length);
            if (rc != (int)Status.TPM_RC_SUCCESS &&
                rc != (int)Status.NOT_COMPILED_IN) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_CSR_SetCustomExt", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CSR_SetKeyUsage")]
        private static extern int wolfTPM2_CSR_SetKeyUsage(IntPtr dev,
                                                            IntPtr csr,
                                                            string keyUsage);

        /// <summary>
        /// Helper for Certificate Signing Request (CSR) generation to set a
        /// key usage for a Csr class.
        /// </summary>
        /// <param name="keyUsage">keyUsage string list of comma separated key usage attributes.
        ///     Possible values: any, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping and OCSPSigning
        ///     Default: "serverAuth,clientAuth,codeSigning"</param>
        /// <returns>Success: 0</returns>
        public int SetKeyUsage(string keyUsage)
        {
            int rc = wolfTPM2_CSR_SetKeyUsage(IntPtr.Zero, csr, keyUsage);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_CSR_SetKeyUsage", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CSR_SetSubject")]
        private static extern int wolfTPM2_CSR_SetSubject(IntPtr dev,
                                                          IntPtr csr,
                                                          string subject);
        /// <summary>
        /// Helper for Certificate Signing Request (CSR) generation to set a
        /// subject for a Csr class.
        /// </summary>
        /// <param name="subject">distinguished name string using /CN= syntax.
        ///     Example: "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"</param>
        /// <returns>Success: 0</returns>
        public int SetSubject(string subject)
        {
            int rc = wolfTPM2_CSR_SetSubject(IntPtr.Zero, csr, subject);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_CSR_SetSubject", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CSR_MakeAndSign")]
        private static extern int wolfTPM2_CSR_MakeAndSign(IntPtr dev,
                                                           IntPtr csr,
                                                           IntPtr key,
                                                           int outFormat,
                                                           byte[] output,
                                                           int outputSz);
        /// <summary>
        /// Helper for Certificate Signing Request (CSR) generation using a TPM based key.
        /// Uses a provided WOLFTPM2_CSR structure with subject and key usage already set.
        /// </summary>
        /// <param name="device">Reference to Device class reference</param>
        /// <param name="keyBlob">Reference to KeyBlob class</param>
        /// <param name="outputFormat">X509_Format.PEM or X509_Format.DER</param>
        /// <param name="output">byte array for output</param>
        /// <returns>Success: Positive integer (size of the output)</returns>
        public int MakeAndSign(Device device,
                               KeyBlob keyBlob,
                               X509_Format outputFormat,
                               byte[] output)
        {
            int rc = wolfTPM2_CSR_MakeAndSign(device.Ref, csr,
                keyBlob.keyblob, (int)outputFormat, output, output.Length);
            /* positive return code is length of resulting output */
            if (rc < 0) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_CSR_MakeAndSign", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CSR_MakeAndSign_ex")]
        private static extern int wolfTPM2_CSR_MakeAndSign_ex(IntPtr dev,
                                                              IntPtr csr,
                                                              IntPtr key,
                                                              int outFormat,
                                                              byte[] output,
                                                              int outputSz,
                                                              int sigType,
                                                              int selfSign,
                                                              int devId);

        /// <summary>
        /// Helper for Certificate Signing Request (CSR) generation using a TPM based key.
        /// Uses a provided Csr class with subject and key usage already set.
        /// </summary>
        /// <param name="device">Reference to Device class reference</param>
        /// <param name="keyBlob">Reference to KeyBlob class</param>
        /// <param name="outputFormat">X509_Format.PEM or X509_Format.DER</param>
        /// <param name="output">byte array for output</param>
        /// <param name="sigType">Use 0 to automatically select SHA2-256 based on keyType (CTC_SHA256wRSA or CTC_SHA256wECDSA).
        ///     See wolfCrypt "enum Ctc_SigType" for list of possible values.</param>
        /// <param name="selfSignCert">If set to 1 (non-zero) then result will be a self signed certificate.
        ///     Zero (0) will generate a CSR (Certificate Signing Request) to be used by a CA.</param>
        /// <returns>Success: Positive integer (size of the output)</returns>
        public int MakeAndSign(Device device,
                               KeyBlob keyBlob,
                               X509_Format outputFormat,
                               byte[] output,
                               int sigType,
                               int selfSign)
        {
            int rc = wolfTPM2_CSR_MakeAndSign_ex(device.Ref, csr,
                keyBlob.keyblob, (int)outputFormat, output, output.Length,
                sigType, selfSign, Device.INVALID_DEVID);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_CSR_MakeAndSign_ex", rc);
            }
            return rc;
        }
    }

    public class Device : IDisposable
    {
        /* ================================================================== */
        /* Constants                                                          */
        /* ================================================================== */

        const string DLLNAME = "wolftpm";

        public const int MAX_KEYBLOB_BYTES = 1024;
        public const int MAX_TPM_BUFFER = 2048;
        public const int INVALID_DEVID = -2;
        private IntPtr device = IntPtr.Zero;

        public Device()
        {
            device = wolfTPM2_New();
        }
        ~Device() => Dispose(false);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        protected virtual void Dispose(bool disposing)
        {
            /* free un-managed objects */
            if (device != IntPtr.Zero) {
                /* ignore return code */
                wolfTPM2_Free(device);
                device = IntPtr.Zero;
            }
        }

        public IntPtr Ref
        {
            get {
                return device;
            }
        }


        /* Note that this one is not an empty; it actually calls wolfTPM2_Init()
         * as a convenience for the user. */
        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_New")]
        private static extern IntPtr wolfTPM2_New();

        /* WOLFTPM_API int wolfTPM2_Free(WOLFTPM2_DEV *dev); */
        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_Free")]
        private static extern int wolfTPM2_Free(IntPtr dev);

        /* ================================================================== */
        /* Native Wrappers                                                    */
        /* ================================================================== */

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_SelfTest")]
        private static extern int wolfTPM2_SelfTest(IntPtr dev);
        /// <summary>
        /// Asks the TPM to perform its self test.
        /// </summary>
        /// <returns>0: Success; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int SelfTest()
        {
            int rc = wolfTPM2_SelfTest(device);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_SelfTest", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetRandom")]
        private static extern int wolfTPM2_GetRandom(IntPtr dev,
                                                     byte[] buf,
                                                     int len);
        /// <summary>
        /// Get a set of random number, generated with the TPM RNG or wolfcrypt RNG.
        /// Define WOLFTPM2_USE_HW_RNG to use the TPM RNG source
        /// </summary>
        /// <param name="buf">Buffer used to store the generated random numbers.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int GetRandom(byte[] buf)
        {
            int rc = wolfTPM2_GetRandom(device, buf, buf.Length);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_GetRandom", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CreateSRK")]
        private static extern int wolfTPM2_CreateSRK(IntPtr dev,
                                                     IntPtr srkKey,
                                                     uint alg,
                                                     string auth,
                                                     int authSz);
        /// <summary>
        /// Generates a new TPM Primary Key that will be used as a Storage Key for other TPM keys.
        /// </summary>
        /// <param name="srkKey">Empty key, to store information about the new EK.</param>
        /// <param name="alg">TPM2_Alg.RSA or TPM2_Alg.ECC</param>
        /// <param name="auth">String constant specifying the password authorization for the TPM 2.0 Key.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int CreateSRK(Key srkKey,
                             TPM2_Alg alg,
                             string auth)
        {
            int rc = wolfTPM2_CreateSRK(device,
                                        srkKey.key,
                                        (uint)alg,
                                        auth,
                                        auth.Length);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_CreateSRK", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_StartSession")]
        private static extern int wolfTPM2_StartSession(IntPtr dev,
                                                        IntPtr session,
                                                        IntPtr tmpKey,
                                                        IntPtr bind,
                                                        byte sesType,
                                                        int encDecAlg);
        /// <summary>
        /// Create a TPM session, Policy, HMAC or Trial. This wrapper can also be used to start TPM
        /// session for parameter encryption; see wolfTPM nvram or keygen example.
        /// </summary>
        /// <param name="tpmSession">An empty session object.</param>
        /// <param name="tmpKey">A key that will be used as a salt for the session.</param>
        /// <param name="bind">A handle that will be used to make the session bounded.</param>
        /// <param name="sesType">The session type (HMAC, Policy or Trial).</param>
        /// <param name="encDecAlg">The algorithm for parameter encryption (TPM2_Alg.NULL, TPM2_Alg.CFB or TPM2_Alg.XOR). Using NULL disables parameter encryption</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments.</returns>
        public int StartSession(Session tpmSession,
                                Key tmpKey,
                                IntPtr bind,
                                byte sesType,
                                int encDecAlg)
        {
            int rc = wolfTPM2_StartSession(device,
                                           tpmSession.session,
                                           tmpKey.key,
                                           bind,
                                           sesType,
                                           encDecAlg);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_StartSession", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_SetAuthSession")]
        private static extern int wolfTPM2_SetAuthSession(IntPtr dev,
                                                          int index,
                                                          IntPtr tpmSession,
                                                          byte sessionAttributes);
        /// <summary>
        /// Sets a TPM Authorization slot using the provided TPM session handle, index and session
        /// attributes. This wrapper is useful for configuring TPM sessions, e.g. session for
        /// parameter encryption.
        /// </summary>
        /// <param name="tpmSession">A session object.</param>
        /// <param name="index">Integer value, specifying the TPM Authorization slot (0, 1, 2, or 3).</param>
        /// <param name="sessionAttributes">Integer value from TPMA_SESSION selecting one or more attributes for the Session.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments.</returns>
        public int SetAuthSession(Session tpmSession,
                                  int index,
                                  byte sessionAttributes)
        {
            /* For sessionAttributes suggest using:
             * (byte)(SESSION_mask.decrypt | SESSION_mask.encrypt | SESSION_mask.continueSession)
             */
            int rc = wolfTPM2_SetAuthSession(device,
                                             index,
                                             tpmSession.session,
                                             sessionAttributes);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_SetAuthSession", rc);
            }
            return rc;
        }

        /// <summary>
        /// Clears a TPM Authorization slot using the provided TPM session handle and index.
        /// </summary>
        /// <param name="tpmSession">A session object.</param>
        /// <param name="index">Integer value, specifying the TPM Authorization slot (0, 1, 2, or 3).</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments.</returns>
        public int ClearAuthSession(Session tpmSession,
                                    int index)
        {
            int rc = wolfTPM2_SetAuthSession(device,
                                             index,
                                             IntPtr.Zero,
                                             0);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_SetAuthSession clear", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_ReadPublicKey")]
        private static extern int wolfTPM2_ReadPublicKey(IntPtr dev,
                                                         IntPtr key,
                                                         ulong handle);

        /// <summary>
        /// Helper function to receive the public part of a loaded TPM object using its handle. The
        /// public part of a TPM symmetric keys contains just TPM meta data.
        /// </summary>
        /// <param name="key">An empty key object.</param>
        /// <param name="handle">Integer value specifying handle of a loaded TPM object.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int ReadPublicKey(Key key, ulong handle)
        {
            int rc = wolfTPM2_ReadPublicKey(device, key.key, handle);
            if (rc != (int)Status.TPM_RC_SUCCESS &&
                rc != (int)Status.TPM_RC_HANDLE)
            {
                throw new WolfTpm2Exception(
                    "wolfTPM2_ReadPublicKey", rc);
            }
            return rc;
        }

        /// <summary>
        /// Helper function to receive the public part of a loaded TPM object using its handle. The
        /// public part of a TPM symmetric keys contains just TPM meta data.
        /// </summary>
        /// <param name="keyBlob">An empty KeyBlob object.</param>
        /// <param name="handle">Integer value specifying handle of a loaded TPM object.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int ReadPublicKey(KeyBlob keyBlob, ulong handle)
        {
            int rc = wolfTPM2_ReadPublicKey(device, keyBlob.keyblob, handle);
            if (rc != (int)Status.TPM_RC_SUCCESS &&
                rc != (int)Status.TPM_RC_HANDLE)
            {
                throw new WolfTpm2Exception(
                    "wolfTPM2_ReadPublicKey", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CreateKey")]
        private static extern int wolfTPM2_CreateKey(
            IntPtr dev,
            IntPtr keyBlob,
            IntPtr parent,
            IntPtr publicTemplate,
            string auth,
            int authSz);
        /// <summary>
        /// Single function to prepare and create a TPM 2.0 Key. This function only creates the key
        /// material and stores it into the keyblob argument. To load the key use wolfTPM2_LoadKey.
        /// </summary>
        /// <param name="keyBlob">An empty KeyBlob object.</param>
        /// <param name="parent">A handle specifying the a 2.0 Primary Key to be used as the parent(Storage Key).</param>
        /// <param name="publicTemplate">A template populated manually or using one of the GetKeyTemplate_...() wrappers.</param>
        /// <param name="auth">A string specifying the password authorization for the TPM 2.0 Key.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int CreateKey(KeyBlob keyBlob,
                             Key parent,
                             Template publicTemplate,
                             string auth)
        {
            int rc = wolfTPM2_CreateKey(device,
                                        keyBlob.keyblob,
                                        parent.GetHandle(),
                                        publicTemplate.template,
                                        auth,
                                        auth.Length);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_CreateKey", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_LoadKey")]
        private static extern int wolfTPM2_LoadKey(
            IntPtr dev,
            IntPtr keyBlob,
            IntPtr parent);
        /// <summary>
        /// Single function to load a TPM 2.0 key. To load a TPM 2.0 key its parent(Primary Key)
        /// should also be loaded prior to this operation. Primary Keys are loaded when they are
        /// created.
        /// </summary>
        /// <param name="keyBlob">An empty KeyBlob object.</param>
        /// <param name="parent">A handle specifying the a 2.0 Primary Key to be used as the parent(Storage Key)</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int LoadKey(KeyBlob keyBlob,
                           Key parent)
        {
            int rc = wolfTPM2_LoadKey(device, keyBlob.keyblob,
                                      parent.GetHandle());
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_LoadKey", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_NVStoreKey")]
        private static extern int wolfTPM2_NVStoreKey(IntPtr dev,
            ulong primaryHandle, IntPtr key, ulong persistentHandle);

        /// <summary>
        /// Helper function to store a TPM 2.0 Key into the TPM's NVRAM.
        /// </summary>
        /// <param name="key">The TPM 2.0 key to be stored.</param>
        /// <param name="primaryHandle">Integer value, specifying a TPM 2.0 Hierarchy. Typically TPM_RH_OWNER.</param>
        /// <param name="persistentHandle">Integer value, specifying an existing nvIndex.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int StoreKey(Key key, ulong primaryHandle, ulong persistentHandle)
        {
            int rc = wolfTPM2_NVStoreKey(device, primaryHandle, key.key,
                                         persistentHandle);
            if (rc != (int)Status.TPM_RC_SUCCESS &&
                rc != (int)Status.TPM_RC_NV_UNAVAILABLE) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_NVStoreKey", rc);
            }
            return rc;
        }

        /// <summary>
        /// Helper function to store a TPM 2.0 Key into the TPM's NVRAM.
        /// </summary>
        /// <param name="keyBlob">The TPM 2.0 keyBlob to be stored.</param>
        /// <param name="primaryHandle">Integer value, specifying a TPM 2.0 Hierarchy. Typically TPM_RH_OWNER.</param>
        /// <param name="persistentHandle">Integer value, specifying an existing nvIndex.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int StoreKey(KeyBlob keyBlob, ulong primaryHandle, ulong persistentHandle)
        {
            int rc = wolfTPM2_NVStoreKey(device, primaryHandle, keyBlob.keyblob,
                                         persistentHandle);
            if (rc != (int)Status.TPM_RC_SUCCESS &&
                rc != (int)Status.TPM_RC_NV_UNAVAILABLE) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_NVStoreKey", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_NVDeleteKey")]
        private static extern int wolfTPM2_NVDeleteKey(IntPtr dev,
            ulong primaryHandle, IntPtr key);

        /// <summary>
        /// Helper function to delete a TPM 2.0 Key from the TPM's NVRAM.
        /// </summary>
        /// <param name="key">The TPM 2.0 key to be stored.</param>
        /// <param name="primaryHandle">Integer value, specifying a TPM 2.0 Hierarchy. Typically TPM_RH_OWNER.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int DeleteKey(Key key, ulong primaryHandle)
        {
            int rc = wolfTPM2_NVDeleteKey(device, primaryHandle, key.key);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_NVDeleteKey", rc);
            }
            return rc;
        }

        /// <summary>
        /// Helper function to delete a TPM 2.0 Key from the TPM's NVRAM.
        /// </summary>
        /// <param name="keyBlob">The TPM 2.0 keyBlob to be stored.</param>
        /// <param name="primaryHandle">Integer value, specifying a TPM 2.0 Hierarchy. Typically TPM_RH_OWNER.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int DeleteKey(KeyBlob keyBlob, ulong primaryHandle)
        {
            int rc = wolfTPM2_NVDeleteKey(device, primaryHandle, keyBlob.keyblob);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_NVDeleteKey", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_ImportRsaPrivateKey")]
        private static extern int wolfTPM2_ImportRsaPrivateKey(
            IntPtr dev,
            IntPtr parentKey,
            IntPtr keyBlob,
            byte[] rsaPub,
            int rsaPubSz,
            int exponent,
            byte[] rsaPriv,
            int rsaPrivSz,
            uint scheme,
            uint hashAlg);

        /// <summary>
        /// Import an external RSA private key.
        /// </summary>
        /// <param name="parentKey">The parent key. Can be NULL for external keys and the key will be imported under the OWNER hierarchy.</param>
        /// <param name="keyBlob">An empty keyBlob.</param>
        /// <param name="rsaPub">Buffer containing the public part of the RSA key.</param>
        /// <param name="exponent">Integer value specifying the RSA exponent.</param>
        /// <param name="rsaPriv">Buffer containing the private material of the RSA key.</param>
        /// <param name="scheme">Value from TPM2_Alg specifying the RSA scheme.</param>
        /// <param name="hashAlg">Value from TPM2_Alg specifying a supported TPM 2.0 hash algorithm.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code; BUFFER_E: arguments size is larger than what the TPM buffers allow.</returns>
        public int ImportRsaPrivateKey(
            Key parentKey,
            KeyBlob keyBlob,
            byte[] rsaPub,
            int exponent,
            byte[] rsaPriv,
            TPM2_Alg scheme,
            TPM2_Alg hashAlg)
        {
            int rc = wolfTPM2_ImportRsaPrivateKey(device,
                                                  parentKey.key,
                                                  keyBlob.keyblob,
                                                  rsaPub,
                                                  rsaPub.Length,
                                                  exponent,
                                                  rsaPriv,
                                                  rsaPriv.Length,
                                                  (uint)scheme,
                                                  (uint)hashAlg);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_ImportRsaPrivateKey", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_LoadRsaPublicKey")]
        private static extern int wolfTPM2_LoadRsaPublicKey(
            IntPtr dev,
            IntPtr key,
            byte[] rsaPub,
            int rsaPubSz,
            int exponent);

        /// <summary>
        /// Helper function to import the public part of an external RSA key. Recommended for use,
        /// because it does not require TPM format of the public part.
        /// </summary>
        /// <param name="key">An empty key.</param>
        /// <param name="rsaPub">Buffer containing the public part of the RSA key.</param>
        /// <param name="exponent">Integer value specifying the RSA exponent.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int LoadRsaPublicKey(Key key,
                                    byte[] rsaPub,
                                    int exponent)
        {
            int rc = wolfTPM2_LoadRsaPublicKey(device,
                                               key.key,
                                               rsaPub,
                                               rsaPub.Length,
                                               exponent);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_LoadRsaPublicKey", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_LoadRsaPrivateKey")]
        private static extern int wolfTPM2_LoadRsaPrivateKey(
            IntPtr dev,
            IntPtr parentKey,
            IntPtr key,
            byte[] rsaPub,
            int rsaPubSz,
            int exponent,
            byte[] rsaPriv,
            int rsaPrivSz);

        /// <summary>
        /// Helper function to import and load an external RSA private key in one step.
        /// </summary>
        /// <param name="parentKey">The parent key. Can be NULL for external keys and the key will be imported under the OWNER hierarchy.</param>
        /// <param name="key">An empty key.</param>
        /// <param name="rsaPub">Buffer containing the public part of the RSA key.</param>
        /// <param name="exponent">Integer value specifying the RSA exponent.</param>
        /// <param name="rsaPriv">Buffer containing the private material of the RSA key.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int LoadRsaPrivateKey(
            Key parentKey,
            Key key,
            byte[] rsaPub,
            int exponent,
            byte[] rsaPriv)
        {
            int rc = wolfTPM2_LoadRsaPrivateKey(
                device,
                parentKey.key,
                key.key,
                rsaPub,
                rsaPub.Length,
                exponent,
                rsaPriv,
                rsaPriv.Length);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_LoadRsaPrivateKey", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CreatePrimaryKey")]
        private static extern int wolfTPM2_CreatePrimaryKey(
            IntPtr dev,
            IntPtr key,
            ulong primaryHandle,
            IntPtr publicTemplate,
            string auth,
            int authSz);

        /// <summary>
        /// Single function to prepare and create a TPM 2.0 Primary Key. TPM 2.0 allows only
        /// asymmetric RSA or ECC primary keys. Afterwards, both symmetric and asymmetric keys can
        ///  be created under a TPM 2.0 Primary Key. Typically, Primary Keys are used to create
        /// Hierarchies of TPM 2.0 Keys. The TPM uses a Primary Key to wrap the other keys, signing
        /// or decrypting.
        /// </summary>
        /// <param name="key">An empty key.</param>
        /// <param name="primaryHandle">Integer value specifying one of four TPM 2.0 Primary Seeds: TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM or TPM_RH_NULL.</param>
        /// <param name="publicTemplate">A template populated manually or using one of the GetKeyTemplate_...() wrappers.</param>
        /// <param name="auth">A string specifying the password authorization for the Primary Key.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int CreatePrimaryKey(
            Key key,
            TPM_RH primaryHandle,
            Template publicTemplate,
            string auth)
        {
            int rc = wolfTPM2_CreatePrimaryKey(
                device,
                key.key,
                (ulong)primaryHandle,
                publicTemplate.template,
                auth,
                !string.IsNullOrEmpty(auth) ? auth.Length : 0);
            if (rc != (int)Status.TPM_RC_SUCCESS) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_CreatePrimaryKey", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CSR_Generate_ex")]
        private static extern int wolfTPM2_CSR_Generate_ex(
            IntPtr dev,
            IntPtr key,
            string subject,
            string keyUsage,
            int outFormat,
            byte[] output,
            int outputSz,
            int sigType,
            int selfSignCert,
            int devId);

        /// <summary>
        /// Helper for Certificate Signing Request (CSR) generation using a TPM based key.
        /// Single shot API for outputting a CSR or self-signed cert based on TPM key.
        /// </summary>
        /// <param name="keyBlob">Reference to KeyBlob class</param>
        /// <param name="subject">distinguished name string using /CN= syntax.
        ///     Example: "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"</param>
        /// <param name="keyUsage">keyUsage string list of comma separated key usage attributes.
        ///     Possible values: any, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping and OCSPSigning
        ///     Default: "serverAuth,clientAuth,codeSigning"</param>
        /// <param name="outputFormat">X509_Format.PEM or X509_Format.DER</param>
        /// <param name="output">byte array for output</param>
        /// <param name="sigType">Use 0 to automatically select SHA2-256 based on keyType (CTC_SHA256wRSA or CTC_SHA256wECDSA).
        ///     See wolfCrypt "enum Ctc_SigType" for list of possible values.</param>
        /// <param name="selfSignCert">If set to 1 (non-zero) then result will be a self signed certificate.
        ///     Zero (0) will generate a CSR (Certificate Signing Request) to be used by a CA.</param>
        /// <returns>Success: Positive integer (size of the output)</returns>
        public int GenerateCSR(
            KeyBlob keyBlob,
            string subject,
            string keyUsage,
            X509_Format outputFormat,
            byte[] output,
            int sigType,
            int selfSignCert)
        {
            int rc = wolfTPM2_CSR_Generate_ex(
                device,
                keyBlob.keyblob,
                subject,
                keyUsage,
                (int)outputFormat,
                output, output.Length,
                sigType,
                selfSignCert,
                Device.INVALID_DEVID);
            /* positive return code is length of resulting output */
            if (rc < 0) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_CSR_Generate_ex", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CSR_Generate")]
        private static extern int wolfTPM2_CSR_Generate(
            IntPtr dev,
            IntPtr key,
            string subject,
            string keyUsage,
            int outFormat,
            byte[] output,
            int outputSz);
        public int GenerateCSR(
            KeyBlob keyBlob,
            string subject,
            string keyUsage,
            X509_Format outputFormat,
            byte[] output)
        {
            int rc = wolfTPM2_CSR_Generate(
                device,
                keyBlob.keyblob,
                subject,
                keyUsage,
                (int)outputFormat,
                output, output.Length);
            /* positive return code is length of resulting output */
            if (rc < 0) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_CSR_Generate", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_RsaEncrypt")]
        private static extern int wolfTPM2_RsaEncrypt(
            IntPtr dev, IntPtr key, uint padScheme, byte[] plain, int plainSz,
            byte[] enc, ref int encSz);

        /// <summary>
        /// Perform RSA encryption using a TPM 2.0 key
        /// </summary>
        /// <param name="keyBlob">A key blob holding TPM key material.</param>
        /// <param name="plain">Buffer containing the arbitrary data for encryption.</param>
        /// <param name="enc">Buffer where the encrypted data will be stored.</param>
        /// <param name="padScheme">Integer from TPM_ALG_ID, specifying the padding scheme.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int RsaEncrypt(KeyBlob keyBlob, byte[] plain, byte[] enc,
            TPM2_Alg padScheme)
        {
            int encSz = enc.Length;
            int rc = wolfTPM2_RsaEncrypt(device, keyBlob.keyblob, (uint)padScheme,
                plain, plain.Length, enc, ref encSz);
            if (rc == 0) {
                rc = encSz;
            }
            else {
                throw new WolfTpm2Exception(
                    "wolfTPM2_RsaEncrypt", rc);
            }

            return rc;
        }
        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_RsaDecrypt")]
        private static extern int wolfTPM2_RsaDecrypt(
            IntPtr dev, IntPtr key, uint padScheme, byte[] enc, int encSz,
            byte[] plain, ref int plainSz);

        /// <summary>
        /// Perform RSA decryption using a TPM 2.0 key
        /// </summary>
        /// <param name="keyBlob">A key blob holding TPM key material.</param>
        /// <param name="enc">Buffer containing the encrypted data.</param>
        /// <param name="plain">Buffer containing the decrypted data.</param>
        /// <param name="padScheme">Integer from TPM_ALG_ID, specifying the padding scheme.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int RsaDecrypt(KeyBlob keyBlob, byte[] enc, byte[] plain,
            TPM2_Alg padScheme)
        {
            int plainSz = enc.Length;
            int rc = wolfTPM2_RsaDecrypt(device, keyBlob.keyblob, (uint)padScheme,
                enc, enc.Length, plain, ref plainSz);
            if (rc == 0) {
                rc = plainSz;
            }
            else {
                throw new WolfTpm2Exception(
                    "wolfTPM2_RsaDecrypt", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_SignHashScheme")]
        private static extern int wolfTPM2_SignHashScheme(
            IntPtr dev, IntPtr key, byte[] digest, int digestSz,
            byte[] sig, ref int sigSz, uint sigAlg, uint hashAlg);

        /// <summary>
        /// Advanced helper function to sign arbitrary data using a TPM key, and specify the signature scheme and hashing algorithm
        /// </summary>
        /// <param name="keyBlob">A key blob holding TPM key material.</param>
        /// <param name="digest">Buffer containing arbitrary data.</param>
        /// <param name="sig">Buffer containing the generated signature.</param>
        /// <param name="sigAlg">Integer from TPMI_ALG_SIG_SCHEME, specifying a supported TPM 2.0 signature scheme.</param>
        /// <param name="hashAlg">Integer from TPMI_ALG_HASH, specifying a supported TPM 2.0 hash algorithm.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int SignHashScheme(KeyBlob keyBlob, byte[] digest, byte[] sig,
            TPM2_Alg sigAlg, TPM2_Alg hashAlg)
        {
            int sigSz = sig.Length;
            int rc = wolfTPM2_SignHashScheme(device, keyBlob.keyblob,
                digest, digest.Length, sig, ref sigSz,
                (uint)sigAlg, (uint)hashAlg);
            if (rc == 0) {
                rc = sigSz;
            }
            else {
                throw new WolfTpm2Exception(
                    "wolfTPM2_SignHashScheme", rc);
            }
            return rc;
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_VerifyHashScheme")]
        private static extern int wolfTPM2_VerifyHashScheme(
            IntPtr dev, IntPtr key, byte[] sig, int sigSz,
            byte[] digest, int digestSz, uint sigAlg, uint hashAlg);

        /// <summary>
        /// Advanced helper function to verify a TPM generated signature
        /// </summary>
        /// <param name="keyBlob">A key blob holding a TPM 2.0 key material.</param>
        /// <param name="sig">Buffer containing the generated signature.</param>
        /// <param name="digest">Buffer containing the signed data.</param>
        /// <param name="sigAlg">Integer from TPMI_ALG_SIG_SCHEME, specifying a supported TPM 2.0 signature scheme.</param>
        /// <param name="hashAlg">Integer from TPMI_ALG_HASH, specifying a supported TPM 2.0 hash algorithm.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int VerifyHashScheme(KeyBlob keyBlob, byte[] sig, byte[] digest,
            TPM2_Alg sigAlg, TPM2_Alg hashAlg)
        {
            int rc = wolfTPM2_VerifyHashScheme(device, keyBlob.keyblob,
                sig, sig.Length, digest, digest.Length,
                (uint)sigAlg, (uint)hashAlg);
            if (rc != 0 && rc != (int)Status.TPM_RC_SIGNATURE) {
                throw new WolfTpm2Exception(
                    "wolfTPM2_VerifyHashScheme", rc);
            }
            return rc;
        }


        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_UnloadHandle")]
        private static extern int wolfTPM2_UnloadHandle(IntPtr dev, IntPtr handle);

        /// <summary>
        /// Use to discard any TPM loaded object
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int UnloadHandle(Key key)
        {
            return wolfTPM2_UnloadHandle(device, key.GetHandle());
        }

        /// <summary>
        /// Use to discard any TPM loaded object
        /// </summary>
        /// <param name="keyBlob">The keyBlob.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int UnloadHandle(KeyBlob keyBlob)
        {
            return wolfTPM2_UnloadHandle(device, keyBlob.GetHandle());
        }

        /// <summary>
        /// Use to discard any TPM loaded object
        /// </summary>
        /// <param name="tpmSession">The TPM session.</param>
        /// <returns>0: Success; BAD_FUNC_ARG: check provided arguments; TPM_RC_FAILURE: check TPM IO and TPM return code.</returns>
        public int UnloadHandle(Session tpmSession)
        {
            return wolfTPM2_UnloadHandle(device, tpmSession.GetHandle());
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetHandleValue")]
        private static extern uint wolfTPM2_GetHandleValue(IntPtr handle);

        /// <summary>
        /// Get the 32-bit handle value from the WOLFTPM2_HANDLE
        /// </summary>
        /// <param name="handle">pointer to WOLFTPM2_HANDLE structure</param>
        /// <param name=""></param>
        /// <returns>TPM_HANDLE value from TPM</returns>
        public uint GetHandleValue(IntPtr handle)
        {
            return wolfTPM2_GetHandleValue(handle);
        }

        [DllImport(DLLNAME, EntryPoint = "TPM2_GetRCString")]
        private static extern IntPtr TPM2_GetRCString(int rc);
        public string GetErrorString(int rc)
        {
            IntPtr err = TPM2_GetRCString(rc);
            return Marshal.PtrToStringAnsi(err);
        }

        /// <summary>
        /// Get a human readable string for any TPM 2.0 return code.
        /// </summary>
        /// <param name="rc">Integer value representing a TPM return code.</param>
        /// <returns>Pointer to a string constant.</returns>
        public string GetErrorString(Status rc)
        {
            return GetErrorString((int)rc);
        }

    }
}
