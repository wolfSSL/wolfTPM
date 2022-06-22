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
using System.Runtime.InteropServices;

namespace wolfTPM
{

    public enum Status : int
    {
        TPM_RC_SUCCESS = 0,
        BAD_FUNC_ARG = -173,
    }

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

    public enum SE : byte
    {
        HMAC = 0x00,
        POLICY = 0x01,
        TRIAL = 0x03,
    }

    public enum SESSION_mask : byte
    {
        continueSession = 0x01,
        auditExclusive  = 0x02,
        auditReset      = 0x04,
        decrypt         = 0x20,
        encrypt         = 0x40,
        audit           = 0x80,
    }

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

    public class KeyBlob
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

        internal IntPtr keyblob;

        public KeyBlob()
        {
            keyblob = wolfTPM2_NewKeyBlob();
        }

        ~KeyBlob()
        {
            if (keyblob != IntPtr.Zero)
            {
                // TODO: check return value?
                wolfTPM2_FreeKeyBlob(keyblob);
            }
        }

        public int GetKeyBlobAsBuffer(byte[] buffer)
        {
            return wolfTPM2_GetKeyBlobAsBuffer(buffer, buffer.Length, keyblob);
        }

        public int SetKeyBlobFromBuffer(byte[] buffer)
        {
            return wolfTPM2_SetKeyBlobFromBuffer(keyblob, buffer, buffer.Length);
        }

        public IntPtr GetHandle()
        {
            return wolfTPM2_GetHandleRefFromKeyBlob(keyblob);
        }
    }

    public class Key
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
            IntPtr key,
            string auth,
            int authSz);

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetHandleRefFromKey")]
        private static extern IntPtr wolfTPM2_GetHandleRefFromKey(IntPtr key);

        internal IntPtr key;

        public Key()
        {
            key = wolfTPM2_NewKey();
        }

        ~Key()
        {
            if (key != IntPtr.Zero)
            {
                // TODO: check return value
                wolfTPM2_FreeKey(key);
            }
        }

        public IntPtr GetHandle()
        {
            return wolfTPM2_GetHandleRefFromKey(key);
        }

        /* kept for backwards compatibility, use GetHandle */
        public IntPtr GetHandleRefFromKey()
        {
            return wolfTPM2_GetHandleRefFromKey(key);
        }

        public int SetKeyAuthPassword(string auth)
        {
            return wolfTPM2_SetKeyAuthPassword(key,
                                               auth,
                                               auth.Length);
        }

    }

    public class Template
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

        ~Template()
        {
            wolfTPM2_FreePublicTemplate(template);
        }

        /* non-device functions: template and auth */
        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_RSA")]
        private static extern int wolfTPM2_GetKeyTemplate_RSA(IntPtr publicTemplate,
                                                              ulong objectAttributes);
        public int GetKeyTemplate_RSA(ulong objectAttributes)
        {
            return wolfTPM2_GetKeyTemplate_RSA(template,
                                               objectAttributes);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_ECC")]
        private static extern int wolfTPM2_GetKeyTemplate_ECC(IntPtr publicTemplate,
                                                              ulong objectAttributes,
                                                              uint curve,
                                                              uint sigScheme);
        public int GetKeyTemplate_ECC(ulong objectAttributes, TPM2_ECC curve,
            TPM2_Alg sigScheme)
        {
            return wolfTPM2_GetKeyTemplate_ECC(template, objectAttributes,
                (uint)curve, (uint)sigScheme);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_Symmetric")]
        private static extern int wolfTPM2_GetKeyTemplate_Symmetric(
            IntPtr publicTemplate, int keyBits, uint algMode, int isSign,
            int isDecrypt);
        public int GetKeyTemplate_Symmetric(int keyBits,
                                            TPM2_Alg algMode,
                                            bool isSign,
                                            bool isDecrypt)
        {
            return wolfTPM2_GetKeyTemplate_Symmetric(template,
                                                     keyBits,
                                                     (uint)algMode,
                                                     isSign ? 1 : 0,
                                                     isDecrypt ? 1 : 0);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_RSA_EK")]
        private static extern int wolfTPM2_GetKeyTemplate_RSA_EK(IntPtr publicTemplate);
        public int GetKeyTemplate_RSA_EK()
        {
            return wolfTPM2_GetKeyTemplate_RSA_EK(template);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_ECC_EK")]
        private static extern int wolfTPM2_GetKeyTemplate_ECC_EK(IntPtr publicTemplate);
        public int GetKeyTemplate_ECC_EK()
        {
            return wolfTPM2_GetKeyTemplate_ECC_EK(template);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_RSA_SRK")]
        private static extern int wolfTPM2_GetKeyTemplate_RSA_SRK(IntPtr publicTemplate);
        public int GetKeyTemplate_RSA_SRK()
        {
            return wolfTPM2_GetKeyTemplate_RSA_SRK(template);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_ECC_SRK")]
        private static extern int wolfTPM2_GetKeyTemplate_ECC_SRK(IntPtr publicTemplate);
        public int GetKeyTemplate_ECC_SRK()
        {
            return wolfTPM2_GetKeyTemplate_ECC_SRK(template);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_RSA_AIK")]
        private static extern int wolfTPM2_GetKeyTemplate_RSA_AIK(IntPtr publicTemplate);
        public int GetKeyTemplate_RSA_AIK()
        {
            return wolfTPM2_GetKeyTemplate_RSA_AIK(template);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetKeyTemplate_ECC_AIK")]
        private static extern int wolfTPM2_GetKeyTemplate_ECC_AIK(IntPtr publicTemplate);
        public int GetKeyTemplate_ECC_AIK()
        {
            return wolfTPM2_GetKeyTemplate_ECC_AIK(template);
        }
    }

    public class Session
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

        ~Session()
        {
            if (session != IntPtr.Zero)
            {
                /* ignore return code on free */
                wolfTPM2_FreeSession(session);
            }
        }

        public IntPtr GetHandle()
        {
            return wolfTPM2_GetHandleRefFromSession(session);
        }

        public int StartAuth(Device device, Key parentKey, TPM2_Alg algMode)
        {
            int ret;

            /* Algorithm modes: With parameter encryption use CFB or XOR.
             * For HMAC only (no parameter encryption) use NULL. */
            if (algMode != TPM2_Alg.NULL &&
                algMode != TPM2_Alg.CFB &&
                algMode != TPM2_Alg.XOR) {
                return (int)Status.BAD_FUNC_ARG;
            }

            /* Start an authenticated session (salted / unbound) with
             * parameter encryption */
            ret = device.StartSession(this, parentKey, IntPtr.Zero,
                (byte)SE.HMAC, (int)algMode);
            if (ret == (int)Status.TPM_RC_SUCCESS) {
                /* Set session for authorization of the primary key */
                ret = device.SetAuthSession(this, this.sessionIdx,
                    (byte)(SESSION_mask.decrypt | SESSION_mask.encrypt |
                        SESSION_mask.continueSession));
            }

            return ret;
        }

        public int StopAuth(Device device)
        {
            int ret;

            /* Clear the auth index, since the auth session is ending */
            device.ClearAuthSession(this, this.sessionIdx);

            /* Unload session */
            ret = device.UnloadHandle(this);

            return ret;
        }
    }

    public class Device
    {
        /* ================================================================== */
        /* Constants                                                          */
        /* ================================================================== */

        const string DLLNAME = "wolftpm";

        public const int MAX_KEYBLOB_BYTES = 1024;
        private IntPtr device = IntPtr.Zero;

        public Device()
        {
            device = wolfTPM2_New();
        }

        ~Device()
        {
            if (device != IntPtr.Zero)
            {
                wolfTPM2_Free(device);
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
        public int SelfTest()
        {
            return wolfTPM2_SelfTest(device);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_GetRandom")]
        private static extern int wolfTPM2_GetRandom(IntPtr dev,
                                                     byte[] buf,
                                                     int len);
        public int GetRandom(byte[] buf)
        {
            return wolfTPM2_GetRandom(device, buf, buf.Length);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CreateSRK")]
        private static extern int wolfTPM2_CreateSRK(IntPtr dev,
                                                     IntPtr srkKey,
                                                     int alg,
                                                     string auth,
                                                     int authSz);
        public int CreateSRK(Key srkKey,
                             int alg,
                             string auth)
        {
            return wolfTPM2_CreateSRK(device,
                                      srkKey.key,
                                      alg,
                                      auth,
                                      auth.Length);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_StartSession")]
        private static extern int wolfTPM2_StartSession(IntPtr dev,
                                                        IntPtr session,
                                                        IntPtr tmpKey,
                                                        IntPtr bind,
                                                        byte sesType,
                                                        int encDecAlg);
        public int StartSession(Session tpmSession,
                                Key tmpKey,
                                IntPtr bind,
                                byte sesType,
                                int encDecAlg)
        {
            return wolfTPM2_StartSession(device,
                                         tpmSession.session,
                                         tmpKey.key,
                                         bind,
                                         sesType,
                                         encDecAlg);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_SetAuthSession")]
        private static extern int wolfTPM2_SetAuthSession(IntPtr dev,
                                                          int index,
                                                          IntPtr tpmSession,
                                                          byte sessionAttributes);
        public int SetAuthSession(Session tpmSession,
                                  int index,
                                  byte sessionAttributes)
        {
            /* For sessionAttributes suggest using:
             * (byte)(SESSION_mask.decrypt | SESSION_mask.encrypt | SESSION_mask.continueSession)
             */
            return wolfTPM2_SetAuthSession(device,
                                           index,
                                           tpmSession.session,
                                           sessionAttributes);
        }

        public int ClearAuthSession(Session tpmSession,
                                    int index)
        {
            return wolfTPM2_SetAuthSession(device,
                                           index,
                                           IntPtr.Zero,
                                           0);
        }


        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_ReadPublicKey")]
        private static extern int wolfTPM2_ReadPublicKey(IntPtr dev,
                                                         IntPtr key,
                                                         ulong handle);
        public int ReadPublicKey(Key key,
                                 ulong handle)
        {
            return wolfTPM2_ReadPublicKey(device,
                                           key.key,
                                           handle);
        }


        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CreateKey")]
        private static extern int wolfTPM2_CreateKey(
            IntPtr dev,
            IntPtr keyBlob,
            IntPtr parent,
            IntPtr publicTemplate,
            string auth,
            int authSz);
        public int CreateKey(KeyBlob keyBlob,
                             Key parent,
                             Template publicTemplate,
                             string auth)
        {
            return wolfTPM2_CreateKey(device,
                                      keyBlob.keyblob,
                                      parent.GetHandle(),
                                      publicTemplate.template,
                                      auth,
                                      auth.Length);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_LoadKey")]
        private static extern int wolfTPM2_LoadKey(
            IntPtr dev,
            IntPtr keyBlob,
            IntPtr parent);
        public int LoadKey(KeyBlob keyBlob,
                           Key parent)
        {
            return wolfTPM2_LoadKey(device, keyBlob.keyblob, parent.GetHandle());
        }


        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_NVStoreKey")]
        private static extern int wolfTPM2_NVStoreKey(IntPtr dev,
            IntPtr primaryHandle, IntPtr key, IntPtr persistentHandle);
        public int StoreKey(Key key, IntPtr primaryHandle, IntPtr persistentHandle)
        {
            return wolfTPM2_NVStoreKey(device, primaryHandle, key.GetHandle(),
                persistentHandle);
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

        public int ImportRsaPrivateKey(
            Key parentKey,
            KeyBlob keyBlob,
            byte[] rsaPub,
            int exponent,
            byte[] rsaPriv,
            uint scheme,
            uint hashAlg)
        {
            return wolfTPM2_ImportRsaPrivateKey(device,
                                                parentKey.key,
                                                keyBlob.keyblob,
                                                rsaPub,
                                                rsaPub.Length,
                                                exponent,
                                                rsaPriv,
                                                rsaPriv.Length,
                                                scheme,
                                                hashAlg);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_LoadRsaPublicKey")]
        private static extern int wolfTPM2_LoadRsaPublicKey(
            IntPtr dev,
            IntPtr key,
            byte[] rsaPub,
            int rsaPubSz,
            int exponent);
        public int LoadRsaPublicKey(Key key,
                                    byte[] rsaPub,
                                    int exponent)
        {
            return wolfTPM2_LoadRsaPublicKey(device,
                                             key.key,
                                             rsaPub,
                                             rsaPub.Length,
                                             exponent);
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
        public int LoadRsaPrivateKey(
            Key parentKey,
            Key key,
            byte[] rsaPub,
            int exponent,
            byte[] rsaPriv)
        {
            return wolfTPM2_LoadRsaPrivateKey(
                device,
                parentKey.key,
                key.key,
                rsaPub,
                rsaPub.Length,
                exponent,
                rsaPriv,
                rsaPriv.Length);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_CreatePrimaryKey")]
        private static extern int wolfTPM2_CreatePrimaryKey(
            IntPtr dev,
            IntPtr key,
            ulong primaryHandle,
            IntPtr publicTemplate,
            string auth,
            int authSz);
        public int CreatePrimaryKey(
            Key key,
            TPM_RH primaryHandle,
            Template publicTemplate,
            string auth)
        {
            return wolfTPM2_CreatePrimaryKey(
                device,
                key.key,
                (ulong)primaryHandle,
                publicTemplate.template,
                auth,
                !string.IsNullOrEmpty(auth) ? auth.Length : 0);
        }

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_UnloadHandle")]
        private static extern int wolfTPM2_UnloadHandle(IntPtr dev, IntPtr handle);
        public int UnloadHandle(Key key)
        {
            return wolfTPM2_UnloadHandle(device, key.GetHandle());
        }

        public int UnloadHandle(KeyBlob keyBlob)
        {
            return wolfTPM2_UnloadHandle(device, keyBlob.GetHandle());
        }

        public int UnloadHandle(Session tpmSession)
        {
            return wolfTPM2_UnloadHandle(device, tpmSession.GetHandle());
        }

    }
}
