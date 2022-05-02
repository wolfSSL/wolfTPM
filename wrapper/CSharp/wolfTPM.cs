using System;
using System.Runtime.InteropServices;

namespace wolfTPM
{

    public enum Status : int
    {
        TPM_RC_SUCCESS = 0,
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

    public enum SE : byte
    {
        HMAC = 0x00,
        POLICY = 0x01,
        TRIAL = 0x03,
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


    }

    public class Session
    {
        const string DLLNAME = "wolftpm";

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_NewSession")]
        private static extern IntPtr wolfTPM2_NewSession();

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_FreeSession")]
        private static extern int wolfTPM2_FreeSession(IntPtr session);


        internal IntPtr session;

        public Session()
        {
            session = wolfTPM2_NewSession();
        }

        ~Session()
        {
            if (session != IntPtr.Zero)
            {
                // TODO: check return value
                wolfTPM2_FreeSession(session);
            }
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
        private static extern int wolfTPM2_StartSession(IntPtr dev, IntPtr session,
                                                        IntPtr tmpKey, IntPtr bind, byte sesType, int encDecAlg);
        public int StartSession(IntPtr session,
                                 Key tmpKey,
                                 IntPtr bind,
                                 byte sesType,
                                 int encDecAlg)
        {
            return wolfTPM2_StartSession(device,
                                          session,
                                          tmpKey.key,
                                          bind,
                                          sesType,
                                          encDecAlg);
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
                                      parent.GetHandleRefFromKey(),
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
            return wolfTPM2_LoadKey(device, keyBlob.keyblob, parent.GetHandleRefFromKey());
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

        [DllImport(DLLNAME, EntryPoint = "wolfTPM2_UnloadHandle")]
        private static extern int wolfTPM2_UnloadHandle(IntPtr dev, IntPtr handle);
        public int UnloadHandle(Key key)
        {
            return wolfTPM2_UnloadHandle(device, key.key);
        }

        public int UnloadHandle(KeyBlob keyblob)
        {
            return wolfTPM2_UnloadHandle(device, keyblob.keyblob);
        }


    }
}
