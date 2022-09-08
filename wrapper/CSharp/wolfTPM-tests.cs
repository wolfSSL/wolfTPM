/* wolfTPM-tests.cs
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

/* Tests for C# wrapper using NUnit */

using NUnit.Framework;
using System;
using System.IO;
using System.Text;
using wolfTPM;

namespace tpm_csharp_test
{
    [TestFixture]
    public class WolfTPMTest
    {
        /* Globals used for setup and teardown */
        private Device device = new Device();
        private Key parent_key;
        private static byte[] priv_buffer = {
            0xd5, 0x38, 0x1b, 0xc3, 0x8f, 0xc5, 0x93, 0x0c,
            0x47, 0x0b, 0x6f, 0x35, 0x92, 0xc5, 0xb0, 0x8d,
            0x46, 0xc8, 0x92, 0x18, 0x8f, 0xf5, 0x80, 0x0a,
            0xf7, 0xef, 0xa1, 0xfe, 0x80, 0xb9, 0xb5, 0x2a,
            0xba, 0xca, 0x18, 0xb0, 0x5d, 0xa5, 0x07, 0xd0,
            0x93, 0x8d, 0xd8, 0x9c, 0x04, 0x1c, 0xd4, 0x62,
            0x8e, 0xa6, 0x26, 0x81, 0x01, 0xff, 0xce, 0x8a,
            0x2a, 0x63, 0x34, 0x35, 0x40, 0xaa, 0x6d, 0x80,
            0xde, 0x89, 0x23, 0x6a, 0x57, 0x4d, 0x9e, 0x6e,
            0xad, 0x93, 0x4e, 0x56, 0x90, 0x0b, 0x6d, 0x9d,
            0x73, 0x8b, 0x0c, 0xae, 0x27, 0x3d, 0xde, 0x4e,
            0xf0, 0xaa, 0xc5, 0x6c, 0x78, 0x67, 0x6c, 0x94,
            0x52, 0x9c, 0x37, 0x67, 0x6c, 0x2d, 0xef, 0xbb,
            0xaf, 0xdf, 0xa6, 0x90, 0x3c, 0xc4, 0x47, 0xcf,
            0x8d, 0x96, 0x9e, 0x98, 0xa9, 0xb4, 0x9f, 0xc5,
            0xa6, 0x50, 0xdc, 0xb3, 0xf0, 0xfb, 0x74, 0x17
        };

        private static byte[] pub_buffer = {
            0xc3, 0x03, 0xd1, 0x2b, 0xfe, 0x39, 0xa4, 0x32,
            0x45, 0x3b, 0x53, 0xc8, 0x84, 0x2b, 0x2a, 0x7c,
            0x74, 0x9a, 0xbd, 0xaa, 0x2a, 0x52, 0x07, 0x47,
            0xd6, 0xa6, 0x36, 0xb2, 0x07, 0x32, 0x8e, 0xd0,
            0xba, 0x69, 0x7b, 0xc6, 0xc3, 0x44, 0x9e, 0xd4,
            0x81, 0x48, 0xfd, 0x2d, 0x68, 0xa2, 0x8b, 0x67,
            0xbb, 0xa1, 0x75, 0xc8, 0x36, 0x2c, 0x4a, 0xd2,
            0x1b, 0xf7, 0x8b, 0xba, 0xcf, 0x0d, 0xf9, 0xef,
            0xec, 0xf1, 0x81, 0x1e, 0x7b, 0x9b, 0x03, 0x47,
            0x9a, 0xbf, 0x65, 0xcc, 0x7f, 0x65, 0x24, 0x69,
            0xa6, 0xe8, 0x14, 0x89, 0x5b, 0xe4, 0x34, 0xf7,
            0xc5, 0xb0, 0x14, 0x93, 0xf5, 0x67, 0x7b, 0x3a,
            0x7a, 0x78, 0xe1, 0x01, 0x56, 0x56, 0x91, 0xa6,
            0x13, 0x42, 0x8d, 0xd2, 0x3c, 0x40, 0x9c, 0x4c,
            0xef, 0xd1, 0x86, 0xdf, 0x37, 0x51, 0x1b, 0x0c,
            0xa1, 0x3b, 0xf5, 0xf1, 0xa3, 0x4a, 0x35, 0xe4,
            0xe1, 0xce, 0x96, 0xdf, 0x1b, 0x7e, 0xbf, 0x4e,
            0x97, 0xd0, 0x10, 0xe8, 0xa8, 0x08, 0x30, 0x81,
            0xaf, 0x20, 0x0b, 0x43, 0x14, 0xc5, 0x74, 0x67,
            0xb4, 0x32, 0x82, 0x6f, 0x8d, 0x86, 0xc2, 0x88,
            0x40, 0x99, 0x36, 0x83, 0xba, 0x1e, 0x40, 0x72,
            0x22, 0x17, 0xd7, 0x52, 0x65, 0x24, 0x73, 0xb0,
            0xce, 0xef, 0x19, 0xcd, 0xae, 0xff, 0x78, 0x6c,
            0x7b, 0xc0, 0x12, 0x03, 0xd4, 0x4e, 0x72, 0x0d,
            0x50, 0x6d, 0x3b, 0xa3, 0x3b, 0xa3, 0x99, 0x5e,
            0x9d, 0xc8, 0xd9, 0x0c, 0x85, 0xb3, 0xd9, 0x8a,
            0xd9, 0x54, 0x26, 0xdb, 0x6d, 0xfa, 0xac, 0xbb,
            0xff, 0x25, 0x4c, 0xc4, 0xd1, 0x79, 0xf4, 0x71,
            0xd3, 0x86, 0x40, 0x18, 0x13, 0xb0, 0x63, 0xb5,
            0x72, 0x4e, 0x30, 0xc4, 0x97, 0x84, 0x86, 0x2d,
            0x56, 0x2f, 0xd7, 0x15, 0xf7, 0x7f, 0xc0, 0xae,
            0xf5, 0xfc, 0x5b, 0xe5, 0xfb, 0xa1, 0xba, 0xd3
        };

        private byte[] generatedAES;
        private byte[] generatedRSA;

        private static void PrintByteArray(byte[] bytes)
        {
            var sb = new StringBuilder("buf: { ");
            foreach (var b in bytes)
            {
                sb.Append(b + ", ");
            }
            sb.Append("} (");
            sb.Append(bytes.Length);
            sb.Append(" bytes)");
            Console.WriteLine(sb.ToString());
        }

        private static void DumpByteArray(string filename, byte[] bytes)
        {
            var writer = new BinaryWriter(File.OpenWrite(filename));
            writer.Write(bytes);
            writer.Close();
        }

        private void GetSRK(Key srkKey, string auth)
        {
            int rc = device.CreateSRK(srkKey,
                                      TPM2_Alg.RSA,
                                      auth);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        private void GenerateKey(string algorithm)
        {
            int rc = (int)Status.TPM_RC_SUCCESS;
            KeyBlob blob = new KeyBlob();
            Template template = new Template();
            byte[] blob_buffer = new byte[Device.MAX_KEYBLOB_BYTES];

            if (algorithm == "RSA")
            {
                rc = template.GetKeyTemplate_RSA((ulong)(
                                                    TPM2_Object.sensitiveDataOrigin |
                                                    TPM2_Object.userWithAuth |
                                                    TPM2_Object.decrypt |
                                                    TPM2_Object.sign |
                                                    TPM2_Object.noDA));
                Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
            }
            else if (algorithm == "AES")
            {
                rc = template.GetKeyTemplate_Symmetric(256, TPM2_Alg.CTR, true, true);
                Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
            }
            else
            {
                Console.WriteLine("Unexpected algorithm name!!!");
                Assert.Fail();
            }

            rc = device.CreateKey(blob, parent_key, template,
                                   "ThisIsMyKeyAuth");
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.LoadKey(blob, parent_key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = blob.GetKeyBlobAsBuffer(blob_buffer);
            if (rc > 0)
            {
                Array.Resize(ref blob_buffer, rc);
                if (algorithm == "RSA")
                {
                    generatedRSA = blob_buffer;
                }
                else if (algorithm == "AES")
                {
                    generatedAES = blob_buffer;
                }
                else
                {
                    Console.WriteLine("Unexpected algorithm name!");
                    return;
                }
                rc = (int)Status.TPM_RC_SUCCESS;
            }
            else
            {
                Console.WriteLine("wolfTPM2_GetKeyBlobAsBuffer() failed");
                rc = -1;
            }

            rc = device.UnloadHandle(blob);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        private void LoadGeneratedKey(string algorithm)
        {
            int rc = (int)Status.TPM_RC_SUCCESS;
            KeyBlob blob = new KeyBlob();
            byte[] blob_buffer;

            if (algorithm == "RSA")
            {
                blob_buffer = generatedRSA;
            }
            else if (algorithm == "AES")
            {
                blob_buffer = generatedAES;
            }
            else
            {
                Console.WriteLine("Unexpected algorithm name!");
                return;
            }

            rc = blob.SetKeyBlobFromBuffer(blob_buffer);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.LoadKey(blob, parent_key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = blob.SetKeyAuthPassword("ThisIsMyKeyAuth");
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.UnloadHandle(blob);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }


        [SetUp]
        public void TestInit()
        {
            parent_key = new Key();
            GetSRK(parent_key, "ThisIsMyStorageKeyAuth");
        }

        [TearDown]
        public void TestCleanup()
        {
            int rc = device.UnloadHandle(parent_key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TrySelfTest()
        {
            int rc = device.SelfTest();
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TryFillBufferWithRandom()
        {
            int rc;
            const int bufSz = 256;
            byte[] buf = new byte[bufSz];

            rc = device.GetRandom(buf);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
            PrintByteArray(buf);

            Assert.That(buf, Has.Some.GreaterThan(0));
        }

        [Test]
        public void TryGenerateAndLoadRSA()
        {
            GenerateKey("RSA");
            LoadGeneratedKey("RSA");
        }

        [Test]
        public void TryGenerateAndLoadAES()
        {
            GenerateKey("AES");
            LoadGeneratedKey("AES");
        }

        [Test]
        public void TryAuthSession()
        {
            int rc;
            Session tpmSession = new Session();
            const int bufSz = 256;
            byte[] buf = new byte[bufSz];

            Console.WriteLine("Testing Parameter Encryption with AES CFB");

            rc = tpmSession.StartAuth(device, parent_key, TPM2_Alg.CFB);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            /* Do sensitive operation */
            rc = device.GetRandom(buf);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = tpmSession.StopAuth(device);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TryLoadRSAPublicKey()
        {
            int rc;
            Key pub_key;
            int exp = 0x10001;

            Console.WriteLine("Testing load RSA Public key");
            PrintByteArray(pub_buffer);

            pub_key = new Key();

            rc = device.LoadRsaPublicKey(pub_key, pub_buffer, exp);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.UnloadHandle(pub_key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TryLoadRSAPrivateKey()
        {
            int rc;
            Key priv_key;
            int exp = 0x10001;

            Console.WriteLine("Testing load RSA Private key");

            PrintByteArray(pub_buffer);
            PrintByteArray(priv_buffer);

            priv_key = new Key();

            rc = device.LoadRsaPrivateKey(parent_key, priv_key,
                                           pub_buffer, exp,
                                           priv_buffer);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.UnloadHandle(priv_key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TryImportRSAPrivateKey()
        {
            int rc;

            KeyBlob blob;
            int exp = 0x10001;

            Console.WriteLine("Testing import RSA Private key");

            PrintByteArray(pub_buffer);
            PrintByteArray(priv_buffer);

            blob = new KeyBlob();

            rc = device.ImportRsaPrivateKey(parent_key, blob,
                                             pub_buffer,
                                             exp, priv_buffer,
                                             TPM2_Alg.NULL,
                                             TPM2_Alg.NULL);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.UnloadHandle(blob);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TryCreatePrimaryKey()
        {
            int rc;
            Key key = new Key();
            Template template = new Template();

            Console.WriteLine("Testing create primary");

            /* Test creating the primary RSA endorsement key (EK) */
            rc = template.GetKeyTemplate_RSA_EK();
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.CreatePrimaryKey(key, TPM_RH.ENDORSEMENT, template, null);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.UnloadHandle(key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TryCreateCustomPrimaryKey()
        {
            int rc;
            Key key = new Key();
            Template template = new Template();

            Console.WriteLine("Testing create primary custom");

            /* Test creating custom SRK (different than one Windows uses) */
            rc = template.GetKeyTemplate_RSA_SRK();
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = template.SetKeyTemplate_Unique("myUniqueValue");
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.CreatePrimaryKey(key, TPM_RH.OWNER, template, null);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            /* use temporary handle (in memory), cannot store to
             * Non-Volatile (NV) Memory on Windows */
            Console.WriteLine("Primary Key Handle 0x{0}",
                device.GetHandleValue(key.GetHandle()).ToString("X8"));

            rc = device.UnloadHandle(key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TryGetErrorString()
        {
            string err = device.GetErrorString(Status.BAD_FUNC_ARG);
            if (!string.IsNullOrEmpty(err))
                Assert.AreEqual(err, "Bad function argument");
        }

        [Test]
        public void TryGenerateCSR()
        {
            int rc;
            KeyBlob keyBlob = new KeyBlob();
            Template template = new Template();
            byte[] output = new byte[Device.MAX_TPM_BUFFER];

            string subject = "/C=US/ST=Oregon/L=Portland/SN=Development" +
                             "/O=wolfSSL/OU=RSA/CN=www.wolfssl.com" +
                             "/emailAddress=info@wolfssl.com";
            string keyUsage = "serverAuth,clientAuth,codeSigning";

            Console.WriteLine("Testing generate CSR");

            rc = template.GetKeyTemplate_RSA((ulong)(
                                            TPM2_Object.sensitiveDataOrigin |
                                            TPM2_Object.userWithAuth |
                                            TPM2_Object.decrypt |
                                            TPM2_Object.sign |
                                            TPM2_Object.noDA));
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.CreateKey(keyBlob, parent_key, template,
                "ThisIsMyKeyAuth");
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.LoadKey(keyBlob, parent_key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            /* Generate a CSR (Certificate Signing Request) */
            rc = device.GenerateCSR(keyBlob, subject, keyUsage,
                X509_Format.PEM, output);
            Assert.That(rc, Is.GreaterThan(0));

            Console.WriteLine("CSR PEM {0} bytes", rc.ToString());
            DumpByteArray("csr.pem", output);

            rc = device.UnloadHandle(keyBlob);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TryGenerateCert()
        {
            int rc;
            KeyBlob keyBlob = new KeyBlob();
            Template template = new Template();
            byte[] output = new byte[Device.MAX_TPM_BUFFER];

            string subject = "/C=US/ST=Oregon/L=Portland/SN=Development" +
                             "/O=wolfSSL/OU=RSA/CN=www.wolfssl.com" +
                             "/emailAddress=info@wolfssl.com";
            string keyUsage = "serverAuth,clientAuth,codeSigning";

            Console.WriteLine("Testing generate Certificate");

            rc = template.GetKeyTemplate_RSA((ulong)(
                                            TPM2_Object.sensitiveDataOrigin |
                                            TPM2_Object.userWithAuth |
                                            TPM2_Object.decrypt |
                                            TPM2_Object.sign |
                                            TPM2_Object.noDA));
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.CreateKey(keyBlob, parent_key, template,
                "ThisIsMyKeyAuth");
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.LoadKey(keyBlob, parent_key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            /* Generate a self signed certificate */
            rc = device.GenerateCSR(keyBlob, subject, keyUsage,
                X509_Format.PEM, output, 0, 1);
            Assert.That(rc, Is.GreaterThan(0));

            Console.WriteLine("Cert PEM {0} bytes", rc.ToString());
            DumpByteArray("cert.pem", output);

            rc = device.UnloadHandle(keyBlob);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TryGenerateCSRCustomOID()
        {
            int rc;
            KeyBlob keyBlob = new KeyBlob();
            Template template = new Template();
            Csr csr = new Csr();
            byte[] output = new byte[Device.MAX_TPM_BUFFER];

            string subject = "/C=US/ST=Oregon/L=Portland/SN=Development" +
                             "/O=wolfSSL/OU=RSA/CN=www.wolfssl.com" +
                             "/emailAddress=info@wolfssl.com";
            string keyUsage = "serverAuth,clientAuth,codeSigning";

            string custOid =    "1.2.3.4.5";
            string custOidVal = "This is NOT a critical extension";

            Console.WriteLine("Testing generate CSR custom");

            rc = template.GetKeyTemplate_RSA((ulong)(
                                            TPM2_Object.sensitiveDataOrigin |
                                            TPM2_Object.userWithAuth |
                                            TPM2_Object.decrypt |
                                            TPM2_Object.sign |
                                            TPM2_Object.noDA));
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.CreateKey(keyBlob, parent_key, template,
                "ThisIsMyKeyAuth");
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.LoadKey(keyBlob, parent_key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = csr.SetSubject(subject);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = csr.SetKeyUsage(keyUsage);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = csr.SetCustomExtension(custOid, custOidVal, 0);
            /* if custom OID support is not compiled in then test is
             * inconclusive */
            if (rc == (int)Status.NOT_COMPILED_IN) {
                device.UnloadHandle(keyBlob);
                Assert.Inconclusive();
            }
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = csr.MakeAndSign(device, keyBlob, X509_Format.PEM, output);
            Assert.That(rc, Is.GreaterThan(0));

            Console.WriteLine("CSR PEM {0} bytes", rc.ToString());
            DumpByteArray("csr_customExt.pem", output);

            rc = device.UnloadHandle(keyBlob);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TryKeyNV()
        {
            int rc;
            KeyBlob keyBlob = new KeyBlob();
            Template template = new Template();
            ulong testPersistentHandle = 0x81000202;

            Console.WriteLine("Testing key with NV");

            rc = template.GetKeyTemplate_RSA((ulong)(
                                            TPM2_Object.sensitiveDataOrigin |
                                            TPM2_Object.userWithAuth |
                                            TPM2_Object.decrypt |
                                            TPM2_Object.sign |
                                            TPM2_Object.noDA));
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            /* Generate new key */
            rc = device.CreateKey(keyBlob, parent_key, template,
                "ThisIsMyKeyAuth");
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            /* Load key */
            rc = device.LoadKey(keyBlob, parent_key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            /* Read public key */
            rc = device.ReadPublicKey(keyBlob,
                device.GetHandleValue(keyBlob.GetHandle()));
            if (rc == (int)Status.TPM_RC_HANDLE) {
                /* valid error if the handle is not found */
                rc = 0; /* ignore error */
            }
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            /* Store key */
            rc = device.StoreKey(keyBlob, (ulong)TPM_RH.OWNER, testPersistentHandle);
            if (rc == (int)Status.TPM_RC_NV_UNAVAILABLE) {
                device.UnloadHandle(keyBlob);

                Assert.Inconclusive();
                /* Windows TBS does not allow storing keys to NV */
                rc = 0; /* ignore error */
            }
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            /* Delete Key */
            rc = device.DeleteKey(keyBlob, (ulong)TPM_RH.OWNER);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.UnloadHandle(keyBlob);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TryRsaEncryptDecrypt()
        {
            int rc;
            KeyBlob keyBlob = new KeyBlob();
            Template template = new Template();
            const int RsaKeySz = 256;
            byte[] message = new byte[RsaKeySz];
            byte[] cipher = new byte[RsaKeySz];
            byte[] plain = new byte[RsaKeySz];

            Console.WriteLine("Testing RSA Encrypt/Decrypt");

            rc = template.GetKeyTemplate_RSA((ulong)(
                                            TPM2_Object.sensitiveDataOrigin |
                                            TPM2_Object.userWithAuth |
                                            TPM2_Object.decrypt |
                                            TPM2_Object.sign |
                                            TPM2_Object.noDA));
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.CreateKey(keyBlob, parent_key, template,
                "ThisIsMyKeyAuth");
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.LoadKey(keyBlob, parent_key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            /* Perform RSA encrypt / decrypt (no pad) */
            for (int i=0; i<message.Length; i++)  {
                message[i] = 0x11;
            }
            rc = device.RsaEncrypt(keyBlob, message, cipher, TPM2_Alg.NULL);
            Assert.AreEqual(RsaKeySz, rc);

            rc = device.RsaDecrypt(keyBlob, cipher, plain, TPM2_Alg.NULL);
            Assert.AreEqual(RsaKeySz, rc);

            /* Validate encrypt / decrypt */
            for (int i=0; i<RsaKeySz; i++)  {
                if (message[i] != plain[i]) {
                    Assert.True(false);
                }
            }

            rc = device.UnloadHandle(keyBlob);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

        [Test]
        public void TrySignVerify()
        {
            int rc;
            KeyBlob keyBlob = new KeyBlob();
            Template template = new Template();
            const int RsaKeySz = 256;
            const int HashDigestSz = 32;
            byte[] sig = new byte[RsaKeySz];
            byte[] digest = new byte[HashDigestSz];

            Console.WriteLine("Testing RSA Sign/Verify");

            rc = template.GetKeyTemplate_RSA((ulong)(
                                            TPM2_Object.sensitiveDataOrigin |
                                            TPM2_Object.userWithAuth |
                                            TPM2_Object.decrypt |
                                            TPM2_Object.sign |
                                            TPM2_Object.noDA));
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.CreateKey(keyBlob, parent_key, template,
                "ThisIsMyKeyAuth");
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.LoadKey(keyBlob, parent_key);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            /* Perform RSA sign / verify - PKCSv1.5 (SSA) padding */
            for (int i=0; i<digest.Length; i++)  {
                digest[i] = 0x11;
            }
            rc = device.SignHashScheme(keyBlob, digest, sig,
                TPM2_Alg.RSASSA, TPM2_Alg.SHA256);
            Assert.AreEqual(RsaKeySz, rc);

            rc = device.VerifyHashScheme(keyBlob, sig, digest,
                TPM2_Alg.RSASSA, TPM2_Alg.SHA256);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);

            rc = device.UnloadHandle(keyBlob);
            Assert.AreEqual((int)Status.TPM_RC_SUCCESS, rc);
        }

    }
}
