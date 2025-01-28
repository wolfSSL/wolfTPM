# TPM Endorsement Certificates

TPM manufactures provision Endorsement Certificates based on a TPM key. This certificate can be used for signing/endorsement.

The `get_ek_certs` example will enumerate and validate the Endorsement Key Certificates stored in the NV TCG region.

We have loaded some of the root and intermediate CA's into the trusted_certs.h file.

## Example Detail

1) Get handles in the TCG NV range using `wolfTPM2_GetHandles` with `TPM_20_TCG_NV_SPACE`.
2) Get size of the certificate by reading the public NV information using `wolfTPM2_NVReadPublic`.
3) Read the NV data (certificate DER/ASN.1) from the NV index using `wolfTPM2_NVReadAuth`.
4) Get the EK public template using the NV index by calling `wolfTPM2_GetKeyTemplate_EKIndex` or `wolfTPM2_GetKeyTemplate_EK`.
5) Create the primary endorsement key with public template and TPM_RH_ENDORSEMENT hierarchy using `wolfTPM2_CreatePrimaryKey`.
6) Parse the ASN.1/DER certificate using `wc_ParseCert` to extract issuer, serial number, etc...
7) The URI for the CA issuer certificate can be obtained in `extAuthInfoCaIssuer`.
8) Import the certificate public key and compare it against the primary EK public unique area.
9) Use the wolfSSL Certificate Manager to validate the EK certificate. Trusted certificates are loaded using `wolfSSL_CertManagerLoadCABuffer` and the EK certificate is validated using `wolfSSL_CertManagerVerifyBuffer`.
10) Optionally covert to PEM and export using `wc_DerToPem`.

## Example certificate chains

### Infineon SLB9672

Infineon certificates for TPM 2.0 can be downloaded from the following URLs (replace xxx with 3-digit CA number):

https://pki.infineon.com/OptigaRsaMfrCAxxx/OptigaRsaMfrCAxxx.crt
https://pki.infineon.com/OptigaEccMfrCAxxx/OptigaEccMfrCAxxx.crt


Examples:

- Infineon OPTIGA(TM) RSA Root CA 2
  - Infineon OPTIGA(TM) TPM 2.0 RSA CA 059
- Infineon OPTIGA(TM) ECC Root CA 2
  - Infineon OPTIGA(TM) TPM 2.0 ECC CA 059

### STMicro ST33KTPM

Example:

- STSAFE RSA root CA 02 (http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt)
  - STSAFE-TPM RSA intermediate CA 10 (http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt)
- STSAFE ECC root CA 02 (http://sw-center.st.com/STSAFE/STSAFEEccRootCA02.crt)
  - STSAFE-TPM ECC intermediate CA 10 (http://sw-center.st.com/STSAFE/stsafetpmeccint10.crt)

Sample Output:

```
$ ./examples/endorsement/verify_ek_cert
Endorsement Certificate Verify
TPM2: Caps 0x30000415, Did 0x0004, Vid 0x104a, Rid 0x 1
TPM2_Startup pass
TPM2_NV_ReadPublic: Sz 14, Idx 0x1c00002, nameAlg 11, Attr 0x62076801, authPol 0, dataSz 1300, name 34
TPM2_NV_ReadPublic: Sz 14, Idx 0x1c00002, nameAlg 11, Attr 0x62076801, authPol 0, dataSz 1300, name 34
TPM2_NV_Read: Auth 0x1c00002, Idx 0x1c00002, Offset 0, Size 768
TPM2_NV_Read: Auth 0x1c00002, Idx 0x1c00002, Offset 768, Size 532
EK Data: 1300
        30 82 05 10 30 82 02 f8 a0 03 02 01 02 02 14 58 | 0...0..........X
        63 86 17 74 73 22 ca 34 60 4a f6 cf d9 b4 44 9e | c..ts".4`J....D.
        4b ba 03 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0c | K..0...*.H......
        05 00 30 59 31 0b 30 09 06 03 55 04 06 13 02 43 | ..0Y1.0...U....C
        48 31 1e 30 1c 06 03 55 04 0a 13 15 53 54 4d 69 | H1.0...U....STMi
        63 72 6f 65 6c 65 63 74 72 6f 6e 69 63 73 20 4e | croelectronics N
        56 31 2a 30 28 06 03 55 04 03 13 21 53 54 53 41 | V1*0(..U...!STSA
        46 45 20 54 50 4d 20 52 53 41 20 49 6e 74 65 72 | FE TPM RSA Inter
        6d 65 64 69 61 74 65 20 43 41 20 32 30 30 20 17 | mediate CA 200 .
        0d 32 33 30 36 30 31 30 39 34 39 33 35 5a 18 0f | .230601094935Z..
        39 39 39 39 31 32 33 31 32 33 35 39 35 39 5a 30 | 99991231235959Z0
        00 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 | .0.."0...*.H....
        01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 | .........0......
        01 00 b3 20 db 1a 10 d2 16 8c 5d 92 c0 47 87 b1 | ... ......]..G..
        dc ae af 5b f2 44 15 dd 84 9a 17 3f c6 76 61 29 | ...[.D.....?.va)
        c6 c3 4c e5 50 27 a2 26 8b fd e0 9d 34 09 93 0f | ..L.P'.&....4...
        64 6a b0 46 f5 5b 19 1c 14 45 b7 24 d3 a9 a5 7d | dj.F.[...E.$...}
        4c a7 0a ba cc d4 72 a2 18 2e 1a 20 a5 33 6f 5f | L.....r.... .3o_
        f5 21 10 bf db af 74 7f 97 93 46 64 40 16 c2 e9 | .!....t...Fd@...
        8f cc e0 f2 4a 94 29 4e 73 87 6f a4 bb c8 f3 e1 | ....J.)Ns.o.....
        02 35 12 c9 c7 e8 4c f2 59 94 5f d2 5a ca 35 48 | .5....L.Y._.Z.5H
        e3 0d 59 90 41 33 10 cd 4b f5 ff a7 0c 4e 94 ce | ..Y.A3..K....N..
        86 45 fb 89 aa b4 76 10 8e ed 90 1e bf b9 6b 88 | .E....v.......k.
        df 5a 1a b7 b5 cb a8 80 ff cf 4d a8 c1 05 b6 15 | .Z........M.....
        49 8d 22 74 29 56 95 56 e5 1d 4f 31 44 da 77 3c | I."t)V.V..O1D.w<
        a7 46 a3 e2 d5 ee 18 51 0c 9c 51 52 49 ff d1 ba | .F.....Q..QRI...
        4f cd 33 42 0d 8e e9 c8 da a0 ff 10 02 0d dd e4 | O.3B............
        fa 49 21 98 e9 28 c7 c5 25 ac 7b 90 91 99 fb 99 | .I!..(..%.{.....
        36 63 dc 50 98 fa fd 32 37 c2 08 9c 43 fc 59 d6 | 6c.P...27...C.Y.
        27 5f 02 03 01 00 01 a3 82 01 25 30 82 01 21 30 | '_........%0..!0
        1f 06 03 55 1d 23 04 18 30 16 80 14 8f e0 78 f8 | ...U.#..0.....x.
        ca 88 59 fe fe 3f 7a 98 37 2c fc 02 c6 08 44 49 | ..Y..?z.7,....DI
        30 58 06 03 55 1d 11 01 01 ff 04 4e 30 4c a4 4a | 0X..U......N0L.J
        30 48 31 16 30 14 06 05 67 81 05 02 01 0c 0b 69 | 0H1.0...g......i
        64 3a 35 33 35 34 34 44 32 30 31 16 30 14 06 05 | d:53544D201.0...
        67 81 05 02 02 0c 0b 53 54 33 33 4b 54 50 4d 32 | g......ST33KTPM2
        41 49 31 16 30 14 06 05 67 81 05 02 03 0c 0b 69 | AI1.0...g......i
        64 3a 30 30 30 41 30 31 30 31 30 22 06 03 55 1d | d:000A01010"..U.
        09 04 1b 30 19 30 17 06 05 67 81 05 02 10 31 0e | ...0.0...g....1.
        30 0c 0c 03 32 2e 30 02 01 00 02 02 00 9f 30 0c | 0...2.0.......0.
        06 03 55 1d 13 01 01 ff 04 02 30 00 30 10 06 03 | ..U.......0.0...
        55 1d 25 04 09 30 07 06 05 67 81 05 08 01 30 0e | U.%..0...g....0.
        06 03 55 1d 0f 01 01 ff 04 04 03 02 05 20 30 50 | ..U.......... 0P
        06 08 2b 06 01 05 05 07 01 01 04 44 30 42 30 40 | ..+........D0B0@
        06 08 2b 06 01 05 05 07 30 02 86 34 68 74 74 70 | ..+.....0..4http
        3a 2f 2f 73 77 2d 63 65 6e 74 65 72 2e 73 74 2e | ://sw-center.st.
        63 6f 6d 2f 53 54 53 41 46 45 2f 73 74 73 61 66 | com/STSAFE/stsaf
        65 74 70 6d 72 73 61 69 6e 74 32 30 2e 63 72 74 | etpmrsaint20.crt
        30 0d 06 09 2a 86 48 86 f7 0d 01 01 0c 05 00 03 | 0...*.H.........
        82 02 01 00 b5 7a 68 4d aa d5 3a bf a2 6a 6f 1d | .....zhM..:..jo.
        1a 5e 35 74 47 f4 b7 ee a0 63 8e 08 42 8c a3 80 | .^5tG....c..B...
        3a 91 8e 92 1a 22 73 c8 a6 07 61 42 63 5f 4e c7 | :...."s...aBc_N.
        17 dc 5e c2 51 73 13 51 0f 57 17 01 63 9e da b5 | ..^.Qs.Q.W..c...
        4a fd 92 6d 0a 33 8b e4 dc 5f 63 96 7b 89 d3 3a | J..m.3..._c.{..:
        99 29 ac f0 7c 0a 99 ea 9c 40 33 86 4b 55 30 03 | .)..|....@3.KU0.
        24 41 05 f6 48 43 5f b9 39 b4 74 17 2c 71 bf 26 | $A..HC_.9.t.,q.&
        f4 a3 7a 9f ae 80 0c 8b 92 c8 22 35 0f f8 64 da | ..z......."5..d.
        50 b1 2f 5f e2 a4 19 32 a6 7e 74 bb 31 74 93 10 | P./_...2.~t.1t..
        85 a2 5f 10 9f 1d 0c 57 90 d2 56 e4 70 7f 54 99 | .._....W..V.p.T.
        87 c0 bd d7 8f c4 31 eb 9d bc cd ca 35 b2 64 d0 | ......1.....5.d.
        ee 6b c8 e1 1b 34 bc 09 3f cd d1 f1 53 c2 18 dd | .k...4..?...S...
        82 85 2e 6c 44 9b 21 df eb 7b 5b 8f 07 f5 61 34 | ...lD.!..{[...a4
        25 e5 97 ee bd 01 2e 1c 35 53 00 b0 be 92 96 80 | %.......5S......
        50 9b 6e e0 f3 e3 1d 0c 0a 99 96 cd 42 64 e4 43 | P.n.........Bd.C
        6a 4a de c2 03 19 a2 a7 b6 fa 7d 25 37 04 53 30 | jJ........}%7.S0
        3a 69 b2 38 6c c9 e9 e3 59 a4 8b 1e ae 62 5d eb | :i.8l...Y....b].
        3c 85 e3 2f f1 cb 7b 3c 0d 2d bf 6e f0 9c 7c c9 | <../..{<.-.n..|.
        c8 84 35 26 21 82 2a 83 f7 54 80 51 73 34 c2 7b | ..5&!.*..T.Qs4.{
        2b 5d 32 b7 26 a6 8c b2 46 d6 c2 63 5c 38 0c 0b | +]2.&...F..c\8..
        5e ba 81 ee 0b 55 c6 e7 ab 48 8d 6a e4 c7 ec 45 | ^....U...H.j...E
        0d 46 b9 2e 8e a9 be e1 26 b4 79 b5 56 4c 2a dd | .F......&.y.VL*.
        93 22 01 d5 2c ca bd c0 6a 30 ff 53 8c 08 98 22 | ."..,...j0.S..."
        33 3c 78 a1 59 25 43 cc db e1 26 cc 55 7f bb 4b | 3<x.Y%C...&.U..K
        fe 9f 3f d9 92 44 6d 72 a4 74 75 e4 f6 40 bf 3d | ..?..Dmr.tu..@.=
        a4 b5 fb 78 39 2a 9d 5e 91 ba e4 67 50 5a 99 6e | ...x9*.^...gPZ.n
        5a 53 56 4e ca aa a3 b3 55 28 f1 68 b5 c1 dc 3b | ZSVN....U(.h...;
        78 20 5b 86 8e 54 84 8b 6e 3c fd 5a fb a4 4a 46 | x [..T..n<.Z..JF
        ba 2e d0 47 c7 43 b9 65 8f b5 01 c6 c3 17 ce 34 | ...G.C.e.......4
        3b 51 d5 ea c4 0a c2 cf 02 94 d6 1f 93 4c 43 79 | ;Q...........LCy
        a9 44 fa f7 62 82 50 d5 2b 73 56 06 c1 16 b5 41 | .D..b.P.+sV....A
        36 17 8b e4 8c 4a 25 fb e4 c9 dc 2e d3 f5 bc c9 | 6....J%.........
        c2 6d c6 7d                                     | .m.}
Creating Endorsement Key
TPM2_CreatePrimary: 0x80000000 (314 bytes)
Endorsement key loaded at handle 0x80000000
EK RSA, Hash: SHA256, objAttr: 0x300B2
        KeyBits: 2048, exponent: 0x0, unique size 256
        b3:20:db:1a:10:d2:16:8c:5d:92:c0:47:87:b1:dc:ae:
        af:5b:f2:44:15:dd:84:9a:17:3f:c6:76:61:29:c6:c3:
        4c:e5:50:27:a2:26:8b:fd:e0:9d:34:09:93:0f:64:6a:
        b0:46:f5:5b:19:1c:14:45:b7:24:d3:a9:a5:7d:4c:a7:
        0a:ba:cc:d4:72:a2:18:2e:1a:20:a5:33:6f:5f:f5:21:
        10:bf:db:af:74:7f:97:93:46:64:40:16:c2:e9:8f:cc:
        e0:f2:4a:94:29:4e:73:87:6f:a4:bb:c8:f3:e1:02:35:
        12:c9:c7:e8:4c:f2:59:94:5f:d2:5a:ca:35:48:e3:0d:
        59:90:41:33:10:cd:4b:f5:ff:a7:0c:4e:94:ce:86:45:
        fb:89:aa:b4:76:10:8e:ed:90:1e:bf:b9:6b:88:df:5a:
        1a:b7:b5:cb:a8:80:ff:cf:4d:a8:c1:05:b6:15:49:8d:
        22:74:29:56:95:56:e5:1d:4f:31:44:da:77:3c:a7:46:
        a3:e2:d5:ee:18:51:0c:9c:51:52:49:ff:d1:ba:4f:cd:
        33:42:0d:8e:e9:c8:da:a0:ff:10:02:0d:dd:e4:fa:49:
        21:98:e9:28:c7:c5:25:ac:7b:90:91:99:fb:99:36:63:
        dc:50:98:fa:fd:32:37:c2:08:9c:43:fc:59:d6:27:5f
wolfTPM2_HashStart: Handle 0x80000002
wolfTPM2_HashUpdate: Handle 0x80000002, DataSz 764
wolfTPM2_HashFinish: Handle 0x80000002, DigestSz 48
Cert Hash: 48
        54:70:93:7f:05:79:3b:b8:fb:2f:2f:e0:eb:96:ec:95:
        6e:bd:25:49:45:69:38:6b:67:48:09:cd:47:17:cc:c6:
        8d:c9:6a:5a:01:16:ba:9f:75:96:0c:be:dc:40:0c:ee
Issuer Public Exponent 0x10001, Modulus 512
        c5:5e:b9:a1:35:8b:76:d6:df:ed:93:a5:66:9d:11:93:
        fd:46:42:fd:48:f7:33:6a:96:e3:64:6c:2a:74:ba:52:
        9e:71:48:c6:ca:42:e1:06:a0:c7:bc:c4:0d:6e:48:ed:
        1c:5f:dc:aa:44:c1:f4:5c:b3:ac:22:85:ad:5f:b0:b0:
        d9:f4:8e:51:3e:05:70:41:ac:cf:5c:f8:0f:29:aa:94:
        5b:24:a3:bf:39:33:e9:1a:bb:51:de:22:b2:52:a6:8b:
        27:c1:aa:92:e1:38:80:40:ae:f9:04:d0:cc:d5:3b:72:
        7f:d5:69:bc:9b:80:55:ff:c2:4a:87:3e:b5:74:55:c7:
        83:04:9e:d9:ec:ee:fb:c7:21:d6:51:b4:c8:a4:6f:03:
        57:3d:8c:ae:fc:df:d9:6c:a4:80:4e:83:2d:96:40:6f:
        e2:bf:45:a5:0a:32:c1:d6:de:69:35:53:24:37:e4:7a:
        8c:2f:96:b6:8a:8c:74:14:eb:5a:05:4a:fe:23:03:d9:
        ce:af:9e:c4:2e:23:b4:e2:ff:e4:76:1b:ce:4d:6b:54:
        af:bf:fc:c2:4e:24:6f:24:e6:bc:34:61:cb:15:0a:ce:
        8b:5b:22:0a:fd:3f:26:93:63:b4:a5:b3:43:6a:1a:20:
        14:47:d2:d9:fd:65:59:ae:13:0d:61:3c:38:bb:2e:59:
        0b:f0:49:92:12:db:9d:73:09:42:54:15:0c:97:d7:14:
        a4:bb:3a:5e:e8:7f:d9:dc:76:3d:ca:36:77:52:12:58:
        e9:d1:ff:06:e6:da:05:6a:9c:7f:a6:05:4b:2e:48:62:
        26:b0:2d:5c:a6:7d:c9:49:18:cb:76:24:4d:7a:62:04:
        b4:b4:ee:48:24:c0:11:ba:78:f0:ca:f0:f2:97:84:15:
        0a:99:de:0a:56:13:30:a6:f5:76:c6:c8:95:4a:44:94:
        b1:fe:78:1e:55:7e:fc:4c:2e:4f:3c:7a:f3:4d:69:ae:
        95:60:51:a0:4e:0c:eb:e3:62:4a:0c:a7:67:10:a7:ab:
        e7:44:e6:d4:96:32:a0:c8:09:45:20:2f:cc:04:10:c1:
        53:31:5f:e7:fb:e0:36:c8:1d:08:b4:d1:a2:01:a1:7f:
        6c:94:a7:81:e9:c1:c7:19:0d:30:bc:4f:a5:ad:d5:ec:
        dd:9c:68:58:6c:49:b9:fa:e6:92:9b:30:6a:90:84:a3:
        eb:90:6c:fe:8e:d6:21:df:45:23:78:1e:be:0c:c1:b9:
        05:bd:a3:0e:ef:b6:96:95:75:92:d0:a5:05:b7:88:9e:
        46:fd:54:a2:f1:98:9c:b5:01:ac:5c:51:b8:b7:05:25:
        52:f6:12:a1:e1:f4:bf:b2:4e:3e:27:b7:71:9f:d4:e1
TPM2_LoadExternal: 0x80000002
EK Certificate Signature: 512
        b5:7a:68:4d:aa:d5:3a:bf:a2:6a:6f:1d:1a:5e:35:74:
        47:f4:b7:ee:a0:63:8e:08:42:8c:a3:80:3a:91:8e:92:
        1a:22:73:c8:a6:07:61:42:63:5f:4e:c7:17:dc:5e:c2:
        51:73:13:51:0f:57:17:01:63:9e:da:b5:4a:fd:92:6d:
        0a:33:8b:e4:dc:5f:63:96:7b:89:d3:3a:99:29:ac:f0:
        7c:0a:99:ea:9c:40:33:86:4b:55:30:03:24:41:05:f6:
        48:43:5f:b9:39:b4:74:17:2c:71:bf:26:f4:a3:7a:9f:
        ae:80:0c:8b:92:c8:22:35:0f:f8:64:da:50:b1:2f:5f:
        e2:a4:19:32:a6:7e:74:bb:31:74:93:10:85:a2:5f:10:
        9f:1d:0c:57:90:d2:56:e4:70:7f:54:99:87:c0:bd:d7:
        8f:c4:31:eb:9d:bc:cd:ca:35:b2:64:d0:ee:6b:c8:e1:
        1b:34:bc:09:3f:cd:d1:f1:53:c2:18:dd:82:85:2e:6c:
        44:9b:21:df:eb:7b:5b:8f:07:f5:61:34:25:e5:97:ee:
        bd:01:2e:1c:35:53:00:b0:be:92:96:80:50:9b:6e:e0:
        f3:e3:1d:0c:0a:99:96:cd:42:64:e4:43:6a:4a:de:c2:
        03:19:a2:a7:b6:fa:7d:25:37:04:53:30:3a:69:b2:38:
        6c:c9:e9:e3:59:a4:8b:1e:ae:62:5d:eb:3c:85:e3:2f:
        f1:cb:7b:3c:0d:2d:bf:6e:f0:9c:7c:c9:c8:84:35:26:
        21:82:2a:83:f7:54:80:51:73:34:c2:7b:2b:5d:32:b7:
        26:a6:8c:b2:46:d6:c2:63:5c:38:0c:0b:5e:ba:81:ee:
        0b:55:c6:e7:ab:48:8d:6a:e4:c7:ec:45:0d:46:b9:2e:
        8e:a9:be:e1:26:b4:79:b5:56:4c:2a:dd:93:22:01:d5:
        2c:ca:bd:c0:6a:30:ff:53:8c:08:98:22:33:3c:78:a1:
        59:25:43:cc:db:e1:26:cc:55:7f:bb:4b:fe:9f:3f:d9:
        92:44:6d:72:a4:74:75:e4:f6:40:bf:3d:a4:b5:fb:78:
        39:2a:9d:5e:91:ba:e4:67:50:5a:99:6e:5a:53:56:4e:
        ca:aa:a3:b3:55:28:f1:68:b5:c1:dc:3b:78:20:5b:86:
        8e:54:84:8b:6e:3c:fd:5a:fb:a4:4a:46:ba:2e:d0:47:
        c7:43:b9:65:8f:b5:01:c6:c3:17:ce:34:3b:51:d5:ea:
        c4:0a:c2:cf:02:94:d6:1f:93:4c:43:79:a9:44:fa:f7:
        62:82:50:d5:2b:73:56:06:c1:16:b5:41:36:17:8b:e4:
        8c:4a:25:fb:e4:c9:dc:2e:d3:f5:bc:c9:c2:6d:c6:7d
TPM2_RSA_Encrypt: 512
Decrypted Sig: 512
        00:01:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:30:41:30:
        0d:06:09:60:86:48:01:65:03:04:02:02:05:00:04:30:
        54:70:93:7f:05:79:3b:b8:fb:2f:2f:e0:eb:96:ec:95:
        6e:bd:25:49:45:69:38:6b:67:48:09:cd:47:17:cc:c6:
        8d:c9:6a:5a:01:16:ba:9f:75:96:0c:be:dc:40:0c:ee
Expected Hash: 48
        54:70:93:7f:05:79:3b:b8:fb:2f:2f:e0:eb:96:ec:95:
        6e:bd:25:49:45:69:38:6b:67:48:09:cd:47:17:cc:c6:
        8d:c9:6a:5a:01:16:ba:9f:75:96:0c:be:dc:40:0c:ee
Sig Hash: 48
        54:70:93:7f:05:79:3b:b8:fb:2f:2f:e0:eb:96:ec:95:
        6e:bd:25:49:45:69:38:6b:67:48:09:cd:47:17:cc:c6:
        8d:c9:6a:5a:01:16:ba:9f:75:96:0c:be:dc:40:0c:ee
Certificate signature is valid
TPM2_FlushContext: Closed handle 0x80000002
TPM2_FlushContext: Closed handle 0x80000000
```
