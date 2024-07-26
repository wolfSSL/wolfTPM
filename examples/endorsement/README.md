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
