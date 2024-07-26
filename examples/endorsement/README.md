# TPM Endorsement Certificates

The `get_ek_certs` example will enumerate and validate the Endorsement Key Certificates stored in the NV TCG region.

TPM manufactures provision Endorsement Certificates based on a TPM key. This certificate can be used for signing/endorsement.

We have loaded some of the root and intermediate CA's into the trusted_certs.h file.

## Infineon SLB9672 EK Certificate Chain

Infineon certificates for TPM 2.0 can be downloaded from the following URLs (replace xxx with 3-digit CA number):

https://pki.infineon.com/OptigaRsaMfrCAxxx/OptigaRsaMfrCAxxx.crt
https://pki.infineon.com/OptigaEccMfrCAxxx/OptigaEccMfrCAxxx.crt


Examples:

- Infineon OPTIGA(TM) RSA Root CA 2
  - Infineon OPTIGA(TM) TPM 2.0 RSA CA 059
- Infineon OPTIGA(TM) ECC Root CA 2
  - Infineon OPTIGA(TM) TPM 2.0 ECC CA 059

## STMicro ST33KTPM EK Certificate Chain

Example:

- STSAFE RSA root CA 02 (http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt)
  - STSAFE-TPM RSA intermediate CA 10 (http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt)
- STSAFE ECC root CA 02 (http://sw-center.st.com/STSAFE/STSAFEEccRootCA02.crt)
  - STSAFE-TPM ECC intermediate CA 10 (http://sw-center.st.com/STSAFE/stsafetpmeccint10.crt)
