# Secure Boot Root-of-Trust (ROT)

Design for storage of public key based root of trust into TPM:

1) Use AES-CFB parameter encryption for all communication (salted and bound)
2) Derive a password based on unique device parameters used as "auth" to load NV (authenticate)
3) The NV contains a hash of the public key (hash matches .config setting)
4) WolfBoot still has the public key internally and programs the TPM with the NV if not populated.
5) The NV is locked and created under the platform hierarchy


