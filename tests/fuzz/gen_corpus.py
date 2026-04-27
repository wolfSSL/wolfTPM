#!/usr/bin/env python3
"""Generate seed corpus for fwTPM fuzzer.

Creates minimal valid TPM 2.0 command packets for common commands.
Run from the wolftpm root: python3 tests/fuzz/gen_corpus.py
"""

import struct
import os

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "corpus")
os.makedirs(CORPUS_DIR, exist_ok=True)

TPM_ST_NO_SESSIONS = 0x8001
TPM_ST_SESSIONS    = 0x8002

def tpm_cmd(cc, payload=b"", tag=TPM_ST_NO_SESSIONS):
    size = 10 + len(payload)
    return struct.pack(">HII", tag, size, cc) + payload

def write_seed(name, data):
    path = os.path.join(CORPUS_DIR, name + ".bin")
    with open(path, "wb") as f:
        f.write(data)

# --- Basic commands ---
write_seed("startup_clear", tpm_cmd(0x0144, struct.pack(">H", 0)))
write_seed("startup_state", tpm_cmd(0x0144, struct.pack(">H", 1)))
write_seed("shutdown_clear", tpm_cmd(0x0145, struct.pack(">H", 0)))
write_seed("selftest", tpm_cmd(0x0143, struct.pack(">B", 1)))
write_seed("incremental_selftest", tpm_cmd(0x0142))
write_seed("get_test_result", tpm_cmd(0x017C))

# --- Random ---
write_seed("getrandom_16", tpm_cmd(0x017B, struct.pack(">H", 16)))
write_seed("getrandom_32", tpm_cmd(0x017B, struct.pack(">H", 32)))
write_seed("stirrandom", tpm_cmd(0x0146, struct.pack(">H", 4) + b"\xDE\xAD\xBE\xEF"))

# --- GetCapability ---
write_seed("getcap_algs", tpm_cmd(0x017A, struct.pack(">III", 0, 0, 64)))       # TPM_CAP_ALGS
write_seed("getcap_cmds", tpm_cmd(0x017A, struct.pack(">III", 2, 0, 256)))      # TPM_CAP_COMMANDS
write_seed("getcap_props", tpm_cmd(0x017A, struct.pack(">III", 6, 0x100, 64)))   # TPM_CAP_TPM_PROPERTIES
write_seed("getcap_pcrs", tpm_cmd(0x017A, struct.pack(">III", 5, 0, 8)))         # TPM_CAP_PCRS

# --- PCR ---
# PCR_Read: pcrSelCount(4) + selection(hashAlg=SHA256, sizeOfSelect=3, pcrSelect=0x01,0,0)
pcr_read_sel = struct.pack(">I", 1) + struct.pack(">HB", 0x000B, 3) + b"\x01\x00\x00"
write_seed("pcr_read", tpm_cmd(0x017E, pcr_read_sel))

# PCR_Extend: pcrHandle(4) + authArea + count(4) + hashAlg(2) + digest(32)
pcr_handle = struct.pack(">I", 0)  # PCR 0
auth_area = struct.pack(">I", 9)   # authAreaSize
auth_area += struct.pack(">I", 0x40000009)  # TPM_RS_PW
auth_area += struct.pack(">H", 0)  # nonce size
auth_area += struct.pack(">B", 0)  # attributes
auth_area += struct.pack(">H", 0)  # hmac size
digest_count = struct.pack(">I", 1)
digest_data = struct.pack(">H", 0x000B) + b"\x00" * 32  # SHA-256 zero digest
write_seed("pcr_extend", tpm_cmd(0x0182, pcr_handle + auth_area + digest_count + digest_data, TPM_ST_SESSIONS))

# PCR_Reset
write_seed("pcr_reset", tpm_cmd(0x013D, struct.pack(">I", 16) +  # PCR 16 (resettable)
    struct.pack(">I", 9) +  # authAreaSize
    struct.pack(">I", 0x40000009) + struct.pack(">H", 0) + struct.pack(">B", 0) + struct.pack(">H", 0),
    TPM_ST_SESSIONS))

# --- Clock ---
write_seed("readclock", tpm_cmd(0x0181))

# --- TestParms ---
# RSA 2048
write_seed("testparms_rsa", tpm_cmd(0x018A, struct.pack(">HH", 0x0001, 2048) +
    struct.pack(">HH", 0x0010, 0) + struct.pack(">HHH", 0x0006, 128, 0x0043)))
# ECC P-256
write_seed("testparms_ecc", tpm_cmd(0x018A, struct.pack(">HH", 0x0023, 0x0003) +
    struct.pack(">HH", 0x0010, 0) + struct.pack(">H", 0x0010)))

# --- Hash ---
write_seed("hash", tpm_cmd(0x017D, struct.pack(">H", 5) + b"hello" +
    struct.pack(">H", 0x000B) + struct.pack(">I", 0x40000007)))  # SHA-256, owner hierarchy

# --- Malformed packets for edge case testing ---
write_seed("truncated_header", b"\x80\x01\x00\x00\x00")
write_seed("zero_size", struct.pack(">HII", 0x8001, 0, 0x017B))
write_seed("bad_tag", struct.pack(">HII", 0xFFFF, 10, 0x017B))
write_seed("huge_size", struct.pack(">HII", 0x8001, 0xFFFFFFFF, 0x017B))
write_seed("unknown_cc", tpm_cmd(0xDEAD))
write_seed("min_header", struct.pack(">HII", 0x8001, 10, 0x017B))

# --- FlushContext ---
write_seed("flushcontext", tpm_cmd(0x0165, struct.pack(">I", 0x80000000)))

# --- ReadPublic ---
write_seed("readpublic", tpm_cmd(0x0173, struct.pack(">I", 0x80000000)))

# --- ContextSave ---
write_seed("contextsave", tpm_cmd(0x0162, struct.pack(">I", 0x80000000)))

# --- v1.85 PQC command seeds ---
# These provide libFuzzer with starting shapes for the 8 new v1.85 commands.
# They are intentionally minimal / partially malformed in places — the fuzzer
# mutates them toward interesting inputs. Command codes per Part 2 Sec.6.5.2
# Table 11.
pw_auth = (struct.pack(">I", 9) +                 # authAreaSize
           struct.pack(">I", 0x40000009) +         # TPM_RS_PW
           struct.pack(">H", 0) +                  # nonce size
           struct.pack(">B", 0) +                  # attributes
           struct.pack(">H", 0))                   # hmac size

# Encapsulate (no auth): just keyHandle.
write_seed("pqc_encapsulate_mlkem",
    tpm_cmd(0x000001A7, struct.pack(">I", 0x80000001)))

# Decapsulate (USER auth on key): handle + auth + TPM2B_KEM_CIPHERTEXT.
# Include a tiny 8-byte ciphertext to exercise the parse path.
write_seed("pqc_decapsulate_mlkem",
    tpm_cmd(0x000001A8,
        struct.pack(">I", 0x80000001) + pw_auth +
        struct.pack(">H", 8) + b"\x00" * 8,
        TPM_ST_SESSIONS))

# SignSequenceStart: handle + auth + TPM2B_AUTH + TPM2B_SIGNATURE_HINT +
# TPM2B_SIGNATURE_CTX. All empty.
write_seed("pqc_signseqstart_mldsa",
    tpm_cmd(0x000001AA,
        struct.pack(">I", 0x80000001) + pw_auth +
        struct.pack(">H", 0) + struct.pack(">H", 0) + struct.pack(">H", 0),
        TPM_ST_SESSIONS))

# SignSequenceComplete: seqHandle + keyHandle + 2 auths + TPM2B_MAX_BUFFER.
write_seed("pqc_signseqcomplete_mldsa",
    tpm_cmd(0x000001A4,
        struct.pack(">I", 0x80000002) + struct.pack(">I", 0x80000001) +
        struct.pack(">I", 18) +                   # 2 auths stacked
        struct.pack(">I", 0x40000009) + struct.pack(">H", 0) +
        struct.pack(">B", 0) + struct.pack(">H", 0) +
        struct.pack(">I", 0x40000009) + struct.pack(">H", 0) +
        struct.pack(">B", 0) + struct.pack(">H", 0) +
        struct.pack(">H", 4) + b"test",            # message buffer
        TPM_ST_SESSIONS))

# VerifySequenceStart: handle + auth + TPM2B_AUTH + TPM2B_SIGNATURE_HINT +
# TPM2B_SIGNATURE_CTX. All empty.
write_seed("pqc_verifyseqstart_mldsa",
    tpm_cmd(0x000001A9,
        struct.pack(">I", 0x80000001) + pw_auth +
        struct.pack(">H", 0) + struct.pack(">H", 0) + struct.pack(">H", 0),
        TPM_ST_SESSIONS))

# VerifySequenceComplete: seqHandle + keyHandle + auth + TPMT_SIGNATURE.
# sigAlg=TPM_ALG_MLDSA, empty sig body (fuzzer will grow).
write_seed("pqc_verifyseqcomplete_mldsa",
    tpm_cmd(0x000001A3,
        struct.pack(">I", 0x80000002) + struct.pack(">I", 0x80000001) +
        pw_auth +
        struct.pack(">H", 0x00A1) + struct.pack(">H", 0),  # TPM_ALG_MLDSA + empty
        TPM_ST_SESSIONS))

# SignDigest: keyHandle + auth + context + digest + validation (null ticket).
write_seed("pqc_signdigest_mldsa",
    tpm_cmd(0x000001A6,
        struct.pack(">I", 0x80000001) + pw_auth +
        struct.pack(">H", 0) +                     # ctx = empty
        struct.pack(">H", 32) + b"\x00" * 32 +     # 32-byte digest
        struct.pack(">H", 0x8001) +                # TPM_ST_HASHCHECK
        struct.pack(">I", 0x40000007) +            # hierarchy = owner
        struct.pack(">H", 0),                      # digest = empty
        TPM_ST_SESSIONS))

# VerifyDigestSignature: keyHandle + context + digest + TPMT_SIGNATURE.
write_seed("pqc_verifydigestsig_mldsa",
    tpm_cmd(0x000001A5,
        struct.pack(">I", 0x80000001) +
        struct.pack(">H", 0) +                     # ctx = empty
        struct.pack(">H", 32) + b"\x00" * 32 +     # 32-byte digest
        struct.pack(">H", 0x00A1) + struct.pack(">H", 0)))  # MLDSA + empty sig

# CreatePrimary MLKEM-768: minimal TPMT_PUBLIC template.
mlkem_tmpl = (struct.pack(">H", 0x00A0) +          # type=TPM_ALG_MLKEM
              struct.pack(">H", 0x000B) +          # nameAlg=SHA256
              struct.pack(">I", 0x00020072) +      # attrs decrypt/etc
              struct.pack(">H", 0) +               # authPolicy=empty
              struct.pack(">H", 0x0010) +          # sym=NULL
              struct.pack(">H", 0x0002) +          # param set = MLKEM-768
              struct.pack(">H", 0))                # unique=empty
write_seed("pqc_createprimary_mlkem",
    tpm_cmd(0x00000131,
        struct.pack(">I", 0x40000001) + pw_auth +  # owner + empty auth
        struct.pack(">H", 4) + struct.pack(">HH", 0, 0) +   # sensitive=empty
        struct.pack(">H", len(mlkem_tmpl)) + mlkem_tmpl +
        struct.pack(">H", 0) +                     # outsideInfo=empty
        struct.pack(">I", 0),                      # creationPCR=empty
        TPM_ST_SESSIONS))

# CreatePrimary MLDSA-65: minimal template.
mldsa_tmpl = (struct.pack(">H", 0x00A1) +          # type=TPM_ALG_MLDSA
              struct.pack(">H", 0x000B) +
              struct.pack(">I", 0x00040072) +      # attrs sign/etc
              struct.pack(">H", 0) +
              struct.pack(">H", 0x0002) +          # param set = MLDSA-65
              struct.pack(">B", 0) +               # allowExternalMu=NO
              struct.pack(">H", 0))
write_seed("pqc_createprimary_mldsa",
    tpm_cmd(0x00000131,
        struct.pack(">I", 0x40000001) + pw_auth +
        struct.pack(">H", 4) + struct.pack(">HH", 0, 0) +
        struct.pack(">H", len(mldsa_tmpl)) + mldsa_tmpl +
        struct.pack(">H", 0) +
        struct.pack(">I", 0),
        TPM_ST_SESSIONS))

print(f"Generated {len(os.listdir(CORPUS_DIR))} seed corpus files in {CORPUS_DIR}")
