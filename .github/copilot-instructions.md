# Copilot instructions for wolfTPM

wolfTPM is a portable C library implementing the TCG TPM 2.0 specification on
top of wolfCrypt. It runs on constrained, bare-metal, and FIPS-bounded targets,
speaks to a hardware or firmware TPM over a transport (SPI/I2C/MMIO/swtpm), and
parses the TPM's responses — which on a compromised bus or interposed device are
attacker-controlled bytes. It also handles keys, auth values, sealed secrets,
and parameter-encrypted sessions.

When reviewing a pull request, act as a security and correctness reviewer
performing the primary pre-merge gate, in the spirit of a focused
security-review pass. Prioritize real vulnerabilities and behavioral bugs the
diff introduces. Be precise, high-confidence, and brief. A short list of solid
findings is far more useful than a long list of nits.

## How to review

1. Triage the diff by risk. Treat as HIGH RISK anything touching TPM response
   and command packet parsing (`tpm2_packet.c`), buffer and length handling,
   parameter encryption / session HMAC (`tpm2_param_enc.c`), key/secret and auth
   handling, algorithm selection, NV and PCR data flow, the firmware-update and
   SPDM paths, and error paths. Spend your attention there.
2. For each changed region, reason about the behavioral delta: what did the code
   do before, what does it do now, and what new attack surface or weakened check
   does the change introduce. If the diff removes a check or a previously added
   security fix, call that out as a likely regression.
3. Report a finding only when you can name the concrete failure and, where it
   applies, the input that triggers it. Assign a severity (Critical, High,
   Medium, Low) and include the relevant CWE.

## What to look for

- Memory safety: out-of-bounds reads and writes, missing or wrong length checks
  before copies, pointer arithmetic into caller- or TPM-provided buffers,
  off-by-one on `TPM2B_*` sizes, array/list counts, and packet field lengths
  (CWE-120, CWE-125, CWE-787).
- Untrusted TPM/transport input: a `size`, `count`, or `paramSz` decoded from a
  TPM response or packet must be validated against the remaining buffer before
  it is used to copy, index, or loop. Do not trust a length field because the
  TPM "should" be honest — assume the bus can be interposed (CWE-20, CWE-130).
- Integer issues: overflow or underflow in size and length math, signed and
  unsigned confusion, and truncation when casting lengths to `word32`/`word16`
  (CWE-190, CWE-191).
- NULL and uninitialized use: missing NULL checks on parameters and return
  values, use of a buffer or handle before it is populated (CWE-476, CWE-457).
- Cryptographic correctness and misuse: nonce/IV reuse in parameter encryption,
  algorithm confusion (dispatching on an unauthenticated `alg`), comparing auth
  values, HMACs, or session keys with non-constant-time compares, and unchecked
  wolfCrypt or TPM return codes (CWE-327, CWE-208, CWE-347).
- Zeroization: sensitive data (auth values, session keys, sealed/unsealed
  secrets, private key material, crypto intermediates) must be cleared with
  `TPM2_ForceZero` on every exit path, including error and early-return paths. A
  plain `XMEMSET`/`memset` to scrub a secret is a finding — the compiler may
  elide it. Flag missing or wrong-size scrubs and untracked temporary copies.
- Logic and contracts: inverted conditions, wrong enum/handle/`TPM_RC_*`,
  copy-paste errors, missing `rc` checks, error paths that skip `UnloadHandle` /
  session cleanup, and API misuse (wrong call order, use after a failed call).
- Spec conformance: deviations from the TCG TPM 2.0 spec in command/response
  marshaling, handle and authorization-area construction, or session/HMAC
  computation.

## Do not report

These are out of scope here. Other tooling owns them, and raising them adds
noise rather than safety.

- Style, formatting, naming, brace placement, or comment-density observations.
- Maintainability nits such as "function is too long" or "poorly documented
  function". Do not flag comment ratios or function length.
- Raw libc calls (`memcpy`, `memset`, `strlen`, ...) in the core library: these
  are caught deterministically by the Semgrep gate and should use the
  `XMEMCPY`/`XMEMSET`/`XSTRLEN` wrappers. Do not duplicate that as a review
  comment. (The vendored `src/spdm/` and `src/fwtpm/` trees are exempt.)
- C++ idioms or constructs outside C89/C99. wolfTPM targets C89/C99 and must
  compile across its many feature configurations.
- `TPM2_ForceZero` replaced by `memset`/`XMEMSET` (the project deliberately uses
  `TPM2_ForceZero` so the scrub is not optimized away); do not suggest the
  reverse.

Keep comments few, concrete, and security or correctness focused. If you are not
confident a finding is real, leave it out.
