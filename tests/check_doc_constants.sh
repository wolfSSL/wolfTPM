#!/usr/bin/env bash
# tests/check_doc_constants.sh — verify doc / header constant parity.
#
# Greps every FWTPM_MAX_* / FWTPM_NV_* / FWTPM_SEED_* compile-time constant
# from wolftpm/fwtpm/fwtpm.h and asserts that docs/FWTPM.md mentions each one.
# Catches doc drift when a constant is bumped (e.g. v1.85 lifted
# FWTPM_MAX_COMMAND_SIZE 4096->8192) but the docs still cite the old value.
#
# Exit 0 if every constant is mentioned in the doc; non-zero otherwise.
# Exit 77 (autotools SKIP) if either source file is missing.

set -u

HEADER="wolftpm/fwtpm/fwtpm.h"
DOC="docs/FWTPM.md"

if [ ! -f "$HEADER" ] || [ ! -f "$DOC" ]; then
    echo "SKIP: $HEADER or $DOC not found"
    exit 77
fi

# Pull every #define FWTPM_<UPPER>_<UPPER>... NUMERIC_LITERAL line.
# Constants ending in MAX/SIZE/EST/SEED are the ones we care about; pure
# enum-style symbols (FWTPM_NO_*, FWTPM_*_DECLARE_VAR) don't appear in docs.
mapfile -t CONSTS < <(
    grep -E '^\s*#\s*define\s+FWTPM_[A-Z0-9_]*(MAX|SIZE|EST|SEED|BYTES|DIGEST)[A-Z0-9_]*\s' "$HEADER" \
        | awk '{print $2}' \
        | sort -u
)

if [ "${#CONSTS[@]}" -eq 0 ]; then
    echo "SKIP: no FWTPM_*_(MAX|SIZE|EST|SEED|BYTES|DIGEST) constants found in $HEADER"
    exit 77
fi

echo "Checking ${#CONSTS[@]} FWTPM_* constants in $DOC..."

MISSING=()
for c in "${CONSTS[@]}"; do
    if ! grep -qF "$c" "$DOC"; then
        MISSING+=("$c")
    fi
done

if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "ERROR: the following constants are defined in $HEADER but NOT mentioned in $DOC:"
    printf '  %s\n' "${MISSING[@]}"
    echo ""
    echo "Add a row for each to the Configuration Macros table in $DOC."
    exit 1
fi

echo "OK: every FWTPM_* size/seed/digest constant is mentioned in $DOC."
exit 0
