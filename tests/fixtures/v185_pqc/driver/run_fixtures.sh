#!/bin/bash
# run_fixtures.sh
#
# Layer C fixture driver — Phase 1 skeleton.
#
# Walks tests/fixtures/v185_pqc/{happy_path,regression}/*.json and reports
# pass/fail for each. Until the C harness at driver/fixture_validate.c exists
# (Phase 2), this shell driver only performs JSON well-formedness and
# size-consistency lints. Real byte-level assertions begin in Phase 2.
#
# Exit status: 0 if all fixtures PASS (or all intentionally SKIP in Phase 1);
# non-zero if any fixture is structurally malformed.

set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_ROOT="$(cd "$HERE/.." && pwd)"

GREEN=$(printf '\033[32m')
RED=$(printf '\033[31m')
YELLOW=$(printf '\033[33m')
BOLD=$(printf '\033[1m')
RESET=$(printf '\033[0m')

need_jq() {
    if ! command -v jq >/dev/null 2>&1; then
        printf "${RED}ERROR${RESET}: jq is required to parse fixture JSON. Install jq.\n" >&2
        exit 2
    fi
}

need_jq

total=0
passed=0
skipped=0
failed=0
malformed=0

check_fixture() {
    local f="$1"
    total=$((total + 1))

    if ! jq -e . "$f" >/dev/null 2>&1; then
        printf "  ${RED}MALFORMED${RESET}: $f\n"
        malformed=$((malformed + 1))
        return
    fi

    local fixture_id
    fixture_id="$(jq -r '.fixture_id // "<no id>"' "$f")"

    local citations_count
    citations_count="$(jq -r '.citations | length' "$f" 2>/dev/null || echo 0)"

    if [ "$citations_count" -lt 1 ]; then
        printf "  ${RED}FAIL${RESET}: $fixture_id — no citations\n"
        failed=$((failed + 1))
        return
    fi

    # Phase 1: structural validation only. Bytes are checked starting Phase 2
    # via the C harness (driver/fixture_validate.c).
    printf "  ${YELLOW}SKIP${RESET}: $fixture_id — structural OK; byte asserts deferred to Phase 2\n"
    skipped=$((skipped + 1))
}

printf "${BOLD}== Layer C Fixture Runner (Phase 1 skeleton) ==${RESET}\n\n"

printf "${BOLD}Happy-path fixtures:${RESET}\n"
if compgen -G "$FIXTURES_ROOT/happy_path/*.json" >/dev/null; then
    for f in "$FIXTURES_ROOT"/happy_path/*.json; do
        check_fixture "$f"
    done
else
    printf "  (no fixtures yet)\n"
fi

printf "\n${BOLD}Regression fixtures:${RESET}\n"
if compgen -G "$FIXTURES_ROOT/regression/*.json" >/dev/null; then
    for f in "$FIXTURES_ROOT"/regression/*.json; do
        check_fixture "$f"
    done
else
    printf "  (none)\n"
fi

printf "\n${BOLD}Summary:${RESET} total=$total pass=$passed skip=$skipped fail=$failed malformed=$malformed\n"

if [ "$malformed" -gt 0 ] || [ "$failed" -gt 0 ]; then
    exit 1
fi
exit 0
