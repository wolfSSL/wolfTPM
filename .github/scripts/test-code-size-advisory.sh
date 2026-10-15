#!/usr/bin/env bash
set -euo pipefail

if [ "$(basename "$0")" = curl ]; then
    capture_payload=false
    is_lookup=false
    payload=""
    for arg in "$@"; do
        if [ "$capture_payload" = true ]; then
            payload=$arg
            capture_payload=false
        fi
        if [ "$arg" = "--data-binary" ]; then
            capture_payload=true
        fi
        case "$arg" in
            */commits/*/check-runs\?*)
                is_lookup=true
                ;;
        esac
        printf 'ARG %s\n' "$arg" >> "$CURL_LOG"
    done
    if [ "$payload" = "@-" ]; then
        payload=$(cat)
    fi
    if [ -n "$payload" ]; then
        printf 'PAYLOAD %s\n' "$payload" >> "$CURL_LOG"
    fi
    if [ "$is_lookup" = true ]; then
        if [ -n "${MOCK_CHECK_ID:-}" ]; then
            printf '{"check_runs":[{"id":%s}]}\n' "$MOCK_CHECK_ID"
        else
            echo '{"check_runs":[]}'
        fi
    else
        echo '{"id":1}'
    fi
    exit 0
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ADVISORY_SCRIPT="$SCRIPT_DIR/code-size-advisory.sh"
WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/wolftpm-size-advisory-test.XXXXXX")
SHA=0123456789abcdef0123456789abcdef01234567

cleanup()
{
    rm -rf "$WORK_ROOT"
}
trap cleanup EXIT

mkdir -p "$WORK_ROOT/stable" "$WORK_ROOT/master"
echo false > "$WORK_ROOT/stable/code-size-warning.txt"
echo false > "$WORK_ROOT/master/code-size-warning.txt"

output=$(CODE_SIZE_ADVISORY_DRY_RUN=true "$ADVISORY_SCRIPT" \
    "$WORK_ROOT" wolfSSL/wolfTPM "$SHA" https://example.test/run)
jq -e '.conclusion == "success" and
    .output.title == "PR-reported code size growth is within 5%"' \
    <<< "$output" >/dev/null

echo true > "$WORK_ROOT/master/code-size-warning.txt"
output=$(CODE_SIZE_ADVISORY_DRY_RUN=true "$ADVISORY_SCRIPT" \
    "$WORK_ROOT" wolfSSL/wolfTPM "$SHA" https://example.test/run)
jq -e '.conclusion == "neutral" and
    .output.title == "PR-reported code size growth exceeded 5%"' \
    <<< "$output" >/dev/null

echo invalid > "$WORK_ROOT/master/code-size-warning.txt"
if CODE_SIZE_ADVISORY_DRY_RUN=true "$ADVISORY_SCRIPT" \
        "$WORK_ROOT" wolfSSL/wolfTPM "$SHA" https://example.test/run \
        >/dev/null 2>&1; then
    echo "invalid warning result was accepted" >&2
    exit 1
fi

echo false > "$WORK_ROOT/master/code-size-warning.txt"
mkdir "$WORK_ROOT/bin"
ln -s "$SCRIPT_DIR/test-code-size-advisory.sh" "$WORK_ROOT/bin/curl"

if PATH="$WORK_ROOT/bin:$PATH" GH_TOKEN='' "$ADVISORY_SCRIPT" \
        "$WORK_ROOT" wolfSSL/wolfTPM "$SHA" https://example.test/run \
        >/dev/null 2>&1; then
    echo "missing API token was accepted" >&2
    exit 1
fi

CURL_LOG="$WORK_ROOT/curl.log"
: > "$CURL_LOG"
PATH="$WORK_ROOT/bin:$PATH" GH_TOKEN=test CURL_LOG="$CURL_LOG" \
    "$ADVISORY_SCRIPT" "$WORK_ROOT" wolfSSL/wolfTPM "$SHA" \
    https://example.test/run
grep -Fqx 'ARG POST' "$CURL_LOG"
payload=$(sed -n 's/^PAYLOAD //p' "$CURL_LOG" | tail -n 1)
jq -e '.conclusion == "success" and has("head_sha")' \
    <<< "$payload" >/dev/null

: > "$CURL_LOG"
PATH="$WORK_ROOT/bin:$PATH" GH_TOKEN=test CURL_LOG="$CURL_LOG" \
    MOCK_CHECK_ID=42 "$ADVISORY_SCRIPT" "$WORK_ROOT" wolfSSL/wolfTPM \
    "$SHA" https://example.test/run
grep -Fqx 'ARG PATCH' "$CURL_LOG"
grep -Fq 'ARG https://api.github.com/repos/wolfSSL/wolfTPM/check-runs/42' \
    "$CURL_LOG"
payload=$(sed -n 's/^PAYLOAD //p' "$CURL_LOG" | tail -n 1)
jq -e '.conclusion == "success" and (has("head_sha") | not)' \
    <<< "$payload" >/dev/null

echo "code-size advisory tests passed"
