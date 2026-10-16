#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPORT_SCRIPT="$SCRIPT_DIR/code-size-report.sh"
WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/wolftpm-size-test.XXXXXX")

cleanup()
{
    rm -rf "$WORK_ROOT"
}
trap cleanup EXIT

printf '%s\n' \
    $'artifact\ttext\tdata\tbss\tflash\tram' \
    $'exact\t90\t10\t90\t100\t100' \
    $'negative\t290\t10\t90\t300\t100' \
    $'zero\t390\t10\t90\t400\t100' > "$WORK_ROOT/base.tsv"

printf '%s\n' \
    $'artifact\ttext\tdata\tbss\tflash\tram' \
    $'exact\t95\t10\t95\t105\t105' \
    $'negative\t280\t10\t80\t290\t90' \
    $'zero\t390\t10\t90\t400\t100' > "$WORK_ROOT/head.tsv"

output=$(GITHUB_ACTIONS=true SIZE_MAX_GROWTH_PERCENT=5 \
    SIZE_WARNING_FILE="$WORK_ROOT/warning.txt" \
    "$REPORT_SCRIPT" --compare-results \
    "$WORK_ROOT/base.tsv" "$WORK_ROOT/head.tsv" "$WORK_ROOT/summary.md")

grep -Fq "| \`exact\` | 100 B | 105 B | +5 B | +5.00% | 100 B | 105 B | +5 B | +5.00% |" \
    <<< "$output"
grep -Fq "| \`negative\` | 300 B | 290 B | -10 B | -3.33% | 100 B | 90 B | -10 B | -10.00% |" \
    <<< "$output"
grep -Fq "| \`zero\` | 400 B | 400 B | 0 B | +0.00% | 100 B | 100 B | 0 B | +0.00% |" \
    <<< "$output"
grep -Fq 'Growth above 5% in flash or RAM emits a warning.' \
    <<< "$output"
if grep -Fq '::warning' <<< "$output"; then
    echo "exact threshold unexpectedly emitted a warning" >&2
    exit 1
fi
grep -Fq '## wolfTPM code-size report' "$WORK_ROOT/summary.md"
grep -Fxq false "$WORK_ROOT/warning.txt"

sed $'s/^exact\t95\t10\t95\t105\t105$/exact\t96\t10\t95\t106\t105/' \
    "$WORK_ROOT/head.tsv" > "$WORK_ROOT/flash-warning.tsv"
output=$(GITHUB_ACTIONS=true SIZE_MAX_GROWTH_PERCENT=5 \
    SIZE_WARNING_FILE="$WORK_ROOT/warning.txt" \
    "$REPORT_SCRIPT" --compare-results \
    "$WORK_ROOT/base.tsv" "$WORK_ROOT/flash-warning.tsv")
grep -Fq '::warning title=Code size growth exceeded::exact grew +6.00% in flash and +5.00% in RAM; warning threshold is 5%' \
    <<< "$output"
grep -Fq '1 artifact(s) exceeded the 5% growth warning threshold' <<< "$output"
grep -Fxq true "$WORK_ROOT/warning.txt"

sed $'s/^exact\t95\t10\t95\t105\t105$/exact\t95\t10\t96\t105\t106/' \
    "$WORK_ROOT/head.tsv" > "$WORK_ROOT/ram-warning.tsv"
output=$(GITHUB_ACTIONS=true SIZE_MAX_GROWTH_PERCENT=5 \
    "$REPORT_SCRIPT" --compare-results \
    "$WORK_ROOT/base.tsv" "$WORK_ROOT/ram-warning.tsv")
grep -Fq '::warning title=Code size growth exceeded::exact grew +5.00% in flash and +6.00% in RAM; warning threshold is 5%' \
    <<< "$output"

SIZE_MAX_GROWTH_PERCENT=6 "$REPORT_SCRIPT" --compare-results \
    "$WORK_ROOT/base.tsv" "$WORK_ROOT/flash-warning.tsv" >/dev/null

sed '$d' "$WORK_ROOT/head.tsv" > "$WORK_ROOT/head-missing.tsv"
if "$REPORT_SCRIPT" --compare-results \
        "$WORK_ROOT/base.tsv" "$WORK_ROOT/head-missing.tsv" \
        >/dev/null 2>&1; then
    echo "missing artifact did not fail" >&2
    exit 1
fi

if SIZE_MAX_GROWTH_PERCENT=invalid "$REPORT_SCRIPT" --compare-results \
        "$WORK_ROOT/base.tsv" "$WORK_ROOT/head.tsv" >/dev/null 2>&1; then
    echo "invalid growth percentage did not fail" >&2
    exit 1
fi

# shellcheck disable=SC2016 # The command substitution must remain literal.
payload='required_tools[$(touch '"$WORK_ROOT"'/executed)]'
printf '%s\n' \
    $'artifact\ttext\tdata\tbss\tflash\tram' \
    $'payload\t90\t10\t90\t100\t100' > "$WORK_ROOT/payload-base.tsv"
printf 'artifact\ttext\tdata\tbss\tflash\tram\n' \
    > "$WORK_ROOT/payload-head.tsv"
printf 'payload\t96\t10\t96\t%s\t106\n' "$payload" \
    >> "$WORK_ROOT/payload-head.tsv"
if "$REPORT_SCRIPT" --compare-results "$WORK_ROOT/payload-base.tsv" \
        "$WORK_ROOT/payload-head.tsv" >/dev/null 2>&1; then
    echo "malformed size measurement did not fail" >&2
    exit 1
fi
if [ -e "$WORK_ROOT/executed" ]; then
    echo "malformed size measurement was evaluated" >&2
    exit 1
fi

echo "code-size report tests passed"
