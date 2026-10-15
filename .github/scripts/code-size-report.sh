#!/usr/bin/env bash
set -euo pipefail

MODE=build
if [ "${1:-}" = "--compare-results" ]; then
    if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
        echo "usage: $0 --compare-results BASE_TSV HEAD_TSV [SUMMARY_FILE]" >&2
        exit 2
    fi
    MODE=compare
    BASE_RESULTS=$2
    HEAD_RESULTS=$3
    SUMMARY_FILE=${4:-}
    if [ ! -f "$BASE_RESULTS" ] || [ ! -f "$HEAD_RESULTS" ]; then
        echo "comparison result file not found" >&2
        exit 2
    fi
else
    if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
        echo "usage: $0 BASE_SOURCE HEAD_SOURCE [SUMMARY_FILE]" >&2
        exit 2
    fi
    BASE_SOURCE=$(cd "$1" && pwd)
    HEAD_SOURCE=$(cd "$2" && pwd)
    SUMMARY_FILE=${3:-}
fi

SIZE_TOOL=${SIZE_TOOL:-size}
BUILD_CC=${CC:-gcc}
MAX_GROWTH_PERCENT=${SIZE_MAX_GROWTH_PERCENT:-5}
PARALLEL_JOBS=${PARALLEL_JOBS:-$(nproc 2>/dev/null || echo 2)}
WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/wolftpm-size.XXXXXX")

cleanup()
{
    rm -rf "$WORK_ROOT"
}
trap cleanup EXIT

required_tools=(awk)
if [ "$MODE" = build ]; then
    required_tools+=("$BUILD_CC" "$SIZE_TOOL" make)
fi
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required tool: $tool" >&2
        exit 2
    fi
done
case "$MAX_GROWTH_PERCENT" in
    ''|*[!0-9]*)
        echo "SIZE_MAX_GROWTH_PERCENT must be a non-negative integer" >&2
        exit 2
        ;;
esac
if [ "${#MAX_GROWTH_PERCENT}" -gt 3 ] || \
        [ "$MAX_GROWTH_PERCENT" -gt 100 ]; then
    echo "SIZE_MAX_GROWTH_PERCENT must be between 0 and 100" >&2
    exit 2
fi

sum_size()
{
    "$SIZE_TOOL" "$1" | awk '
        NR > 1 && $1 ~ /^[0-9]+$/ {
            text += $1
            data += $2
            bss += $3
        }
        END {
            if (NR < 2) {
                exit 1
            }
            printf "%d\t%d\t%d\n", text, data, bss
        }
    '
}

measure_tree()
{
    local source_dir=$1
    local label=$2
    local result_file=$3
    local build_dir="$WORK_ROOT/$label"
    local common_cflags="-Os -g0 -ffunction-sections -fdata-sections -DWC_RSA_NO_PADDING"
    local text_size data_size bss_size

    mkdir -p "$build_dir/client" "$build_dir/fwtpm"
    (
        cd "$source_dir"
        ./autogen.sh
    )

    (
        cd "$build_dir/client"
        "$source_dir/configure" \
            --enable-swtpm \
            --disable-fwtpm \
            --disable-examples \
            --disable-shared \
            CC="$BUILD_CC" CFLAGS="$common_cflags"
        make -j"$PARALLEL_JOBS" src/libwolftpm.la
    )

    IFS=$'\t' read -r text_size data_size bss_size < <(
        sum_size "$build_dir/client/src/.libs/libwolftpm.a"
    )
    printf 'artifact\ttext\tdata\tbss\tflash\tram\n' > "$result_file"
    printf 'libwolftpm.a\t%d\t%d\t%d\t%d\t%d\n' \
        "$text_size" "$data_size" "$bss_size" \
        "$((text_size + data_size))" "$((data_size + bss_size))" \
        >> "$result_file"

    (
        cd "$build_dir/fwtpm"
        "$source_dir/configure" \
            --enable-fwtpm-only \
            --enable-swtpm \
            --disable-shared \
            CC="$BUILD_CC" CFLAGS="$common_cflags" \
            LDFLAGS="-Wl,--gc-sections"
        make -j"$PARALLEL_JOBS" src/fwtpm/fwtpm_server
    )

    IFS=$'\t' read -r text_size data_size bss_size < <(
        sum_size "$build_dir/fwtpm/src/fwtpm/fwtpm_server"
    )
    printf 'fwtpm_server\t%d\t%d\t%d\t%d\t%d\n' \
        "$text_size" "$data_size" "$bss_size" \
        "$((text_size + data_size))" "$((data_size + bss_size))" \
        >> "$result_file"
}

signed_value()
{
    if [ "$1" -gt 0 ]; then
        printf '+%d' "$1"
    else
        printf '%d' "$1"
    fi
}

validate_measurements()
{
    local artifact=$1
    local value

    shift
    for value in "$@"; do
        case "$value" in
            ''|*[!0-9]*)
                echo "invalid size measurement for $artifact" >&2
                exit 1
                ;;
        esac
        if [ "${#value}" -gt 15 ]; then
            echo "size measurement out of range for $artifact" >&2
            exit 1
        fi
    done
}

percent_value()
{
    awk -v delta="$1" -v base="$2" 'BEGIN {
        if (base == 0) {
            if (delta == 0) {
                printf "0.00%%"
            }
            else {
                printf "n/a"
            }
        }
        else {
            printf "%+.2f%%", (delta * 100) / base
        }
    }'
}

if [ "$MODE" = build ]; then
    BASE_RESULTS="$WORK_ROOT/base.tsv"
    HEAD_RESULTS="$WORK_ROOT/head.tsv"
    measure_tree "$BASE_SOURCE" base "$BASE_RESULTS"
    measure_tree "$HEAD_SOURCE" head "$HEAD_RESULTS"
fi

REPORT_FILE="$WORK_ROOT/report.md"
{
    echo "## wolfTPM code-size report"
    echo
    echo "GCC \`-Os\` builds. Flash is text + initialized data; RAM is initialized data + BSS."
    echo
    echo "| Artifact | Base flash | Head flash | Delta | Growth | Base RAM | Head RAM | Delta | Growth |"
    echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|"
} > "$REPORT_FILE"

warning_count=0
while IFS=$'\t' read -r artifact base_text base_data base_bss \
        base_flash base_ram; do
    if [ "$artifact" = "artifact" ]; then
        continue
    fi

    head_line=$(awk -F '\t' -v artifact="$artifact" \
        '$1 == artifact { print; exit }' "$HEAD_RESULTS")
    if [ -z "$head_line" ]; then
        echo "missing head measurement for $artifact" >&2
        exit 1
    fi
    IFS=$'\t' read -r _ head_text head_data head_bss head_flash head_ram \
        <<< "$head_line"

    validate_measurements "$artifact" \
        "$base_text" "$base_data" "$base_bss" "$base_flash" "$base_ram" \
        "$head_text" "$head_data" "$head_bss" "$head_flash" "$head_ram"

    base_flash=$((10#$base_flash))
    base_ram=$((10#$base_ram))
    head_flash=$((10#$head_flash))
    head_ram=$((10#$head_ram))

    flash_delta=$((head_flash - base_flash))
    ram_delta=$((head_ram - base_ram))
    flash_percent=$(percent_value "$flash_delta" "$base_flash")
    ram_percent=$(percent_value "$ram_delta" "$base_ram")

    printf "| \`%s\` | %d B | %d B | %s B | %s | %d B | %d B | %s B | %s |\n" \
        "$artifact" "$base_flash" "$head_flash" \
        "$(signed_value "$flash_delta")" "$flash_percent" \
        "$base_ram" "$head_ram" "$(signed_value "$ram_delta")" \
        "$ram_percent" \
        >> "$REPORT_FILE"

    if { [ "$flash_delta" -gt 0 ] && \
         [ $((flash_delta * 100)) -gt \
           $((base_flash * MAX_GROWTH_PERCENT)) ]; } || \
       { [ "$ram_delta" -gt 0 ] && \
         [ $((ram_delta * 100)) -gt \
           $((base_ram * MAX_GROWTH_PERCENT)) ]; }; then
        warning_count=$((warning_count + 1))
        if [ "${GITHUB_ACTIONS:-false}" = "true" ]; then
            printf '::warning title=Code size growth exceeded::%s grew %s in flash and %s in RAM; warning threshold is %s%%\n' \
                "$artifact" "$flash_percent" "$ram_percent" \
                "$MAX_GROWTH_PERCENT"
        fi
    fi
done < "$BASE_RESULTS"

{
    printf '\nGrowth above %d%% in flash or RAM emits a warning.\n' \
        "$MAX_GROWTH_PERCENT"
} >> "$REPORT_FILE"

cat "$REPORT_FILE"
if [ -n "$SUMMARY_FILE" ]; then
    cat "$REPORT_FILE" >> "$SUMMARY_FILE"
fi

if [ "$warning_count" -gt 0 ]; then
    echo "$warning_count artifact(s) exceeded the" \
        "$MAX_GROWTH_PERCENT% growth warning threshold"
fi

if [ -n "${SIZE_WARNING_FILE:-}" ]; then
    if [ "$warning_count" -gt 0 ]; then
        echo true > "$SIZE_WARNING_FILE"
    else
        echo false > "$SIZE_WARNING_FILE"
    fi
fi
