#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <results-dir> <repository> <head-sha> <details-url>" >&2
    exit 2
fi

RESULTS_DIR=$1
REPOSITORY=$2
HEAD_SHA=$3
DETAILS_URL=$4
CHECK_NAME="Code Size Advisory (PR-reported)"
MAX_GROWTH_PERCENT=${SIZE_MAX_GROWTH_PERCENT:-5}

if [[ ! "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
   [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]] ||
   [[ ! "$MAX_GROWTH_PERCENT" =~ ^[0-9]+$ ]]; then
    echo "invalid advisory metadata" >&2
    exit 1
fi

result_files=()
while IFS= read -r result_file; do
    result_files+=("$result_file")
done < <(find "$RESULTS_DIR" -type f -name code-size-warning.txt | sort)

if [ "${#result_files[@]}" -ne 2 ]; then
    echo "expected two code-size warning results" >&2
    exit 1
fi

warning=false
for result_file in "${result_files[@]}"; do
    result=$(<"$result_file")
    case "$result" in
        true)
            warning=true
            ;;
        false)
            ;;
        *)
            echo "invalid code-size warning result" >&2
            exit 1
            ;;
    esac
done

if [ "$warning" = true ]; then
    conclusion=neutral
    title="PR-reported code size growth exceeded ${MAX_GROWTH_PERCENT}%"
    summary="The PR measurement reported growth above the advisory threshold. Review the measurement workflow for exact flash and RAM changes."
else
    conclusion=success
    title="PR-reported code size growth is within ${MAX_GROWTH_PERCENT}%"
    summary="The PR measurement reported all configurations within the advisory threshold."
fi

payload=$(jq -nc \
    --arg name "$CHECK_NAME" \
    --arg head_sha "$HEAD_SHA" \
    --arg details_url "$DETAILS_URL" \
    --arg conclusion "$conclusion" \
    --arg title "$title" \
    --arg summary "$summary" \
    '{name:$name, head_sha:$head_sha, details_url:$details_url,
      status:"completed", conclusion:$conclusion,
      output:{title:$title, summary:$summary}}')

if [ "${CODE_SIZE_ADVISORY_DRY_RUN:-false}" = true ]; then
    echo "$payload"
    exit 0
fi

if [ -z "${GH_TOKEN:-}" ]; then
    echo "GH_TOKEN is required" >&2
    exit 1
fi

api_url="${GITHUB_API_URL:-https://api.github.com}/repos/$REPOSITORY"
curl_args=(
    -fsS --retry 3
    -H "Accept: application/vnd.github+json"
    -H "Authorization: Bearer $GH_TOKEN"
    -H "X-GitHub-Api-Version: 2022-11-28"
)
checks=$(
    curl "${curl_args[@]}" \
        "$api_url/commits/$HEAD_SHA/check-runs?check_name=Code%20Size%20Advisory%20%28PR-reported%29&filter=latest"
)
check_id=$(jq -r '.check_runs[0].id // empty' <<< "$checks")
if [ -n "$check_id" ] && [[ ! "$check_id" =~ ^[0-9]+$ ]]; then
    echo "invalid existing check identifier" >&2
    exit 1
fi

if [ -n "$check_id" ]; then
    jq -c 'del(.head_sha)' <<< "$payload" |
        curl "${curl_args[@]}" -X PATCH --data-binary @- \
            "$api_url/check-runs/$check_id" >/dev/null
else
    curl "${curl_args[@]}" -X POST --data-binary "$payload" \
        "$api_url/check-runs" >/dev/null
fi
