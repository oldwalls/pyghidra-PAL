#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# PAL 9-SPECIMEN GHIDRA/BATCH REGENERATOR
#
# Matrix:
#   O0/default: alpha_corpo, alpha_four, alpha_two, PALexec
#   O3:         o3_alpha_corpo, o3_alpha_four, o3_alpha_two,
#               o3_PALexec
#   game:       drop_axe
#
# One fresh Ghidra project name is used for all nine imports.
# The corresponding PAL project/<binary> trees are removed first.
# ============================================================

PAL_ROOT="${PAL_ROOT:-/home/rem/gh/PAL/pyghidra-PAL/PAL}"
GHIDRA_PROJECT_PATH="${GHIDRA_PROJECT_PATH:-/home/rem/gh/scraps}"
PYGHIDRA="${PYGHIDRA:-pyghidra}"
CRYSTAL_BATCH="${CRYSTAL_BATCH:-$PAL_ROOT/crystal_batch.py}"
STAMP="${PAL_MATRIX_STAMP:-$(date +%Y%m%d_%H%M%S)}"
GHIDRA_PROJECT_NAME="${GHIDRA_PROJECT_NAME:-PAL_MATRIX_REGEN_${STAMP}}"
LOG_ROOT="${PAL_MATRIX_LOG_ROOT:-$PAL_ROOT/matrix_logs/regen_${STAMP}}"
CLEAN_PAL_PROJECT_OUTPUTS="${CLEAN_PAL_PROJECT_OUTPUTS:-1}"

CANONICAL_SPECIMENS=(
    "alpha_corpo.exe"
    "alpha_four.exe"
    "alpha_two.exe"
    "PALexec.exe"
    "o3_alpha_corpo.exe"
    "o3_alpha_four.exe"
    "o3_alpha_two.exe"
    "o3_PALexec.exe"
    "drop_axe.exe"
)

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

resolve_specimen() {
    local canonical="$1"
    local candidate="$PAL_ROOT/$canonical"

    if [[ -f "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return 0
    fi

    # Accept the user's occasional uppercase O3_ spelling while keeping
    # lowercase o3_ as the canonical matrix name.
    if [[ "$canonical" == o3_* ]]; then
        candidate="$PAL_ROOT/O3_${canonical#o3_}"
        if [[ -f "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi

    return 1
}

command -v "$PYGHIDRA" >/dev/null 2>&1 \
    || die "pyghidra command not found: $PYGHIDRA"
command -v sha256sum >/dev/null 2>&1 \
    || die "sha256sum is required"
[[ -d "$PAL_ROOT" ]] \
    || die "PAL root does not exist: $PAL_ROOT"
[[ -f "$CRYSTAL_BATCH" ]] \
    || die "crystal_batch.py not found: $CRYSTAL_BATCH"

mkdir -p "$GHIDRA_PROJECT_PATH" "$LOG_ROOT"

declare -a RESOLVED_BINARIES=()
declare -a PROJECT_NAMES=()

printf '\nPAL 9-SPECIMEN REGEN PRE-FLIGHT\n'
printf 'PAL root:             %s\n' "$PAL_ROOT"
printf 'Ghidra project path:  %s\n' "$GHIDRA_PROJECT_PATH"
printf 'Ghidra project name:  %s\n' "$GHIDRA_PROJECT_NAME"
printf 'Batch entrypoint:     %s\n' "$CRYSTAL_BATCH"
printf 'Logs:                 %s\n\n' "$LOG_ROOT"

printf '%-3s %-24s %-64s %s\n' \
    "#" "SPECIMEN" "SHA256" "TIMESTAMP"
printf '%-3s %-24s %-64s %s\n' \
    "---" "------------------------" \
    "----------------------------------------------------------------" \
    "--------------------------"

index=0
for canonical in "${CANONICAL_SPECIMENS[@]}"; do
    index=$((index + 1))
    binary="$(resolve_specimen "$canonical")" \
        || die "missing specimen: $PAL_ROOT/$canonical (also tried O3_ form)"

    actual_name="$(basename "$binary")"
    digest="$(sha256sum "$binary" | awk '{print $1}')"
    modified="$(stat -c '%y' "$binary")"

    RESOLVED_BINARIES+=("$binary")
    PROJECT_NAMES+=("$actual_name")

    printf '%-3d %-24s %-64s %s\n' \
        "$index" "$actual_name" "$digest" "$modified"
done

printf '\n'

if [[ "$CLEAN_PAL_PROJECT_OUTPUTS" == "1" ]]; then
    printf 'Removing the nine generated PAL project trees before regeneration:\n'
    for project_name in "${PROJECT_NAMES[@]}"; do
        target="$PAL_ROOT/project/$project_name"
        printf '  rm -rf %s\n' "$target"
        rm -rf -- "$target"
    done
    printf '\n'
else
    printf 'CLEAN_PAL_PROJECT_OUTPUTS=%s; existing PAL project trees retained.\n\n' \
        "$CLEAN_PAL_PROJECT_OUTPUTS"
fi

summary="$LOG_ROOT/regen_summary.tsv"
printf 'specimen\tstatus\tlog\tpal_project\n' > "$summary"

declare -a FAILED=()
total="${#RESOLVED_BINARIES[@]}"

for i in "${!RESOLVED_BINARIES[@]}"; do
    binary="${RESOLVED_BINARIES[$i]}"
    specimen="$(basename "$binary")"
    ordinal=$((i + 1))
    log="$LOG_ROOT/${specimen}.pyghidra.log"

    printf '\n============================================================\n'
    printf '[%d/%d] GHIDRA + PAL BATCH: %s\n' \
        "$ordinal" "$total" "$specimen"
    printf '============================================================\n'

    set +e
    "$PYGHIDRA" \
        --project-name "$GHIDRA_PROJECT_NAME" \
        --project-path "$GHIDRA_PROJECT_PATH" \
        "$binary" \
        "$CRYSTAL_BATCH" \
        2>&1 | tee "$log"
    status=${PIPESTATUS[0]}
    set -e

    pal_project="$PAL_ROOT/project/$specimen"

    if [[ "$status" -eq 0 \
          && -f "$pal_project/PAL_function_manifest.json" \
          && -f "$pal_project/PAL_dispatch.py" ]]; then
        printf 'PASS: %s\n' "$specimen"
        printf '%s\tPASS\t%s\t%s\n' \
            "$specimen" "$log" "$pal_project" >> "$summary"
    else
        printf 'FAIL: %s (status=%d)\n' "$specimen" "$status" >&2
        printf '%s\tFAIL(%d)\t%s\t%s\n' \
            "$specimen" "$status" "$log" "$pal_project" >> "$summary"
        FAILED+=("$specimen")
    fi
done

printf '\n============================================================\n'
printf 'PAL MATRIX REGEN SUMMARY\n'
printf '============================================================\n'
column -t -s $'\t' "$summary" 2>/dev/null || cat "$summary"
printf '\nGhidra project: %s/%s\n' \
    "$GHIDRA_PROJECT_PATH" "$GHIDRA_PROJECT_NAME"
printf 'Summary file:  %s\n' "$summary"

if (( ${#FAILED[@]} > 0 )); then
    printf 'FAILED SPECIMENS: %s\n' "${FAILED[*]}" >&2
    exit 1
fi

printf 'PASS: all nine specimens regenerated.\n'
