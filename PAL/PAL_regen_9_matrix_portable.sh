#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# PAL 9-SPECIMEN MATRIX REGENERATOR — PATH-PORTABLE
#
# PAL root is resolved only from:
#
#     <script-directory>/../PAL
#
# Required argument:
#
#     $1 = path to the Ghidra project directory
#
# Optional argument:
#
#     $2 = Ghidra project name
#
# Example:
#
#     ./PAL_regen_9_matrix_portable.sh \
#         /home/rem/gh/scraps
#
#     ./PAL_regen_9_matrix_portable.sh \
#         ../scraps \
#         PAL_RELEASE_MATRIX_022
# ============================================================

usage() {
    cat <<'EOF'
Usage:
  PAL_regen_9_matrix_portable.sh PATH_TO_GHIDRA_PROJECT [PROJECT_NAME]

Arguments:
  PATH_TO_GHIDRA_PROJECT
      Existing or creatable directory in which PyGhidra stores its project.

  PROJECT_NAME
      Optional fresh Ghidra project name.
      Default: PAL_MATRIX_REGEN_<timestamp>

PAL root:
  Resolved exclusively as <script-directory>/../PAL

The script removes and regenerates only these PAL project trees:

  alpha_corpo.exe
  alpha_four.exe
  alpha_two.exe
  PALexec.exe
  o3_alpha_corpo.exe
  o3_alpha_four.exe
  o3_alpha_two.exe
  o3_PALexec.exe
  drop_axe.exe
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage >&2
    exit 2
fi

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
    pwd -P
)"

PAL_ROOT_CANDIDATE="$SCRIPT_DIR/../PAL"
[[ -d "$PAL_ROOT_CANDIDATE" ]] \
    || die "PAL root candidate does not exist: $PAL_ROOT_CANDIDATE"

PAL_ROOT="$(
    cd -- "$PAL_ROOT_CANDIDATE"
    pwd -P
)"

GHIDRA_PROJECT_PATH_INPUT="$1"
mkdir -p -- "$GHIDRA_PROJECT_PATH_INPUT"
GHIDRA_PROJECT_PATH="$(
    cd -- "$GHIDRA_PROJECT_PATH_INPUT"
    pwd -P
)"

STAMP="$(date +%Y%m%d_%H%M%S)"
GHIDRA_PROJECT_NAME="${2:-PAL_MATRIX_REGEN_${STAMP}}"

PYGHIDRA="${PYGHIDRA:-pyghidra}"
CRYSTAL_BATCH="$PAL_ROOT/crystal_batch.py"
LOG_ROOT="$PAL_ROOT/matrix_logs/regen_${STAMP}"

SPECIMENS=(
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

resolve_specimen() {
    local canonical="$1"
    local candidate="$PAL_ROOT/$canonical"

    if [[ -f "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return 0
    fi

    # Compatibility with occasional uppercase O3_ spelling.
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
    || die "PyGhidra command not found: $PYGHIDRA"

command -v sha256sum >/dev/null 2>&1 \
    || die "sha256sum is required"

[[ -f "$CRYSTAL_BATCH" ]] \
    || die "crystal_batch.py not found: $CRYSTAL_BATCH"

mkdir -p -- "$LOG_ROOT"

declare -a BINARIES=()
declare -a PROJECT_NAMES=()

printf '\nPAL MATRIX REGEN — PORTABLE PRE-FLIGHT\n'
printf 'Script directory:      %s\n' "$SCRIPT_DIR"
printf 'PAL root:              %s\n' "$PAL_ROOT"
printf 'Ghidra project path:   %s\n' "$GHIDRA_PROJECT_PATH"
printf 'Ghidra project name:   %s\n' "$GHIDRA_PROJECT_NAME"
printf 'Batch entrypoint:      %s\n' "$CRYSTAL_BATCH"
printf 'Logs:                  %s\n\n' "$LOG_ROOT"

printf '%-3s %-24s %-64s %s\n' \
    "#" "SPECIMEN" "SHA256" "MODIFIED"
printf '%-3s %-24s %-64s %s\n' \
    "---" "------------------------" \
    "----------------------------------------------------------------" \
    "--------------------------"

ordinal=0
for canonical in "${SPECIMENS[@]}"; do
    ordinal=$((ordinal + 1))

    binary="$(resolve_specimen "$canonical")" \
        || die "missing specimen: $canonical"

    project_name="$(basename "$binary")"
    digest="$(sha256sum "$binary" | awk '{print $1}')"
    modified="$(stat -c '%y' "$binary")"

    BINARIES+=("$binary")
    PROJECT_NAMES+=("$project_name")

    printf '%-3d %-24s %-64s %s\n' \
        "$ordinal" "$project_name" "$digest" "$modified"
done

printf '\nRemoving generated PAL project trees for the matrix:\n'

for project_name in "${PROJECT_NAMES[@]}"; do
    target="$PAL_ROOT/project/$project_name"
    printf '  rm -rf %s\n' "$target"
    rm -rf -- "$target"
done

summary="$LOG_ROOT/regen_summary.tsv"
printf 'specimen\tstatus\tlog\tpal_project\n' > "$summary"

declare -a FAILED=()
total="${#BINARIES[@]}"

for index in "${!BINARIES[@]}"; do
    binary="${BINARIES[$index]}"
    specimen="$(basename "$binary")"
    current=$((index + 1))
    log="$LOG_ROOT/${specimen}.pyghidra.log"

    printf '\n============================================================\n'
    printf '[%d/%d] GHIDRA + PAL BATCH: %s\n' \
        "$current" "$total" "$specimen"
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
        printf 'FAIL: %s (status=%d)\n' \
            "$specimen" "$status" >&2
        printf '%s\tFAIL(%d)\t%s\t%s\n' \
            "$specimen" "$status" "$log" "$pal_project" \
            >> "$summary"
        FAILED+=("$specimen")
    fi
done

printf '\n============================================================\n'
printf 'PAL MATRIX REGEN SUMMARY\n'
printf '============================================================\n'

if command -v column >/dev/null 2>&1; then
    column -t -s $'\t' "$summary"
else
    cat "$summary"
fi

printf '\nGhidra project: %s/%s\n' \
    "$GHIDRA_PROJECT_PATH" "$GHIDRA_PROJECT_NAME"
printf 'Summary:        %s\n' "$summary"

if (( ${#FAILED[@]} > 0 )); then
    printf 'FAILED SPECIMENS: %s\n' "${FAILED[*]}" >&2
    exit 1
fi

printf 'PASS: all nine specimens regenerated.\n'
