#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================================================================
# PAL ALL-EXE IMPORT + PUBLISH MATRIX — REGRESSION FORENSICS v6
#
# Discovers every regular *.exe file directly in PAL_ROOT, imports each binary
# through PyGhidra, runs crystal_batch.py, audits the published PAL bundle, and
# produces a self-contained FAILED report for every specimen that regresses.
# The outer PyGhidra stream and the canonical internal PALBatchDecompiler streams are archived.
# v5 freezes PyGhidra/PALBatchDecompiler cwd to PAL_ROOT, exports PAL_ROOT and
# PYTHONPATH custody, publishes launch receipts, and renders a compact TABLOID.
# v6 keeps every archival stream byte-complete while defaulting the terminal to
# project/function progress, bounds summary diagnostics, and accepts legacy TSV
# fields larger than Python csv's 128 KiB default.
#
# Each FAILED report contains:
#   - separate PyGhidra stdout and stderr streams plus a combined transcript;
#   - an outer-process transcript of the complete inherited textual stream;
#   - canonical PALBatchDecompiler per-function stdout/stderr/combined logs;
#   - unbounded exact copies of canonical internal logs in failed archives;
#   - a framed outer stream-order transcript with timing metadata;
#   - separate audit stdout and stderr streams;
#   - manifest-derived failed-function inventory and errors;
#   - textual pipeline/debug/ExecTree artifacts relevant to failed functions;
#   - audit, manifest, environment, tree inventory, error excerpts and hashes;
#   - one self-contained .tar.gz archive per failed specimen.
#
# Default layout:
#   PAL root:        script directory when crystal_batch.py is beside it;
#                    otherwise <script-directory>/../PAL
#   Ghidra projects: PAL_ROOT/.ghidra_projects
#   Published tree: PAL_ROOT/project/<specimen-name>
#   Reports:         PAL_ROOT/log_matrix/run_<UTC timestamp>_<pid>
#
# Optional positional arguments:
#   $1 = Ghidra project directory
#   $2 = Ghidra project name
#
# Environment overrides:
#   PAL_ROOT               Explicit PAL root
#   PYGHIDRA               PyGhidra command, default: pyghidra
#   CRYSTAL_BATCH          Batch script, default: PAL_ROOT/crystal_batch.py
#   LOG_MATRIX_ROOT        Report root, default: PAL_ROOT/log_matrix
#   PAL_TIMEOUT_SECONDS    Per-specimen timeout; 0 disables, default: 0
#   PAL_FAILED_REPORT_MAX_FILE_BYTES
#                          Max copied debug artifact size, default: 33554432
#   PAL_FAILED_REPORT_MAX_FILES
#                          Max debug artifacts per failed specimen, default: 512
#   PAL_FAILED_REPORT_EXTRA_ROOTS
#                          Colon-separated extra roots searched for fresh textual
#                          pipeline/debug artifacts
#   PAL_TABLOID            1 renders the final human TABLOID, default: 1
#   PAL_TABLOID_VIEWER     Viewer path, default: PAL_ROOT/PAL_log_tabloid.sh
#   PAL_CONSOLE_MODE       progress (default), full, or silent
#   PAL_SUMMARY_DIAGNOSTIC_MAX_CHARS
#                          Bounded TSV diagnostic size, default: 32768. The
#                          complete diagnostic remains in the audit JSON/log.
# ==============================================================================

usage() {
    cat <<'USAGE'
Usage:
  PAL_import_publish_all_exe_matrix.sh [GHIDRA_PROJECT_PATH] [PROJECT_NAME]

Discovers every regular file matching *.exe, case-insensitively, directly in
PAL_ROOT. Each executable is imported into one Ghidra project and published
through crystal_batch.py.

Defaults:
  GHIDRA_PROJECT_PATH = PAL_ROOT/.ghidra_projects
  PROJECT_NAME        = PAL_ALL_EXE_<UTC timestamp>_<pid>
  reports             = PAL_ROOT/log_matrix/run_<UTC timestamp>_<pid>

Environment:
  PAL_ROOT
  PYGHIDRA
  CRYSTAL_BATCH
  LOG_MATRIX_ROOT
  PAL_TIMEOUT_SECONDS
  PAL_FAILED_REPORT_MAX_FILE_BYTES
  PAL_FAILED_REPORT_MAX_FILES
  PAL_FAILED_REPORT_EXTRA_ROOTS
  PAL_TABLOID
  PAL_TABLOID_VIEWER
  PAL_CONSOLE_MODE
  PAL_SUMMARY_DIAGNOSTIC_MAX_CHARS
USAGE
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

quote_cmd() {
    local arg
    printf 'COMMAND:'
    for arg in "$@"; do
        printf ' %q' "$arg"
    done
    printf '\n'
}

canonical_dir() {
    local path="$1"
    mkdir -p -- "$path"
    (
        cd -- "$path"
        pwd -P
    )
}

canonical_file() {
    local path="$1"
    local dir base
    dir="$(dirname -- "$path")"
    base="$(basename -- "$path")"
    (
        cd -- "$dir"
        printf '%s/%s\n' "$(pwd -P)" "$base"
    )
}

safe_slug() {
    local value="$1"
    value="$(printf '%s' "$value" | sed -E 's/[^[:alnum:]._-]+/_/g; s/^_+//; s/_+$//')"
    [[ -n "$value" ]] || value="specimen"
    printf '%s\n' "$value"
}

iso_utc() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

if [[ $# -gt 2 ]]; then
    usage >&2
    exit 2
fi

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
    pwd -P
)"

if [[ -n "${PAL_ROOT:-}" ]]; then
    [[ -d "$PAL_ROOT" ]] || die "PAL_ROOT does not exist: $PAL_ROOT"
    PAL_ROOT="$(cd -- "$PAL_ROOT" && pwd -P)"
elif [[ -f "$SCRIPT_DIR/crystal_batch.py" ]]; then
    PAL_ROOT="$SCRIPT_DIR"
elif [[ -d "$SCRIPT_DIR/../PAL" ]]; then
    PAL_ROOT="$(cd -- "$SCRIPT_DIR/../PAL" && pwd -P)"
else
    die "cannot resolve PAL root; place this script in PAL or set PAL_ROOT"
fi

# v5 launch-root custody. PALBatchDecompiler defaults output_root to os.getcwd(),
# so the PyGhidra child must run from the same PAL_ROOT audited by this script.
CALLER_PWD="$(pwd -P)"
PAL_BATCH_CWD="$PAL_ROOT"
cd -- "$PAL_ROOT"
[[ "$(pwd -P)" == "$PAL_ROOT" ]]     || die "failed to enter PAL_ROOT: expected=$PAL_ROOT observed=$(pwd -P)"
export PAL_ROOT
case ":${PYTHONPATH:-}:" in
    *":$PAL_ROOT:"*) ;;
    *) export PYTHONPATH="$PAL_ROOT${PYTHONPATH:+:$PYTHONPATH}" ;;
esac

PYGHIDRA="${PYGHIDRA:-pyghidra}"
CRYSTAL_BATCH="${CRYSTAL_BATCH:-$PAL_ROOT/crystal_batch.py}"
LOG_MATRIX_ROOT="${LOG_MATRIX_ROOT:-$PAL_ROOT/log_matrix}"
PAL_TIMEOUT_SECONDS="${PAL_TIMEOUT_SECONDS:-0}"
PAL_FAILED_REPORT_MAX_FILE_BYTES="${PAL_FAILED_REPORT_MAX_FILE_BYTES:-33554432}"
PAL_FAILED_REPORT_MAX_FILES="${PAL_FAILED_REPORT_MAX_FILES:-512}"
PAL_FAILED_REPORT_EXTRA_ROOTS="${PAL_FAILED_REPORT_EXTRA_ROOTS:-}"
PAL_TABLOID="${PAL_TABLOID:-1}"
PAL_TABLOID_VIEWER="${PAL_TABLOID_VIEWER:-$PAL_ROOT/PAL_log_tabloid.sh}"
PAL_CONSOLE_MODE="${PAL_CONSOLE_MODE:-progress}"
PAL_SUMMARY_DIAGNOSTIC_MAX_CHARS="${PAL_SUMMARY_DIAGNOSTIC_MAX_CHARS:-32768}"

[[ "$PAL_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] \
    || die "PAL_TIMEOUT_SECONDS must be a non-negative integer"
[[ "$PAL_FAILED_REPORT_MAX_FILE_BYTES" =~ ^[1-9][0-9]*$ ]] \
    || die "PAL_FAILED_REPORT_MAX_FILE_BYTES must be a positive integer"
[[ "$PAL_FAILED_REPORT_MAX_FILES" =~ ^[1-9][0-9]*$ ]] \
    || die "PAL_FAILED_REPORT_MAX_FILES must be a positive integer"
[[ "$PAL_TABLOID" =~ ^[01]$ ]] \
    || die "PAL_TABLOID must be 0 or 1"
[[ "$PAL_CONSOLE_MODE" =~ ^(progress|full|silent)$ ]] \
    || die "PAL_CONSOLE_MODE must be progress, full, or silent"
[[ "$PAL_SUMMARY_DIAGNOSTIC_MAX_CHARS" =~ ^[1-9][0-9]*$ ]] \
    || die "PAL_SUMMARY_DIAGNOSTIC_MAX_CHARS must be a positive integer"
export PAL_CONSOLE_MODE
export PAL_SUMMARY_DIAGNOSTIC_MAX_CHARS

command -v "$PYGHIDRA" >/dev/null 2>&1 \
    || die "PyGhidra command not found: $PYGHIDRA"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
command -v find >/dev/null 2>&1 || die "find is required"
command -v sort >/dev/null 2>&1 || die "sort is required"
command -v tee >/dev/null 2>&1 || die "tee is required"
command -v sed >/dev/null 2>&1 || die "sed is required"
command -v mktemp >/dev/null 2>&1 || die "mktemp is required"
command -v mkfifo >/dev/null 2>&1 || die "mkfifo is required"

if (( PAL_TIMEOUT_SECONDS > 0 )); then
    command -v timeout >/dev/null 2>&1 \
        || die "timeout is required when PAL_TIMEOUT_SECONDS is nonzero"
fi

[[ -f "$CRYSTAL_BATCH" ]] \
    || die "crystal_batch.py not found: $CRYSTAL_BATCH"
CRYSTAL_BATCH="$(canonical_file "$CRYSTAL_BATCH")"

GHIDRA_PROJECT_PATH_INPUT="${1:-$PAL_ROOT/.ghidra_projects}"
GHIDRA_PROJECT_PATH="$(canonical_dir "$GHIDRA_PROJECT_PATH_INPUT")"

RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
GHIDRA_PROJECT_NAME="${2:-PAL_ALL_EXE_${RUN_STAMP}_$$}"

[[ "$GHIDRA_PROJECT_NAME" =~ ^[[:alnum:]_.-]+$ ]] \
    || die "project name contains unsupported characters: $GHIDRA_PROJECT_NAME"

LOG_MATRIX_ROOT="$(canonical_dir "$LOG_MATRIX_ROOT")"
RUN_DIR="$LOG_MATRIX_ROOT/run_${RUN_STAMP}_$$"
PER_SPECIMEN_DIR="$RUN_DIR/specimens"
AUDIT_DIR="$RUN_DIR/audits"
TREE_DIR="$RUN_DIR/publish_trees"
MANIFEST_DIR="$RUN_DIR/manifests"
FAILED_REPORTS_DIR="$RUN_DIR/failed_reports"
FAILED_ARCHIVES_DIR="$RUN_DIR/failed_archives"

mkdir -p -- \
    "$RUN_DIR" \
    "$PER_SPECIMEN_DIR" \
    "$AUDIT_DIR" \
    "$TREE_DIR" \
    "$MANIFEST_DIR" \
    "$FAILED_REPORTS_DIR" \
    "$FAILED_ARCHIVES_DIR"

MASTER_LOG="$RUN_DIR/master.log"
INVENTORY_TSV="$RUN_DIR/inventory.tsv"
SUMMARY_TSV="$RUN_DIR/summary.tsv"
SUMMARY_JSON="$RUN_DIR/summary.json"
ENV_REPORT="$RUN_DIR/environment.txt"
FAILURES_TXT="$RUN_DIR/failures.txt"
RUN_STATUS="$RUN_DIR/run.status"

# Capture the complete stdout/stderr transcript from this point onward.
exec > >(tee -a "$MASTER_LOG") 2>&1

ABORTED=0
on_signal() {
    ABORTED=1
    printf '\nSIGNAL: matrix run interrupted; current specimen will be recorded.\n' >&2
}
trap on_signal INT TERM

mapfile -d '' -t BINARIES < <(
    find "$PAL_ROOT" \
        -maxdepth 1 \
        -type f \
        -iname '*.exe' \
        -print0 \
    | LC_ALL=C sort -z
)

(( ${#BINARIES[@]} > 0 )) \
    || die "no *.exe files found directly in PAL root: $PAL_ROOT"

{
    printf 'run_started_utc=%s\n' "$(iso_utc)"
    printf 'script=%s\n' "$(canonical_file "${BASH_SOURCE[0]}")"
    printf 'script_sha256=%s\n' "$(sha256sum "${BASH_SOURCE[0]}" | awk '{print $1}')"
    printf 'pal_root=%s\n' "$PAL_ROOT"
    printf 'caller_pwd=%s\n' "$CALLER_PWD"
    printf 'matrix_process_pwd=%s\n' "$(pwd -P)"
    printf 'pyghidra_child_cwd=%s\n' "$PAL_BATCH_CWD"
    printf 'pythonpath=%s\n' "${PYTHONPATH:-}"
    printf 'pyghidra_command=%s\n' "$PYGHIDRA"
    printf 'crystal_batch=%s\n' "$CRYSTAL_BATCH"
    printf 'crystal_batch_sha256=%s\n' "$(sha256sum "$CRYSTAL_BATCH" | awk '{print $1}')"
    printf 'ghidra_project_path=%s\n' "$GHIDRA_PROJECT_PATH"
    printf 'ghidra_project_name=%s\n' "$GHIDRA_PROJECT_NAME"
    printf 'log_matrix_root=%s\n' "$LOG_MATRIX_ROOT"
    printf 'run_directory=%s\n' "$RUN_DIR"
    printf 'timeout_seconds=%s\n' "$PAL_TIMEOUT_SECONDS"
    printf 'failed_report_max_file_bytes=%s\n' "$PAL_FAILED_REPORT_MAX_FILE_BYTES"
    printf 'failed_report_max_files=%s\n' "$PAL_FAILED_REPORT_MAX_FILES"
    printf 'failed_report_extra_roots=%s\n' "$PAL_FAILED_REPORT_EXTRA_ROOTS"
    printf 'tabloid_enabled=%s\n' "$PAL_TABLOID"
    printf 'tabloid_viewer=%s\n' "$PAL_TABLOID_VIEWER"
    printf 'console_mode=%s\n' "$PAL_CONSOLE_MODE"
    printf 'summary_diagnostic_max_chars=%s\n' \
        "$PAL_SUMMARY_DIAGNOSTIC_MAX_CHARS"
    printf 'host=%s\n' "$(hostname 2>/dev/null || printf unknown)"
    printf 'kernel=%s\n' "$(uname -srmo 2>/dev/null || printf unknown)"
    printf 'bash=%s\n' "$BASH_VERSION"
    printf 'python=%s\n' "$(python3 --version 2>&1)"
    printf 'pyghidra_path=%s\n' "$(command -v "$PYGHIDRA")"
    printf 'pyghidra_version_begin\n'
    "$PYGHIDRA" --version 2>&1 || true
    printf 'pyghidra_version_end\n'
} > "$ENV_REPORT"

printf 'ordinal\tspecimen\tabsolute_path\tbytes\tsha256\tmodified_utc\n' \
    > "$INVENTORY_TSV"

printf '\nPAL ALL-EXE IMPORT + PUBLISH MATRIX v6\n'
printf 'Run started:            %s\n' "$(iso_utc)"
printf 'Executables discovered: %d\n' "${#BINARIES[@]}"
printf 'Ghidra project name:    %s\n' "$GHIDRA_PROJECT_NAME"
printf 'Console mode:           %s\n' "$PAL_CONSOLE_MODE"
printf 'Report directory:       %s\n\n' "$RUN_DIR"

if [[ "$PAL_CONSOLE_MODE" == "full" ]]; then
    printf 'PAL root:               %s\n' "$PAL_ROOT"
    printf 'Caller directory:       %s\n' "$CALLER_PWD"
    printf 'Enforced child cwd:     %s\n' "$PAL_BATCH_CWD"
    printf 'Ghidra project path:    %s\n' "$GHIDRA_PROJECT_PATH"
    printf 'Batch entrypoint:       %s\n\n' "$CRYSTAL_BATCH"
    printf '%-4s %-34s %-12s %-64s %s\n' \
        "#" "SPECIMEN" "BYTES" "SHA256" "MODIFIED UTC"
    printf '%-4s %-34s %-12s %-64s %s\n' \
        "----" "----------------------------------" "------------" \
        "----------------------------------------------------------------" \
        "--------------------"
fi

ordinal=0
for binary in "${BINARIES[@]}"; do
    ordinal=$((ordinal + 1))
    specimen="$(basename -- "$binary")"
    bytes="$(stat -c '%s' "$binary")"
    digest="$(sha256sum "$binary" | awk '{print $1}')"
    modified="$(date -u -d "@$(stat -c '%Y' "$binary")" '+%Y-%m-%dT%H:%M:%SZ')"

    printf '%d\t%s\t%s\t%s\t%s\t%s\n' \
        "$ordinal" "$specimen" "$binary" "$bytes" "$digest" "$modified" \
        >> "$INVENTORY_TSV"

    if [[ "$PAL_CONSOLE_MODE" == "full" ]]; then
        printf '%-4d %-34s %-12s %-64s %s\n' \
            "$ordinal" "$specimen" "$bytes" "$digest" "$modified"
    fi
done

if [[ "$PAL_CONSOLE_MODE" == "full" ]]; then
    printf '\n'
fi

printf '%s\n' \
    $'ordinal\tspecimen\tstatus\tpyghidra_exit\taudit_exit\telapsed_seconds\tmanifest_status\tdiscovered\tenumerated\tdecompiled\tfailed\tskipped_external\tpublish_bytes\tpublish_files\tbinary_sha256\tbinary_path\tpublish_path\tpyghidra_log\tpyghidra_stdout\tpyghidra_stderr\tpipeline_full_transcript\tpipeline_framed_transcript\tpipeline_transcript_meta\taudit_stdout\taudit_stderr\taudit_json\ttree_report\tfailed_report_dir\tfailed_report_archive\tfailed_function_records\tdebug_artifacts_copied\tstarted_utc\tfinished_utc\tdiagnostic' \
    > "$SUMMARY_TSV"
: > "$FAILURES_TXT"

audit_publish_bundle() {
    local publish_dir="$1"
    local specimen="$2"
    local expected_binary_sha="$3"
    local audit_json="$4"

    python3 - "$publish_dir" "$specimen" "$expected_binary_sha" "$audit_json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

publish_dir = Path(sys.argv[1])
specimen = sys.argv[2]
expected_binary_sha = sys.argv[3]
audit_path = Path(sys.argv[4])

errors = []
warnings = []
checked_artifacts = 0
checked_python = 0
publish_bytes = 0
publish_files = 0

manifest_path = publish_dir / "PAL_function_manifest.json"
dispatch_path = publish_dir / "PAL_dispatch.py"
jump_table_path = publish_dir / "PAL_jump_table.json"
functions_path = publish_dir / "functions"


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


manifest = None
manifest_status = "missing"
counts = {
    "discovered": 0,
    "enumerated": 0,
    "decompiled": 0,
    "failed": 0,
    "skipped_external": 0,
}
program_name = None
program_executable_path = None

if not publish_dir.is_dir():
    errors.append(f"publish directory missing: {publish_dir}")
else:
    for path in publish_dir.rglob("*"):
        if path.is_file():
            publish_files += 1
            try:
                publish_bytes += path.stat().st_size
            except OSError as exc:
                errors.append(f"cannot stat published file {path}: {exc}")

for required in (manifest_path, dispatch_path, jump_table_path):
    if not required.is_file():
        errors.append(f"required published artifact missing: {required.name}")

if not functions_path.is_dir():
    errors.append("functions directory missing")

if manifest_path.is_file():
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"manifest JSON unreadable: {type(exc).__name__}: {exc}")

if isinstance(manifest, dict):
    manifest_status = str(manifest.get("status") or "unknown")
    raw_counts = manifest.get("counts") or {}
    for key in counts:
        try:
            counts[key] = int(raw_counts.get(key, 0) or 0)
        except Exception:
            errors.append(f"manifest count is not an integer: {key}")
            counts[key] = 0

    program = manifest.get("program") or {}
    program_name = program.get("name")
    program_executable_path = program.get("executable_path")

    if manifest_status != "complete":
        errors.append(f"manifest status is {manifest_status!r}, expected 'complete'")
    if counts["failed"] != 0:
        errors.append(f"manifest reports {counts['failed']} failed function(s)")
    if counts["decompiled"] < 1:
        errors.append("manifest reports no decompiled functions")
    if counts["enumerated"] != (
        counts["decompiled"] + counts["failed"] + counts["skipped_external"]
    ):
        errors.append(
            "manifest count mismatch: enumerated != "
            "decompiled + failed + skipped_external"
        )
    if counts["discovered"] < counts["enumerated"]:
        errors.append("manifest count mismatch: discovered < enumerated")

    if program_name and program_name != specimen:
        warnings.append(
            f"manifest program name {program_name!r} differs from specimen {specimen!r}"
        )

    functions = manifest.get("functions")
    if not isinstance(functions, list):
        errors.append("manifest functions field is not a list")
        functions = []

    record_status_counts = {}
    for record in functions:
        if not isinstance(record, dict):
            errors.append("manifest contains a non-object function record")
            continue

        status = str(record.get("status") or "unknown")
        record_status_counts[status] = record_status_counts.get(status, 0) + 1

        if status == "failed":
            name = record.get("qualified_name") or record.get("name") or "unknown"
            error = record.get("error") or {}
            errors.append(
                f"function failed: {name}: "
                f"{error.get('type', 'Error')}: {error.get('message', '')}"
            )

        artifacts = record.get("artifacts") or {}
        if not isinstance(artifacts, dict):
            errors.append("function artifacts field is not an object")
            continue

        for artifact_name, artifact in artifacts.items():
            if not isinstance(artifact, dict):
                errors.append(
                    f"artifact descriptor is not an object: {artifact_name}"
                )
                continue

            rel = artifact.get("path")
            expected_sha = artifact.get("sha256")
            if not rel:
                errors.append(f"artifact path missing: {artifact_name}")
                continue

            artifact_path = (publish_dir / rel).resolve()
            try:
                artifact_path.relative_to(publish_dir.resolve())
            except ValueError:
                errors.append(
                    f"artifact escapes publish directory: {artifact_name}: {rel}"
                )
                continue

            if not artifact_path.is_file():
                errors.append(
                    f"manifest artifact missing: {artifact_name}: {rel}"
                )
                continue

            checked_artifacts += 1
            if expected_sha:
                actual_sha = sha256_file(artifact_path)
                if actual_sha != expected_sha:
                    errors.append(
                        f"artifact hash mismatch: {artifact_name}: {rel}"
                    )

    if record_status_counts.get("decompiled", 0) != counts["decompiled"]:
        errors.append("record count mismatch for decompiled functions")
    if record_status_counts.get("failed", 0) != counts["failed"]:
        errors.append("record count mismatch for failed functions")
    if record_status_counts.get("skipped_external", 0) != counts["skipped_external"]:
        errors.append("record count mismatch for skipped external functions")

# Syntax-check every published Python file without importing or writing pyc files.
if publish_dir.is_dir():
    for path in sorted(publish_dir.rglob("*.py")):
        try:
            source = path.read_text(encoding="utf-8")
            compile(source, str(path), "exec")
            checked_python += 1
        except Exception as exc:
            errors.append(
                f"Python syntax failure: {path.relative_to(publish_dir)}: "
                f"{type(exc).__name__}: {exc}"
            )

result = {
    "audit_schema": "pal_publish_audit_v1",
    "ok": not errors,
    "specimen": specimen,
    "expected_binary_sha256": expected_binary_sha,
    "publish_directory": str(publish_dir),
    "manifest_path": str(manifest_path),
    "manifest_status": manifest_status,
    "program_name": program_name,
    "program_executable_path": program_executable_path,
    "counts": counts,
    "publish_files": publish_files,
    "publish_bytes": publish_bytes,
    "checked_manifest_artifacts": checked_artifacts,
    "checked_python_files": checked_python,
    "warnings": warnings,
    "errors": errors,
}

audit_path.parent.mkdir(parents=True, exist_ok=True)
audit_path.write_text(
    json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
    encoding="utf-8",
)

for warning in warnings:
    print(f"AUDIT WARNING: {warning}")
for error in errors:
    print(f"AUDIT ERROR: {error}")

print(
    "AUDIT RESULT: "
    + ("PASS" if result["ok"] else "FAIL")
    + f" | manifest={manifest_status}"
    + f" | decompiled={counts['decompiled']}"
    + f" | failed={counts['failed']}"
    + f" | files={publish_files}"
    + f" | bytes={publish_bytes}"
)

sys.exit(0 if result["ok"] else 1)
PY
}

read_audit_fields() {
    local audit_json="$1"

    python3 - "$audit_json" <<'PY'
import json
import os
import sys

path = sys.argv[1]
try:
    with open(path, "rt", encoding="utf-8") as handle:
        data = json.load(handle)
except Exception as exc:
    data = {
        "manifest_status": "audit_unreadable",
        "counts": {},
        "publish_bytes": 0,
        "publish_files": 0,
        "errors": [f"{type(exc).__name__}: {exc}"],
    }

counts = data.get("counts") or {}
errors = data.get("errors") or []
warnings = data.get("warnings") or []
diagnostic = "; ".join(str(x) for x in errors + warnings)
diagnostic = diagnostic.replace("\t", " ").replace("\r", " ").replace("\n", " ")
try:
    diagnostic_limit = int(
        os.environ.get("PAL_SUMMARY_DIAGNOSTIC_MAX_CHARS", "32768")
    )
except (TypeError, ValueError):
    diagnostic_limit = 32768
diagnostic_limit = max(1, diagnostic_limit)
if len(diagnostic) > diagnostic_limit:
    omitted = len(diagnostic) - diagnostic_limit
    diagnostic = (
        diagnostic[:diagnostic_limit]
        + f" ... [SUMMARY TRUNCATED: {omitted} characters omitted; "
        + f"full evidence: {path}]"
    )

fields = [
    data.get("manifest_status", "unknown"),
    counts.get("discovered", 0),
    counts.get("enumerated", 0),
    counts.get("decompiled", 0),
    counts.get("failed", 0),
    counts.get("skipped_external", 0),
    data.get("publish_bytes", 0),
    data.get("publish_files", 0),
    diagnostic,
]
for field in fields:
    print(field)
PY
}

run_captured_streams() {
    local stdout_file="$1"
    local stderr_file="$2"
    local combined_file="$3"
    shift 3

    : > "$stdout_file"
    : > "$stderr_file"
    touch -- "$combined_file"

    # Named pipes let us wait only for this command's two tee consumers. A
    # bare `wait` would also wait for the script-wide master-log process
    # substitution and deadlock the matrix runner.
    local capture_dir stdout_fifo stderr_fifo stdout_pid stderr_pid status
    capture_dir="$(mktemp -d "$RUN_DIR/.capture.XXXXXX")"
    stdout_fifo="$capture_dir/stdout.fifo"
    stderr_fifo="$capture_dir/stderr.fifo"
    mkfifo -- "$stdout_fifo" "$stderr_fifo"

    if [[ "$PAL_CONSOLE_MODE" == "full" ]]; then
        tee -a "$stdout_file" "$combined_file" < "$stdout_fifo" &
    else
        tee -a "$stdout_file" "$combined_file" < "$stdout_fifo" >/dev/null &
    fi
    stdout_pid=$!
    if [[ "$PAL_CONSOLE_MODE" == "full" ]]; then
        tee -a "$stderr_file" "$combined_file" < "$stderr_fifo" >&2 &
    else
        tee -a "$stderr_file" "$combined_file" < "$stderr_fifo" >/dev/null &
    fi
    stderr_pid=$!

    "$@" > "$stdout_fifo" 2> "$stderr_fifo"
    status=$?

    wait "$stdout_pid" || true
    wait "$stderr_pid" || true
    rm -rf -- "$capture_dir"
    return "$status"
}

run_pipeline_archived_streams() {
    local stdout_file="$1"
    local stderr_file="$2"
    local combined_file="$3"
    local transcript_file="$4"
    local framed_file="$5"
    local metadata_file="$6"
    shift 6

    python3 - \
        "$stdout_file" \
        "$stderr_file" \
        "$combined_file" \
        "$transcript_file" \
        "$framed_file" \
        "$metadata_file" \
        "$PAL_BATCH_CWD" \
        "$@" <<'PIPELINE_ARCHIVE_PY'
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import selectors
import shlex
import subprocess
import sys
import time
from pathlib import Path

stdout_path = Path(sys.argv[1])
stderr_path = Path(sys.argv[2])
combined_path = Path(sys.argv[3])
transcript_path = Path(sys.argv[4])
framed_path = Path(sys.argv[5])
metadata_path = Path(sys.argv[6])
cwd = sys.argv[7]
command = sys.argv[8:]
console_mode = os.environ.get("PAL_CONSOLE_MODE", "progress")

if not command:
    raise SystemExit("pipeline capture received no command")
if console_mode not in {"progress", "full", "silent"}:
    raise SystemExit(
        "PAL_CONSOLE_MODE must be progress, full, or silent; "
        f"observed={console_mode!r}"
    )

for path in (
    stdout_path,
    stderr_path,
    combined_path,
    transcript_path,
    framed_path,
    metadata_path,
):
    path.parent.mkdir(parents=True, exist_ok=True)


def utc_now():
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


started_utc = utc_now()
started_monotonic_ns = time.monotonic_ns()
sequence = 0
stream_chunks = {"stdout": 0, "stderr": 0}
stream_bytes = {"stdout": 0, "stderr": 0}
console_buffers = {"stdout": bytearray(), "stderr": bytearray()}
progress_patterns = (
    re.compile(
        r"^\[\d+/\d+\]\s+"
        r"(?:decompile|skip external)\s+.+(?:\s+@\s+0x[0-9a-fA-F]+)?$"
    ),
    re.compile(r"^\s+(?:OK|FAILED)\s+->\s+\S+"),
    re.compile(
        r"^PAL batch (?:complete|partial|interrupted):\s+"
        r"\d+ decompiled,\s+\d+ failed,\s+\d+ external skipped$"
    ),
    re.compile(r"^PAL batch interrupted by operator$"),
)


def console_destination(stream_name):
    return (
        sys.stdout.buffer
        if stream_name == "stdout"
        else sys.stderr.buffer
    )


def emit_progress_line(stream_name, line):
    rendered = line.decode("utf-8", errors="replace").rstrip("\r")
    if not any(pattern.match(rendered) for pattern in progress_patterns):
        return
    destination = console_destination(stream_name)
    try:
        destination.write(rendered.encode("utf-8", errors="replace") + b"\n")
        destination.flush()
    except BrokenPipeError:
        pass


def emit_console_bytes(stream_name, data, final=False):
    if console_mode == "silent":
        return
    if console_mode == "full":
        if not data:
            return
        destination = console_destination(stream_name)
        try:
            destination.write(data)
            destination.flush()
        except BrokenPipeError:
            pass
        return

    buffer = console_buffers[stream_name]
    if data:
        buffer.extend(data)
    while True:
        newline = buffer.find(b"\n")
        if newline < 0:
            break
        line = bytes(buffer[:newline])
        del buffer[: newline + 1]
        emit_progress_line(stream_name, line)
    if final and buffer:
        emit_progress_line(stream_name, bytes(buffer))
        buffer.clear()

process = subprocess.Popen(
    command,
    cwd=cwd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    bufsize=0,
)
selector = selectors.DefaultSelector()
selector.register(process.stdout, selectors.EVENT_READ, "stdout")
selector.register(process.stderr, selectors.EVENT_READ, "stderr")

interrupted = False
returncode = None

with (
    stdout_path.open("wb") as stdout_handle,
    stderr_path.open("wb") as stderr_handle,
    combined_path.open("wb") as combined_handle,
    transcript_path.open("wb") as transcript_handle,
    framed_path.open("wb") as framed_handle,
):
    stream_files = {
        "stdout": stdout_handle,
        "stderr": stderr_handle,
    }

    try:
        while selector.get_map():
            events = selector.select(timeout=0.25)
            if not events:
                if process.poll() is not None:
                    # Continue until both pipes report EOF.
                    continue
                continue

            for key, unused_mask in events:
                stream_name = key.data
                try:
                    data = os.read(key.fileobj.fileno(), 65536)
                except OSError:
                    data = b""

                if not data:
                    emit_console_bytes(stream_name, b"", final=True)
                    try:
                        selector.unregister(key.fileobj)
                    except Exception:
                        pass
                    try:
                        key.fileobj.close()
                    except Exception:
                        pass
                    continue

                sequence += 1
                observed_ns = time.monotonic_ns()
                stream_chunks[stream_name] += 1
                stream_bytes[stream_name] += len(data)

                stream_files[stream_name].write(data)
                stream_files[stream_name].flush()

                # These two files contain the same unmodified bytes in the
                # order observed by the capture supervisor. The explicitly
                # named transcript is the archival authority.
                combined_handle.write(data)
                combined_handle.flush()
                transcript_handle.write(data)
                transcript_handle.flush()

                header = (
                    "\n===== PAL PIPELINE STREAM CHUNK "
                    f"{sequence:08d} "
                    f"stream={stream_name} "
                    f"monotonic_ns={observed_ns} "
                    f"bytes={len(data)} =====\n"
                ).encode("utf-8")
                footer = (
                    "\n===== END PAL PIPELINE STREAM CHUNK "
                    f"{sequence:08d} =====\n"
                ).encode("utf-8")
                framed_handle.write(header)
                framed_handle.write(data)
                framed_handle.write(footer)
                framed_handle.flush()

                emit_console_bytes(stream_name, data)

        returncode = process.wait()
    except KeyboardInterrupt:
        interrupted = True
        try:
            process.terminate()
        except Exception:
            pass
        try:
            returncode = process.wait(timeout=10)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
            returncode = process.wait()
        if returncode == 0:
            returncode = 130
    finally:
        selector.close()

finished_monotonic_ns = time.monotonic_ns()
finished_utc = utc_now()

files = {}
for label, path in (
    ("stdout", stdout_path),
    ("stderr", stderr_path),
    ("combined", combined_path),
    ("full_transcript", transcript_path),
    ("framed_transcript", framed_path),
):
    files[label] = {
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }

metadata = {
    "schema": "pal_pipeline_full_text_transcript_v3_progress_console",
    "supervisor_process_cwd": os.getcwd(),
    "child_cwd": cwd,
    "child_cwd_exists": Path(cwd).is_dir(),
    "capture_policy": {
        "full_transcript_truncated": False,
        "framed_transcript_truncated": False,
        "artifact_count_limit_applied": False,
        "artifact_size_limit_applied": False,
        "merge_order": "capture_supervisor_observation_order",
        "stream_identity_preserved_in": str(framed_path),
        "console_mode": console_mode,
        "console_is_archival_authority": False,
        "progress_filter_changes_archived_streams": False,
    },
    "command": command,
    "command_shell": shlex.join(command),
    "cwd": cwd,
    "pid": process.pid,
    "returncode": int(returncode),
    "interrupted": interrupted,
    "started_utc": started_utc,
    "finished_utc": finished_utc,
    "started_monotonic_ns": started_monotonic_ns,
    "finished_monotonic_ns": finished_monotonic_ns,
    "elapsed_monotonic_ns": (
        finished_monotonic_ns - started_monotonic_ns
    ),
    "observed_chunks": sequence,
    "stream_chunks": stream_chunks,
    "stream_bytes": stream_bytes,
    "files": files,
}
metadata_path.write_text(
    json.dumps(
        metadata,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
    )
    + "\n",
    encoding="utf-8",
)

raise SystemExit(int(returncode))
PIPELINE_ARCHIVE_PY
}

diagnose_publish_custody() {
    local diagnostic_path="$1"
    local specimen="$2"
    local expected_publish_dir="$3"
    local pyghidra_exit="$4"
    local transcript_path="$5"
    local metadata_path="$6"
    local launch_receipt_path="$7"

    python3 - \
        "$diagnostic_path" \
        "$specimen" \
        "$expected_publish_dir" \
        "$pyghidra_exit" \
        "$transcript_path" \
        "$metadata_path" \
        "$launch_receipt_path" \
        "$PAL_ROOT" \
        "$CALLER_PWD" \
        "$SCRIPT_DIR" \
        "$GHIDRA_PROJECT_PATH" <<'PAL_PUBLISH_CUSTODY_PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

(
    output_path,
    specimen,
    expected_publish_text,
    pyghidra_exit_text,
    transcript_text,
    metadata_text,
    launch_receipt_text,
    pal_root_text,
    caller_pwd_text,
    script_dir_text,
    ghidra_project_path_text,
) = sys.argv[1:]

expected_publish = Path(expected_publish_text)
transcript_path = Path(transcript_text)
metadata_path = Path(metadata_text)
launch_path = Path(launch_receipt_text)
pal_root = Path(pal_root_text).resolve()

def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

metadata = read_json(metadata_path)
launch = read_json(launch_path)
transcript = (
    transcript_path.read_text(encoding="utf-8", errors="replace")
    if transcript_path.is_file()
    else ""
)
lower = transcript.lower()

roots = []
for raw in (
    caller_pwd_text,
    script_dir_text,
    ghidra_project_path_text,
    pal_root_text,
):
    try:
        root = Path(raw).resolve()
    except Exception:
        continue
    if root not in roots:
        roots.append(root)

misplaced = []
for root in roots:
    candidate = root / "project" / specimen
    if candidate.resolve() == expected_publish.resolve():
        continue
    manifest = candidate / "PAL_function_manifest.json"
    if manifest.is_file():
        misplaced.append({
            "publish_dir": str(candidate),
            "manifest": str(manifest),
        })

exception_markers = [
    "traceback",
    "modulenotfounderror",
    "importerror",
    "exception",
    "runtimeerror",
    "syntaxerror",
    "fatal",
]
markers = [
    marker for marker in exception_markers
    if marker in lower
]

child_cwd = metadata.get("child_cwd") or metadata.get("cwd")
try:
    cwd_agrees = Path(str(child_cwd)).resolve() == pal_root
except Exception:
    cwd_agrees = False

expected_exists = expected_publish.is_dir()
if expected_exists:
    classification = "expected_publish_tree_present"
elif misplaced:
    classification = "publish_tree_misplaced_outside_pal_root"
elif not transcript.strip():
    classification = "pyghidra_clean_exit_without_observed_script_output"
elif markers:
    classification = "crystal_batch_or_pipeline_exception_before_publication"
elif int(pyghidra_exit_text) == 0:
    classification = "clean_outer_exit_without_publication"
else:
    classification = "pyghidra_process_failure"

payload = {
    "schema": "pal_publish_custody_diagnostic_v1",
    "specimen": specimen,
    "classification": classification,
    "pyghidra_exit": int(pyghidra_exit_text),
    "expected_publish_dir": str(expected_publish),
    "expected_publish_exists": expected_exists,
    "child_cwd": child_cwd,
    "pal_root": str(pal_root),
    "cwd_agrees_with_pal_root": cwd_agrees,
    "launch_cwd_authority_agrees": launch.get(
        "cwd_authority_agrees"
    ),
    "transcript_bytes": (
        transcript_path.stat().st_size
        if transcript_path.is_file()
        else 0
    ),
    "exception_markers": markers,
    "misplaced_publish_trees": misplaced,
    "next_evidence": {
        "full_transcript": str(transcript_path),
        "transcript_metadata": str(metadata_path),
        "launch_receipt": str(launch_path),
    },
}
Path(output_path).write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

print(
    "PUBLISH CUSTODY: classification=%s cwd=%s expected=%s misplaced=%d"
    % (
        classification,
        "PAL_ROOT" if cwd_agrees else child_cwd,
        "yes" if expected_exists else "no",
        len(misplaced),
    )
)
for item in misplaced:
    print("  MISPLACED PUBLISH:", item["publish_dir"])
if markers:
    print("  PIPELINE MARKERS:", ", ".join(markers))
PAL_PUBLISH_CUSTODY_PY
}

build_failed_report() {
    local specimen="$1"
    local prefix="$2"
    local binary="$3"
    local binary_sha="$4"
    local publish_dir="$5"
    local manifest_path="$6"
    local pyghidra_stdout="$7"
    local pyghidra_stderr="$8"
    local pyghidra_combined="$9"
    shift 9
    local pipeline_transcript="$1"
    local pipeline_framed="$2"
    local pipeline_metadata="$3"
    local launch_receipt="$4"
    local publish_diagnostic="$5"
    local audit_stdout="$6"
    local audit_stderr="$7"
    local audit_combined="$8"
    local audit_json="$9"
    local tree_report="${10}"
    local manifest_snapshot="${11}"
    shift 11
    local environment_report="$1"
    local started_epoch="$2"
    local finished_epoch="$3"
    local pyghidra_exit="$4"
    local audit_exit="$5"
    local report_dir="$6"
    local archive_path="$7"

    python3 - \
        "$specimen" \
        "$prefix" \
        "$binary" \
        "$binary_sha" \
        "$PAL_ROOT" \
        "$publish_dir" \
        "$manifest_path" \
        "$pyghidra_stdout" \
        "$pyghidra_stderr" \
        "$pyghidra_combined" \
        "$pipeline_transcript" \
        "$pipeline_framed" \
        "$pipeline_metadata" \
        "$launch_receipt" \
        "$publish_diagnostic" \
        "$audit_stdout" \
        "$audit_stderr" \
        "$audit_combined" \
        "$audit_json" \
        "$tree_report" \
        "$manifest_snapshot" \
        "$environment_report" \
        "$started_epoch" \
        "$finished_epoch" \
        "$pyghidra_exit" \
        "$audit_exit" \
        "$report_dir" \
        "$archive_path" \
        "$PAL_FAILED_REPORT_MAX_FILE_BYTES" \
        "$PAL_FAILED_REPORT_MAX_FILES" \
        "$PAL_FAILED_REPORT_EXTRA_ROOTS" <<'FAILED_REPORT_PY'
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
from pathlib import Path

(
    specimen,
    prefix,
    binary_text,
    binary_sha,
    pal_root_text,
    publish_dir_text,
    manifest_path_text,
    pyghidra_stdout_text,
    pyghidra_stderr_text,
    pyghidra_combined_text,
    pipeline_transcript_text,
    pipeline_framed_text,
    pipeline_metadata_text,
    launch_receipt_text,
    publish_diagnostic_text,
    audit_stdout_text,
    audit_stderr_text,
    audit_combined_text,
    audit_json_text,
    tree_report_text,
    manifest_snapshot_text,
    environment_report_text,
    started_epoch_text,
    finished_epoch_text,
    pyghidra_exit_text,
    audit_exit_text,
    report_dir_text,
    archive_path_text,
    max_file_bytes_text,
    max_files_text,
    extra_roots_text,
) = sys.argv[1:]

binary = Path(binary_text)
pal_root = Path(pal_root_text)
publish_dir = Path(publish_dir_text)
manifest_path = Path(manifest_path_text)
report_dir = Path(report_dir_text)
archive_path = Path(archive_path_text)
started_epoch = int(started_epoch_text)
finished_epoch = int(finished_epoch_text)
pyghidra_exit = int(pyghidra_exit_text)
audit_exit = int(audit_exit_text)
max_file_bytes = int(max_file_bytes_text)
max_files = int(max_files_text)

if report_dir.exists():
    shutil.rmtree(report_dir)
report_dir.mkdir(parents=True)
(report_dir / "streams").mkdir()
(report_dir / "authorities").mkdir()
(report_dir / "pipeline_artifacts").mkdir()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def copy_authority(source_text: str, destination: Path):
    source = Path(source_text)
    if not source.is_file():
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return destination


stream_sources = {
    "pyghidra.stdout.log": Path(pyghidra_stdout_text),
    "pyghidra.stderr.log": Path(pyghidra_stderr_text),
    "pyghidra.combined.log": Path(pyghidra_combined_text),
    "pipeline.full.transcript.log": Path(pipeline_transcript_text),
    "pipeline.full.transcript.framed.log": Path(pipeline_framed_text),
    "pipeline.full.transcript.meta.json": Path(pipeline_metadata_text),
    "audit.stdout.log": Path(audit_stdout_text),
    "audit.stderr.log": Path(audit_stderr_text),
    "audit.combined.log": Path(audit_combined_text),
}
for name, source in stream_sources.items():
    copy_authority(str(source), report_dir / "streams" / name)

copy_authority(audit_json_text, report_dir / "authorities" / "audit.json")
copy_authority(
    launch_receipt_text,
    report_dir / "authorities" / "launch.custody.json",
)
copy_authority(
    publish_diagnostic_text,
    report_dir / "authorities" / "publish.custody.diagnostic.json",
)
copy_authority(tree_report_text, report_dir / "authorities" / "publish_tree.tsv")
copy_authority(environment_report_text, report_dir / "authorities" / "environment.txt")

manifest_source = manifest_path if manifest_path.is_file() else Path(manifest_snapshot_text)
copy_authority(str(manifest_source), report_dir / "authorities" / "PAL_function_manifest.json")
manifest = read_json(manifest_source) if manifest_source.is_file() else None

failed_functions = []
functions = manifest.get("functions") if isinstance(manifest, dict) else []
if not isinstance(functions, list):
    functions = []
for ordinal, record in enumerate(functions, 1):
    if not isinstance(record, dict) or str(record.get("status") or "") != "failed":
        continue
    error = record.get("error") if isinstance(record.get("error"), dict) else {}
    failed_functions.append({
        "ordinal": ordinal,
        "name": record.get("name") or "",
        "qualified_name": record.get("qualified_name") or "",
        "python_symbol": record.get("python_symbol") or "",
        "function_id": record.get("function_id") or "",
        "entry": record.get("entry"),
        "entry_hex": record.get("entry_hex") or "",
        "module_stem": record.get("module_stem") or "",
        "error_type": error.get("type") or "",
        "error_message": error.get("message") or record.get("diagnostic") or "",
        "traceback": error.get("traceback") or "",
        "record": record,
    })

manifest_failed_function_records = len(failed_functions)

if not failed_functions:
    failed_functions.append({
        "ordinal": 0,
        "name": "<project-level failure>",
        "qualified_name": "",
        "python_symbol": "",
        "function_id": "",
        "entry": None,
        "entry_hex": "",
        "module_stem": "",
        "error_type": "PyGhidraOrAuditFailure",
        "error_message": (
            "No manifest function record with status=failed was available; "
            "inspect captured streams and error excerpt."
        ),
        "traceback": "",
        "record": {},
    })

# Canonical PALBatchDecompiler stream artifacts are copied before the fuzzy
# debug search. They are never truncated and never count against the
# supplementary artifact limits.
internal_stream_root = report_dir / "internal_pipeline_streams"
internal_stream_root.mkdir(parents=True, exist_ok=True)
internal_stream_index = []
internal_seen = set()


def safe_component(value, fallback="function"):
    text = re.sub(r"[^0-9A-Za-z_.-]+", "_", str(value or ""))
    text = text.strip("._")
    return text or fallback


def add_internal_stream(
    function_item,
    artifact_key,
    source_path,
    declared_sha256=None,
):
    try:
        source_path = Path(source_path).resolve()
    except Exception:
        source_path = Path(source_path)
    if not source_path.is_file() or source_path in internal_seen:
        return
    internal_seen.add(source_path)

    function_dir = safe_component(
        function_item.get("module_stem")
        or function_item.get("entry_hex")
        or function_item.get("name")
    )
    destination = (
        internal_stream_root
        / function_dir
        / source_path.name
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, destination)

    source_sha = sha256_file(source_path)
    copied_sha = sha256_file(destination)
    if source_sha != copied_sha:
        raise RuntimeError(
            "canonical internal pipeline stream copy hash mismatch: %s"
            % source_path
        )
    internal_stream_index.append({
        "function": function_item.get("qualified_name")
        or function_item.get("name"),
        "function_id": function_item.get("function_id"),
        "entry_hex": function_item.get("entry_hex"),
        "module_stem": function_item.get("module_stem"),
        "artifact_key": artifact_key,
        "source": str(source_path),
        "copied": str(destination.relative_to(report_dir)),
        "bytes": source_path.stat().st_size,
        "sha256": source_sha,
        "declared_sha256": declared_sha256,
        "declared_sha256_matches": (
            declared_sha256 in (None, "", source_sha)
        ),
        "truncated": False,
        "copy_policy": (
            "canonical_manifest_or_module_stem_pipeline_stream_unbounded"
        ),
    })


for item in failed_functions:
    record = item.get("record") or {}
    artifacts = record.get("artifacts") or {}
    if isinstance(artifacts, dict):
        for artifact_key, descriptor in artifacts.items():
            if not str(artifact_key).startswith("pipeline"):
                continue
            if not isinstance(descriptor, dict) or not descriptor.get("path"):
                continue
            add_internal_stream(
                item,
                str(artifact_key),
                publish_dir / str(descriptor["path"]),
                descriptor.get("sha256"),
            )

    stem = str(item.get("module_stem") or "").strip()
    if stem:
        function_root = publish_dir / "functions"
        for candidate in sorted(
            function_root.glob(stem + ".pipeline*")
        ):
            add_internal_stream(
                item,
                "module_stem_fallback",
                candidate,
            )

# A catastrophic batch failure may prevent failed manifest records from being
# written. Preserve any internal pipeline streams that did materialize.
if not internal_stream_index:
    project_level = failed_functions[0]
    for candidate in sorted(
        (publish_dir / "functions").glob("*.pipeline*")
    ):
        add_internal_stream(
            project_level,
            "project_level_fallback",
            candidate,
        )

(report_dir / "internal_pipeline_streams.json").write_text(
    json.dumps(
        internal_stream_index,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
    )
    + "\n",
    encoding="utf-8",
)
with (
    report_dir / "internal_pipeline_streams.tsv"
).open("wt", encoding="utf-8", newline="") as handle:
    writer = csv.writer(
        handle, delimiter="\t", lineterminator="\n"
    )
    writer.writerow([
        "function", "function_id", "entry_hex", "module_stem",
        "artifact_key", "source", "copied", "bytes", "sha256",
        "declared_sha256", "declared_sha256_matches",
        "truncated", "copy_policy",
    ])
    for item in internal_stream_index:
        writer.writerow([
            item.get("function"),
            item.get("function_id"),
            item.get("entry_hex"),
            item.get("module_stem"),
            item.get("artifact_key"),
            item.get("source"),
            item.get("copied"),
            item.get("bytes"),
            item.get("sha256"),
            item.get("declared_sha256"),
            item.get("declared_sha256_matches"),
            item.get("truncated"),
            item.get("copy_policy"),
        ])

failed_json = [
    {key: value for key, value in item.items() if key != "record"}
    for item in failed_functions
]
(report_dir / "failed_functions.json").write_text(
    json.dumps(failed_json, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
    encoding="utf-8",
)
with (report_dir / "failed_functions.tsv").open("wt", encoding="utf-8", newline="") as handle:
    writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
    writer.writerow([
        "ordinal", "name", "qualified_name", "python_symbol", "function_id",
        "entry", "entry_hex", "error_type", "error_message",
    ])
    for item in failed_functions:
        writer.writerow([
            item["ordinal"], item["name"], item["qualified_name"],
            item["python_symbol"], item["function_id"], item["entry"],
            item["entry_hex"], item["error_type"],
            str(item["error_message"]).replace("\t", " ").replace("\n", " "),
        ])

tokens = set()
for item in failed_functions:
    for value in (
        item.get("name"), item.get("qualified_name"), item.get("python_symbol"),
        item.get("function_id"), item.get("entry_hex"), item.get("module_stem"),
        item.get("entry"),
    ):
        if value in (None, ""):
            continue
        raw = str(value).lower()
        candidates = {raw, re.sub(r"[^a-z0-9]+", "", raw)}
        if raw.startswith("0x"):
            candidates.add(raw[2:])
        for token in candidates:
            if len(token) >= 4 and token not in {"main", "func", "function", "failed"}:
                tokens.add(token)

text_suffixes = {
    ".log", ".txt", ".trace", ".debug", ".dump", ".out", ".err",
    ".json", ".jsonl", ".tsv", ".csv", ".md", ".py",
}
debug_markers = (
    "pipeline", "debug", "trace", "dump", "exec_tree", "exectree",
    "sgl", "palexec", "stderr", "stdout", "error", "failure",
    "icecube", "manifest",
)

roots = []

def add_root(label: str, path: Path, recursive: bool = True):
    try:
        resolved = path.resolve()
    except Exception:
        resolved = path
    if not resolved.exists() or any(existing[1] == resolved for existing in roots):
        return
    roots.append((label, resolved, recursive))

add_root("publish", publish_dir, True)
add_root("PAL_logs", pal_root / "PAL_logs", True)
add_root("PAL_log", pal_root / "log", True)
add_root("PAL_debug", pal_root / "debug", True)
add_root("PAL_root_top", pal_root, False)
for root_index, raw_root in enumerate(filter(None, extra_roots_text.split(":")), 1):
    add_root("extra_%02d" % root_index, Path(raw_root).expanduser(), True)

exact_manifest_artifacts = set()
for item in failed_functions:
    artifacts = item.get("record", {}).get("artifacts") or {}
    if not isinstance(artifacts, dict):
        continue
    for descriptor in artifacts.values():
        if isinstance(descriptor, dict) and descriptor.get("path"):
            exact_manifest_artifacts.add(
                (publish_dir / str(descriptor["path"])).resolve()
            )

candidates = []
seen = set()
for label, root_path, recursive in roots:
    iterator = root_path.rglob("*") if recursive else root_path.glob("*")
    for path in iterator:
        if not path.is_file():
            continue
        try:
            resolved = path.resolve()
            stat = path.stat()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        lower = str(path).lower()
        compact_lower = re.sub(r"[^a-z0-9]+", "", lower)
        suffix_ok = path.suffix.lower() in text_suffixes
        marker_hit = any(marker in lower for marker in debug_markers)
        token_hit = any(token in lower or token in compact_lower for token in tokens)
        fresh = (started_epoch - 3) <= stat.st_mtime <= (finished_epoch + 300)
        exact = resolved in exact_manifest_artifacts
        relevant = exact or token_hit or (marker_hit and (fresh or label == "publish"))
        if relevant and suffix_ok:
            candidates.append((
                0 if exact else 1 if token_hit else 2,
                -int(stat.st_mtime), label, root_path, path,
                exact, token_hit, marker_hit, fresh,
            ))

candidates.sort(key=lambda item: (item[0], item[1], str(item[4])))
artifact_index = []
for candidate in candidates[:max_files]:
    _, _, label, root_path, path, exact, token_hit, marker_hit, fresh = candidate
    try:
        size = path.stat().st_size
        relative = path.relative_to(root_path)
    except Exception:
        size = path.stat().st_size
        relative = Path(path.name)
    destination = report_dir / "pipeline_artifacts" / label / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    truncated = False
    if size <= max_file_bytes:
        shutil.copy2(path, destination)
    else:
        truncated = True
        destination = destination.with_name(destination.name + ".truncated.txt")
        head_size = max_file_bytes // 2
        tail_size = max_file_bytes - head_size
        with path.open("rb") as source, destination.open("wb") as target:
            target.write(source.read(head_size))
            target.write(b"\n\n--- PAL FAILED REPORT: MIDDLE TRUNCATED ---\n\n")
            source.seek(max(0, size - tail_size))
            target.write(source.read(tail_size))
    artifact_index.append({
        "source": str(path),
        "copied": str(destination.relative_to(report_dir)),
        "source_bytes": size,
        "copied_bytes": destination.stat().st_size,
        "source_sha256": sha256_file(path),
        "copied_sha256": sha256_file(destination),
        "truncated": truncated,
        "exact_manifest_artifact": exact,
        "failed_identity_match": token_hit,
        "debug_marker_match": marker_hit,
        "created_during_run": fresh,
    })

with (report_dir / "debug_artifact_index.tsv").open("wt", encoding="utf-8", newline="") as handle:
    writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
    keys = (
        "source", "copied", "source_bytes", "copied_bytes", "source_sha256",
        "copied_sha256", "truncated", "exact_manifest_artifact",
        "failed_identity_match", "debug_marker_match", "created_during_run",
    )
    writer.writerow(keys)
    for item in artifact_index:
        writer.writerow([item[key] for key in keys])
(report_dir / "debug_artifact_index.json").write_text(
    json.dumps(artifact_index, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
    encoding="utf-8",
)

excerpt_sources = [
    report_dir / "streams" / "pyghidra.stderr.log",
    report_dir / "streams" / "pipeline.full.transcript.log",
    report_dir / "streams" / "pyghidra.combined.log",
    report_dir / "streams" / "audit.stderr.log",
    report_dir / "streams" / "audit.combined.log",
]
patterns = re.compile(
    r"traceback|exception|error|failed|fatal|assert|palsgl|palemitter|"
    r"palphifolder|palcompute|typeerror|runtimeerror",
    re.IGNORECASE,
)
excerpt_parts = []
for source in excerpt_sources:
    if not source.is_file():
        continue
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    selected = set(range(max(0, len(lines) - 160), len(lines)))
    for line_index, line in enumerate(lines):
        if patterns.search(line):
            selected.update(range(max(0, line_index - 5), min(len(lines), line_index + 8)))
    excerpt_parts.append("===== %s =====" % source.name)
    excerpt_parts.extend(lines[line_index] for line_index in sorted(selected))
    excerpt_parts.append("")
(report_dir / "error_excerpt.txt").write_text(
    "\n".join(excerpt_parts) + "\n", encoding="utf-8"
)

report = {
    "report_schema": "pal_failed_specimen_report_v5_cwd_custody_tabloid",
    "specimen": specimen,
    "prefix": prefix,
    "binary": str(binary),
    "binary_sha256": binary_sha,
    "publish_directory": str(publish_dir),
    "manifest_source": str(manifest_source) if manifest_source.is_file() else None,
    "pyghidra_exit": pyghidra_exit,
    "audit_exit": audit_exit,
    "started_epoch": started_epoch,
    "finished_epoch": finished_epoch,
    "failed_function_records": manifest_failed_function_records,
    "report_failure_entries": len(failed_functions),
    "debug_artifacts_copied": len(artifact_index),
    "canonical_internal_pipeline_streams": {
        "count": len(internal_stream_index),
        "index_json": "internal_pipeline_streams.json",
        "index_tsv": "internal_pipeline_streams.tsv",
        "copy_policy": "unbounded_exact_hash_verified",
    },
    "pipeline_full_transcript": read_json(
        Path(pipeline_metadata_text)
    ),
    "debug_artifact_limits": {
        "max_file_bytes": max_file_bytes,
        "max_files": max_files,
    },
    "failed_functions": failed_json,
    "debug_artifacts": artifact_index,
}
(report_dir / "report.json").write_text(
    json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
    encoding="utf-8",
)

function_lines = []
for item in failed_functions:
    identity = item.get("qualified_name") or item.get("name") or item.get("function_id")
    entry = item.get("entry_hex") or item.get("entry") or "-"
    function_lines.append(
        "- `%s` at `%s`: **%s** — %s"
        % (
            identity, entry, item.get("error_type") or "Failure",
            str(item.get("error_message") or "").replace("\n", " "),
        )
    )
(report_dir / "REPORT.md").write_text(
    "# PAL failed specimen report\n\n"
    "Specimen: `%s`  \nBinary SHA-256: `%s`  \n"
    "PyGhidra exit: `%d`  \nAudit exit: `%d`\n\n"
    "## Failed functions\n\n%s\n\n"
    "## Captured evidence\n\n"
    "- authoritative stdout/stderr streams: `streams/`\n"
    "- outer PyGhidra pipeline stream: "
    "`streams/pipeline.full.transcript.log`\n"
    "- canonical internal PALBatchDecompiler streams: "
    "`internal_pipeline_streams/`\n"
    "- canonical stream inventory: "
    "`internal_pipeline_streams.tsv` and `.json`\n"
    "- framed pipeline stream/order record: "
    "`streams/pipeline.full.transcript.framed.log`\n"
    "- transcript command/timing/hash metadata: "
    "`streams/pipeline.full.transcript.meta.json`\n"
    "- launch-root receipt: `authorities/launch.custody.json`\n"
    "- publish-root diagnostic: "
    "`authorities/publish.custody.diagnostic.json`\n"
    "- manifest/audit/environment/tree authorities: `authorities/`\n"
    "- textual pipeline/debug artifacts: `pipeline_artifacts/`\n"
    "- artifact provenance and hashes: `debug_artifact_index.tsv`\n"
    "- bounded failure context: `error_excerpt.txt`\n"
    % (specimen, binary_sha, pyghidra_exit, audit_exit, "\n".join(function_lines)),
    encoding="utf-8",
)

archive_path.parent.mkdir(parents=True, exist_ok=True)
temporary_archive = archive_path.with_name(archive_path.name + ".tmp")
if temporary_archive.exists():
    temporary_archive.unlink()
with tarfile.open(temporary_archive, "w:gz") as archive:
    archive.add(report_dir, arcname=report_dir.name, recursive=True)
os.replace(temporary_archive, archive_path)
archive_sha = sha256_file(archive_path)
(archive_path.with_name(archive_path.name + ".sha256")).write_text(
    "%s  %s\n" % (archive_sha, archive_path.name), encoding="utf-8"
)
print(
    "%d\t%d\t%s"
    % (
        manifest_failed_function_records,
        len(artifact_index) + len(internal_stream_index),
        archive_sha,
    )
)
FAILED_REPORT_PY
}

declare -a FAILED=()
total="${#BINARIES[@]}"

for index in "${!BINARIES[@]}"; do
    binary="${BINARIES[$index]}"
    specimen="$(basename -- "$binary")"
    current=$((index + 1))
    binary_sha="$(sha256sum "$binary" | awk '{print $1}')"
    safe_name="$(safe_slug "$specimen")"
    prefix="$(printf '%03d_%s_%s' "$current" "$safe_name" "${binary_sha:0:12}")"

    specimen_stream_dir="$PER_SPECIMEN_DIR/$prefix"
    mkdir -p -- "$specimen_stream_dir"
    pyghidra_log="$specimen_stream_dir/pyghidra.combined.log"
    pyghidra_stdout="$specimen_stream_dir/pyghidra.stdout.log"
    pyghidra_stderr="$specimen_stream_dir/pyghidra.stderr.log"
    pipeline_transcript="$specimen_stream_dir/pipeline.full.transcript.log"
    pipeline_framed="$specimen_stream_dir/pipeline.full.transcript.framed.log"
    pipeline_metadata="$specimen_stream_dir/pipeline.full.transcript.meta.json"
    launch_receipt="$specimen_stream_dir/launch.custody.json"
    publish_diagnostic="$specimen_stream_dir/publish.custody.diagnostic.json"
    audit_log="$specimen_stream_dir/audit.combined.log"
    audit_stdout="$specimen_stream_dir/audit.stdout.log"
    audit_stderr="$specimen_stream_dir/audit.stderr.log"
    audit_json="$AUDIT_DIR/${prefix}.audit.json"
    tree_report="$TREE_DIR/${prefix}.tree.tsv"
    manifest_snapshot="$MANIFEST_DIR/${prefix}.PAL_function_manifest.json"
    failed_report_dir="$FAILED_REPORTS_DIR/${prefix}.failed"
    failed_report_archive="$FAILED_ARCHIVES_DIR/${prefix}.failed.tar.gz"

    publish_dir="$PAL_ROOT/project/$specimen"
    manifest_path="$publish_dir/PAL_function_manifest.json"

    # Protect the destructive cleanup boundary.
    case "$publish_dir" in
        "$PAL_ROOT/project/"?*) ;;
        *) die "unsafe publish cleanup path: $publish_dir" ;;
    esac

    printf '\nPROJECT [%d/%d] START %s\n' "$current" "$total" "$specimen"
    if [[ "$PAL_CONSOLE_MODE" == "full" ]]; then
        printf 'Binary:       %s\n' "$binary"
        printf 'SHA256:       %s\n' "$binary_sha"
        printf 'Publish tree: %s\n' "$publish_dir"
        printf 'Combined log: %s\n' "$pyghidra_log"
        printf 'Stdout log:   %s\n' "$pyghidra_stdout"
        printf 'Stderr log:   %s\n' "$pyghidra_stderr"
        printf 'Full pipeline transcript: %s\n' "$pipeline_transcript"
        printf 'Framed pipeline transcript: %s\n' "$pipeline_framed"
        printf 'Pipeline transcript metadata: %s\n' "$pipeline_metadata"
        printf 'Launch custody receipt: %s\n' "$launch_receipt"
        printf 'Publish custody diagnostic: %s\n' "$publish_diagnostic"
        printf 'Removing stale publish tree: %s\n' "$publish_dir"
    fi
    rm -rf -- "$publish_dir"

    started_utc="$(iso_utc)"
    started_epoch="$(date +%s)"

    python3 -         "$launch_receipt"         "$CALLER_PWD"         "$PAL_ROOT"         "$PAL_BATCH_CWD"         "$binary"         "$CRYSTAL_BATCH"         "$publish_dir"         "${PYTHONPATH:-}" <<'PAL_LAUNCH_RECEIPT_PY'
import json
import os
import sys
from pathlib import Path

(
    receipt_path,
    caller_pwd,
    pal_root,
    child_cwd,
    binary,
    batch_script,
    publish_dir,
    pythonpath,
) = sys.argv[1:]

payload = {
    "schema": "pal_matrix_launch_custody_v1",
    "supervisor_pid": os.getpid(),
    "caller_pwd": caller_pwd,
    "matrix_process_pwd": os.getcwd(),
    "pal_root": pal_root,
    "child_cwd": child_cwd,
    "cwd_authority_agrees": (
        Path(os.getcwd()).resolve() == Path(pal_root).resolve()
        and Path(child_cwd).resolve() == Path(pal_root).resolve()
    ),
    "binary": binary,
    "batch_script": batch_script,
    "expected_publish_dir": publish_dir,
    "pythonpath": pythonpath,
    "pal_root_export": os.environ.get("PAL_ROOT"),
}
Path(receipt_path).write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
if not payload["cwd_authority_agrees"]:
    raise SystemExit("PAL launch cwd custody disagreement")
PAL_LAUNCH_RECEIPT_PY

    cmd=(
        "$PYGHIDRA"
        --project-name "$GHIDRA_PROJECT_NAME"
        --project-path "$GHIDRA_PROJECT_PATH"
        "$binary"
        "$CRYSTAL_BATCH"
    )

    if (( PAL_TIMEOUT_SECONDS > 0 )); then
        run_cmd=(timeout --signal=TERM --kill-after=30 "$PAL_TIMEOUT_SECONDS" "${cmd[@]}")
    else
        run_cmd=("${cmd[@]}")
    fi

    if [[ "$PAL_CONSOLE_MODE" == "full" ]]; then
        quote_cmd "${run_cmd[@]}" | tee "$pyghidra_log"
    else
        quote_cmd "${run_cmd[@]}" > "$pyghidra_log"
    fi

    set +e
    run_pipeline_archived_streams \
        "$pyghidra_stdout" \
        "$pyghidra_stderr" \
        "$pyghidra_log" \
        "$pipeline_transcript" \
        "$pipeline_framed" \
        "$pipeline_metadata" \
        "${run_cmd[@]}"
    pyghidra_exit=$?
    set -e

    if [[ "$PAL_CONSOLE_MODE" == "full" ]]; then
        printf 'PYGHIDRA EXIT: %d\n' "$pyghidra_exit" \
            | tee -a "$pyghidra_log"
        diagnose_publish_custody \
            "$publish_diagnostic" \
            "$specimen" \
            "$publish_dir" \
            "$pyghidra_exit" \
            "$pipeline_transcript" \
            "$pipeline_metadata" \
            "$launch_receipt" \
            | tee -a "$pyghidra_log"
    else
        printf 'PYGHIDRA EXIT: %d\n' "$pyghidra_exit" \
            >> "$pyghidra_log"
        diagnose_publish_custody \
            "$publish_diagnostic" \
            "$specimen" \
            "$publish_dir" \
            "$pyghidra_exit" \
            "$pipeline_transcript" \
            "$pipeline_metadata" \
            "$launch_receipt" \
            >> "$pyghidra_log"
    fi

    set +e
    run_captured_streams \
        "$audit_stdout" \
        "$audit_stderr" \
        "$audit_log" \
        audit_publish_bundle \
        "$publish_dir" \
        "$specimen" \
        "$binary_sha" \
        "$audit_json"
    audit_exit=$?
    set -e

    {
        printf '\n===== AUDIT TRANSCRIPT =====\n'
        cat -- "$audit_log"
    } >> "$pyghidra_log"

    if [[ -d "$publish_dir" ]]; then
        {
            printf 'relative_path\tbytes\tsha256\tmodified_utc\n'
            while IFS= read -r -d '' published_file; do
                rel="${published_file#"$publish_dir"/}"
                pbytes="$(stat -c '%s' "$published_file")"
                psha="$(sha256sum "$published_file" | awk '{print $1}')"
                pmodified="$(date -u -d "@$(stat -c '%Y' "$published_file")" '+%Y-%m-%dT%H:%M:%SZ')"
                printf '%s\t%s\t%s\t%s\n' \
                    "$rel" "$pbytes" "$psha" "$pmodified"
            done < <(
                find "$publish_dir" -type f -print0 | LC_ALL=C sort -z
            )
        } > "$tree_report"
    else
        printf 'relative_path\tbytes\tsha256\tmodified_utc\n' > "$tree_report"
    fi

    if [[ -f "$manifest_path" ]]; then
        cp -- "$manifest_path" "$manifest_snapshot"
    fi

    mapfile -t audit_fields < <(read_audit_fields "$audit_json")
    manifest_status="${audit_fields[0]:-unknown}"
    discovered="${audit_fields[1]:-0}"
    enumerated="${audit_fields[2]:-0}"
    decompiled="${audit_fields[3]:-0}"
    failed_count="${audit_fields[4]:-0}"
    skipped_external="${audit_fields[5]:-0}"
    publish_bytes="${audit_fields[6]:-0}"
    publish_files="${audit_fields[7]:-0}"
    diagnostic="${audit_fields[8]:-}"

    finished_epoch="$(date +%s)"
    finished_utc="$(iso_utc)"
    elapsed_seconds=$((finished_epoch - started_epoch))
    failed_function_records=0
    debug_artifacts_copied=0

    if [[ "$pyghidra_exit" -eq 0 && "$audit_exit" -eq 0 ]]; then
        status="PASS"
        failed_report_dir=""
        failed_report_archive=""
        printf 'PROJECT [%d/%d] DONE PASS %s | functions=%s failed=%s elapsed=%ss\n' \
            "$current" "$total" "$specimen" \
            "$decompiled" "$failed_count" "$elapsed_seconds"
    else
        status="FAIL"
        FAILED+=("$specimen")

        set +e
        report_result="$(
            build_failed_report \
                "$specimen" \
                "$prefix" \
                "$binary" \
                "$binary_sha" \
                "$publish_dir" \
                "$manifest_path" \
                "$pyghidra_stdout" \
                "$pyghidra_stderr" \
                "$pyghidra_log" \
                "$pipeline_transcript" \
                "$pipeline_framed" \
                "$pipeline_metadata" \
                "$launch_receipt" \
                "$publish_diagnostic" \
                "$audit_stdout" \
                "$audit_stderr" \
                "$audit_log" \
                "$audit_json" \
                "$tree_report" \
                "$manifest_snapshot" \
                "$ENV_REPORT" \
                "$started_epoch" \
                "$finished_epoch" \
                "$pyghidra_exit" \
                "$audit_exit" \
                "$failed_report_dir" \
                "$failed_report_archive"
        )"
        report_exit=$?
        set -e

        if [[ "$report_exit" -eq 0 ]]; then
            IFS=$'\t' read -r \
                failed_function_records \
                debug_artifacts_copied \
                failed_archive_sha256 <<< "$report_result"
            if [[ "$PAL_CONSOLE_MODE" == "full" ]]; then
                printf 'FAILED REPORT: %s\n' "$failed_report_dir"
                printf 'FAILED ARCHIVE: %s\n' "$failed_report_archive"
                printf 'FAILED ARCHIVE SHA256: %s\n' "$failed_archive_sha256"
            fi
        else
            failed_report_dir="REPORT_GENERATION_FAILED"
            failed_report_archive="REPORT_GENERATION_FAILED"
            diagnostic="${diagnostic}; failed-report generation exit=${report_exit}"
            printf 'FAILED REPORT GENERATION ERROR: %s\n' "$specimen" >&2
        fi

        printf '%s\tpyghidra_exit=%d\taudit_exit=%d\tlog=%s\tpipeline_transcript=%s\tfailed_report=%s\tarchive=%s\n' \
            "$specimen" \
            "$pyghidra_exit" \
            "$audit_exit" \
            "$pyghidra_log" \
            "$pipeline_transcript" \
            "$failed_report_dir" \
            "$failed_report_archive" \
            >> "$FAILURES_TXT"
        printf 'PROJECT [%d/%d] DONE FAIL %s | functions=%s failed=%s pyghidra=%d audit=%d elapsed=%ss\n' \
            "$current" "$total" "$specimen" \
            "$decompiled" "$failed_count" \
            "$pyghidra_exit" "$audit_exit" "$elapsed_seconds" >&2
        if [[ "$report_exit" -eq 0 && "$PAL_CONSOLE_MODE" != "silent" ]]; then
            printf '  REPORT: %s\n' "$failed_report_dir" >&2
            printf '  ARCHIVE: %s\n' "$failed_report_archive" >&2
        fi
    fi

    diagnostic="${diagnostic//$'\t'/ }"
    diagnostic="${diagnostic//$'\r'/ }"
    diagnostic="${diagnostic//$'\n'/ }"

    printf '%d\t%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$current" \
        "$specimen" \
        "$status" \
        "$pyghidra_exit" \
        "$audit_exit" \
        "$elapsed_seconds" \
        "$manifest_status" \
        "$discovered" \
        "$enumerated" \
        "$decompiled" \
        "$failed_count" \
        "$skipped_external" \
        "$publish_bytes" \
        "$publish_files" \
        "$binary_sha" \
        "$binary" \
        "$publish_dir" \
        "$pyghidra_log" \
        "$pyghidra_stdout" \
        "$pyghidra_stderr" \
        "$pipeline_transcript" \
        "$pipeline_framed" \
        "$pipeline_metadata" \
        "$audit_stdout" \
        "$audit_stderr" \
        "$audit_json" \
        "$tree_report" \
        "$failed_report_dir" \
        "$failed_report_archive" \
        "$failed_function_records" \
        "$debug_artifacts_copied" \
        "$started_utc" \
        "$finished_utc" \
        "$diagnostic" \
        >> "$SUMMARY_TSV"

    if (( ABORTED )); then
        printf 'Run aborted after specimen %s.\n' "$specimen" >&2
        break
    fi
done

python3 - "$SUMMARY_TSV" "$SUMMARY_JSON" "$RUN_DIR" "$GHIDRA_PROJECT_PATH" "$GHIDRA_PROJECT_NAME" "$ABORTED" <<'PY'
import csv
import json
import sys
from pathlib import Path

summary_tsv = Path(sys.argv[1])
summary_json = Path(sys.argv[2])
run_dir = sys.argv[3]
project_path = sys.argv[4]
project_name = sys.argv[5]
aborted = bool(int(sys.argv[6]))


def install_csv_field_limit():
    """Raise csv's C-long field ceiling without assuming platform width."""
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return limit
        except OverflowError:
            limit //= 10


csv_field_limit = install_csv_field_limit()

with summary_tsv.open("rt", encoding="utf-8", newline="") as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))

payload = {
    "report_schema": (
        "pal_all_exe_import_publish_matrix_"
        "v6_progress_console_large_field_safe"
    ),
    "csv_field_size_limit": csv_field_limit,
    "run_directory": run_dir,
    "ghidra_project_path": project_path,
    "ghidra_project_name": project_name,
    "aborted": aborted,
    "counts": {
        "attempted": len(rows),
        "passed": sum(row.get("status") == "PASS" for row in rows),
        "failed": sum(row.get("status") == "FAIL" for row in rows),
    },
    "specimens": rows,
}

summary_json.write_text(
    json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
    encoding="utf-8",
)
PY

attempted="$(awk 'NR > 1 {count++} END {print count+0}' "$SUMMARY_TSV")"
passed="$(awk -F '\t' 'NR > 1 && $3 == "PASS" {count++} END {print count+0}' "$SUMMARY_TSV")"
failed_total="$(awk -F '\t' 'NR > 1 && $3 == "FAIL" {count++} END {print count+0}' "$SUMMARY_TSV")"

printf '\n======================================================================\n'
printf 'PAL ALL-EXE MATRIX SUMMARY\n'
printf '======================================================================\n'

if [[ "$PAL_CONSOLE_MODE" == "full" ]]; then
    if command -v column >/dev/null 2>&1; then
        cut -f 1-14 "$SUMMARY_TSV" | column -t -s $'\t'
    else
        cat "$SUMMARY_TSV"
    fi
fi

printf '\nAttempted:      %s\n' "$attempted"
printf 'Passed:         %s\n' "$passed"
printf 'Failed:         %s\n' "$failed_total"
printf 'Aborted:        %s\n' "$ABORTED"
printf 'Ghidra project: %s/%s\n' "$GHIDRA_PROJECT_PATH" "$GHIDRA_PROJECT_NAME"
printf 'Master log:     %s\n' "$MASTER_LOG"
printf 'Inventory:      %s\n' "$INVENTORY_TSV"
printf 'TSV summary:    %s\n' "$SUMMARY_TSV"
printf 'JSON summary:   %s\n' "$SUMMARY_JSON"
printf 'Failures:       %s\n' "$FAILURES_TXT"
printf 'Failed reports: %s\n' "$FAILED_REPORTS_DIR"
printf 'Failed archives: %s\n' "$FAILED_ARCHIVES_DIR"
printf 'Run directory:  %s\n' "$RUN_DIR"

if (( ABORTED )); then
    final_status="ABORTED"
    exit_code=130
elif (( failed_total > 0 )); then
    final_status="FAIL"
    exit_code=1
elif (( attempted != total )); then
    final_status="INCOMPLETE"
    exit_code=1
else
    final_status="PASS"
    exit_code=0
fi

{
    printf 'status=%s\n' "$final_status"
    printf 'exit_code=%d\n' "$exit_code"
    printf 'attempted=%d\n' "$attempted"
    printf 'passed=%d\n' "$passed"
    printf 'failed=%d\n' "$failed_total"
    printf 'discovered=%d\n' "$total"
    printf 'finished_utc=%s\n' "$(iso_utc)"
} > "$RUN_STATUS"

# Update a stable pointer only after all reports are durable.
latest_tmp="$LOG_MATRIX_ROOT/.latest.$$"
rm -f -- "$latest_tmp"
ln -s -- "$(basename -- "$RUN_DIR")" "$latest_tmp"
mv -Tf -- "$latest_tmp" "$LOG_MATRIX_ROOT/latest"

if [[ "$exit_code" -eq 0 ]]; then
    printf 'PASS: all discovered executables imported and published.\n'
else
    printf '%s: inspect %s and per-specimen logs.\n' \
        "$final_status" "$SUMMARY_TSV" >&2
    if (( failed_total > 0 )); then
        printf 'Failure archives: %s\n' "$FAILED_ARCHIVES_DIR" >&2
    fi
fi

if [[ "$PAL_TABLOID" == "1" ]]; then
    if [[ -x "$PAL_TABLOID_VIEWER" ]]; then
        printf '\nRendering PAL LOG TABLOID...\n'
        "$PAL_TABLOID_VIEWER" "$RUN_DIR" ||             printf 'TABLOID WARNING: viewer failed: %s\n'                 "$PAL_TABLOID_VIEWER" >&2
    else
        printf 'TABLOID WARNING: viewer is not executable: %s\n'             "$PAL_TABLOID_VIEWER" >&2
    fi
fi

exit "$exit_code"
