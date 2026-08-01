#!/usr/bin/env bash
# build_matrix_debug_report.sh
#
# Build one clean PAL bug-matrix row per failed-function record, then converge
# those records at three separate custody levels:
#
#   report_sha256       whole REPORT.md provenance only
#   occurrence_signature
#                       exact normalized function/site/error occurrence
#   family_signature    normalized runtime bug family
#   affected_module_errors
#                       keyed module:error diagnostics aggregated without
#                       changing failure/diagnostic cardinality
#
# Default source preference:
#   1. /PAL/pyghidra-PAL/PAL/log_matrix/latest
#   2. /PAL/log_matrix/latest
#
# Output:
#   Bug_Matrix_report_<YYYY-MM-DD_HH-MM-SS>.md
#
# Usage:
#   ./build_matrix_debug_report.sh
#   ./build_matrix_debug_report.sh /custom/log_matrix/latest
#   ./build_matrix_debug_report.sh /custom/log_matrix/latest /custom/output_dir
#
# PAL_REPORT_DATETIME may be set to a filename-safe value for deterministic
# regression runs. Normal operation should leave it unset.

set -Eeuo pipefail
IFS=$'\n\t'

readonly BUILD="v3_affected_module_error_aggregation"
readonly PRIMARY_DEFAULT="/PAL/pyghidra-PAL/PAL/log_matrix/latest"
readonly FALLBACK_DEFAULT="/PAL/log_matrix/latest"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

choose_latest_root() {
    if [[ $# -ge 1 && -n "${1:-}" ]]; then
        printf '%s\n' "$1"
        return
    fi

    if [[ -d "$PRIMARY_DEFAULT" ]]; then
        printf '%s\n' "$PRIMARY_DEFAULT"
    elif [[ -d "$FALLBACK_DEFAULT" ]]; then
        printf '%s\n' "$FALLBACK_DEFAULT"
    else
        # Preserve the preferred location in the final diagnostic.
        printf '%s\n' "$PRIMARY_DEFAULT"
    fi
}

command -v python3 >/dev/null 2>&1 || die "python3 is required"

LATEST_ROOT="$(choose_latest_root "${1:-}")"
FAILED_ROOT="${LATEST_ROOT%/}/failed_reports"
OUTPUT_DIR="${2:-$LATEST_ROOT}"
REPORT_DATETIME="${PAL_REPORT_DATETIME:-$(date '+%Y-%m-%d_%H-%M-%S')}"

[[ -d "$LATEST_ROOT" ]] || die "latest matrix directory not found: $LATEST_ROOT"
[[ -d "$FAILED_ROOT" ]] || die "failed_reports directory not found: $FAILED_ROOT"
[[ "$REPORT_DATETIME" =~ ^[0-9A-Za-z._+-]+$ ]] \
    || die "PAL_REPORT_DATETIME must be filename-safe: $REPORT_DATETIME"

mkdir -p "$OUTPUT_DIR"
OUTPUT_MD="${OUTPUT_DIR%/}/Bug_Matrix_report_${REPORT_DATETIME}.md"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pal-bug-matrix.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
TMP_OUTPUT="$TMP_DIR/$(basename "$OUTPUT_MD").partial"

python3 - "$LATEST_ROOT" "$FAILED_ROOT" "$TMP_OUTPUT" "$OUTPUT_MD" "$BUILD" <<'PY'
from __future__ import annotations

import ast
import hashlib
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


latest_root = Path(sys.argv[1]).resolve()
failed_root = Path(sys.argv[2]).resolve()
tmp_output = Path(sys.argv[3])
final_output = Path(sys.argv[4]).resolve()
build = sys.argv[5]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def one_line(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("\r", " ")).strip()


def md_cell(value: object) -> str:
    text = one_line(str(value))
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "\\`")
    )


def code(value: object) -> str:
    # Hashes, identifiers, paths and names in this report never contain a
    # backtick. Keep one helper so table construction remains legible.
    return f"`{value}`"


def metadata_value(text: str, label: str) -> str:
    match = re.search(
        rf"^{re.escape(label)}:[ \t]*(?:`([^`\n]+)`|([^\n]+))",
        text,
        flags=re.MULTILINE | re.IGNORECASE,
    )
    if not match:
        return ""
    return one_line(match.group(1) or match.group(2) or "")


def find_reports(root: Path) -> tuple[list[Path], str]:
    exact = sorted(
        (p for p in root.rglob("REPORT.md") if p.is_file()),
        key=lambda p: p.as_posix(),
    )
    if exact:
        return exact, "REPORT.md"

    compatibility_names = ("REPORT", "READ.me", "README.md", "README")
    fallback = sorted(
        (
            p
            for name in compatibility_names
            for p in root.rglob(name)
            if p.is_file()
        ),
        key=lambda p: p.as_posix(),
    )
    return fallback, ", ".join(compatibility_names)


def failed_function_bullets(text: str) -> list[str]:
    section = re.search(
        r"^##[ \t]+Failed functions[ \t]*$\n(?P<body>.*?)(?=^##[ \t]+|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    if not section:
        return []

    bullets: list[str] = []
    current: list[str] = []
    for line in section.group("body").splitlines():
        if re.match(r"^[ \t]*-[ \t]+", line):
            if current:
                bullets.append(one_line(" ".join(current)))
            current = [re.sub(r"^[ \t]*-[ \t]+", "", line, count=1)]
        elif current and line.strip():
            current.append(line.strip())
    if current:
        bullets.append(one_line(" ".join(current)))
    return bullets


FAILURE_RE = re.compile(
    r"^`(?P<function>[^`]+)`[ \t]+at[ \t]+`(?P<address>[^`]+)`:"
    r"[ \t]*\*\*(?P<exception>[^*]+)\*\*[ \t]*(?:—|--|-)[ \t]*"
    r"(?P<message>.*)$"
)


def parse_list_literal(message: str, key: str) -> tuple[str, ...]:
    match = re.search(
        rf"['\"]{re.escape(key)}['\"]\s*:\s*(\[[^\]]*\])",
        message,
    )
    if not match:
        return ()
    try:
        value = ast.literal_eval(match.group(1))
    except (SyntaxError, ValueError):
        return ()
    if not isinstance(value, list):
        return ()
    return tuple(sorted(one_line(str(item)) for item in value))


def normalized_reason_values(message: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                one_line(value)
                for value in re.findall(
                    r"['\"]reason['\"]\s*:\s*['\"]([^'\"]+)['\"]",
                    message,
                )
            }
        )
    )


def diagnostic_kinds(message: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                one_line(value)
                for value in re.findall(
                    r"['\"]kind['\"]\s*:\s*['\"]([^'\"]+)['\"]",
                    message,
                )
            }
        )
    )


def component_name(message: str) -> str:
    match = re.search(r"\b(PAL[A-Za-z0-9_]+)\b", message)
    return match.group(1) if match else "Unknown component"


MODULE_LABELS = {
    "palemitter": "emitter",
    "palphifolder": "phifolder",
    "palsgl": "sgl",
    "palsgldecomp": "sgl",
    "palsemanticgraphbuilder": "semantic_graph",
    "palsemanticgraph": "semantic_graph",
    "palcfg": "cfg",
    "functioncfg": "cfg",
    "edgetruth": "edge_truth",
    "palcompute": "compute",
    "palexecinterface": "exec_interface",
    "palbatchdecompiler": "pipeline",
}

ERROR_SCALAR_KEYS = (
    "kind",
    "reason",
    "gate",
    "failed_gate",
    "failure_kind",
    "error_kind",
    "non_render_reason",
)
ERROR_LIST_KEYS = (
    "failed_gates",
    "missing_gates",
    "rejected_gates",
)


def module_label(value: str) -> str:
    compact = re.sub(r"[^a-z0-9]+", "", str(value).lower())
    if compact in MODULE_LABELS:
        return MODULE_LABELS[compact]
    if compact.startswith("palemitter"):
        return "emitter"
    if compact.startswith("palphifolder"):
        return "phifolder"
    if compact.startswith("palsgl"):
        return "sgl"
    if "semanticgraph" in compact:
        return "semantic_graph"
    if compact in {"cfg", "functioncfg", "palcfg"}:
        return "cfg"
    return "unknown"


def module_for_error_key(
    message: str,
    key_value: str,
    offset: int,
    default_component: str,
) -> str:
    lowered = key_value.lower().lstrip("_")
    explicit_prefixes = (
        (("emitter_", "mars_phi_execution_", "holy_ghost_"), "emitter"),
        (("phi_", "phifolder_", "last_emperor_", "vanquish_emperor_"), "phifolder"),
        (("sgl_", "state_flow_", "condition_custody_"), "sgl"),
        (("semantic_graph_", "semanticgraph_"), "semantic_graph"),
        (("cfg_", "function_cfg_"), "cfg"),
        (("edge_truth_", "edgetruth_"), "edge_truth"),
        (("compute_", "palcompute_"), "compute"),
        (("abi_",), "abi"),
    )
    for prefixes, label in explicit_prefixes:
        if lowered.startswith(prefixes):
            return label
    if "holy_ghost" in lowered:
        return "emitter"
    if "phifolder" in lowered:
        return "phifolder"
    if "palsgl" in lowered:
        return "sgl"

    # Nested pipeline receipts often carry their own PAL component nearby.
    # Use only the closest preceding explicit component marker; never infer
    # module ownership from specimen/function names.
    preceding = message[max(0, offset - 320):offset]
    matches = list(re.finditer(r"\b(PAL[A-Za-z0-9_]+|FunctionCFG|EdgeTruth)\b", preceding))
    if matches:
        local = module_label(matches[-1].group(1))
        if local != "unknown":
            return local

    default = module_label(default_component)
    return default if default != "unknown" else "pipeline"


def keyed_error_values(message: str) -> list[tuple[str, int]]:
    values: list[tuple[str, int]] = []
    for key in ERROR_SCALAR_KEYS:
        pattern = re.compile(
            rf"['\"]{re.escape(key)}['\"]\s*:\s*['\"]([^'\"]+)['\"]",
            flags=re.IGNORECASE,
        )
        for match in pattern.finditer(message):
            value = one_line(match.group(1))
            if value:
                values.append((value, match.start()))

    for key in ERROR_LIST_KEYS:
        pattern = re.compile(
            rf"['\"]{re.escape(key)}['\"]\s*:\s*(\[[^\]]*\])",
            flags=re.IGNORECASE,
        )
        for match in pattern.finditer(message):
            try:
                parsed = ast.literal_eval(match.group(1))
            except (SyntaxError, ValueError):
                continue
            if not isinstance(parsed, list):
                continue
            for item in parsed:
                value = one_line(str(item))
                if value:
                    values.append((value, match.start()))
    return values


def affected_module_errors(message: str, default_component: str) -> tuple[str, ...]:
    collected = set()
    for value, offset in keyed_error_values(message):
        # Keep keyed values verbatim apart from whitespace collapse. This is
        # an evidence inventory, not a classifier and not a family counter.
        module = module_for_error_key(
            message,
            value,
            offset,
            default_component,
        )
        collected.add(f"{module}: {value}")
    return tuple(sorted(collected, key=lambda item: (item.split(":", 1)[0], item)))


def aggregate_module_errors(records: Iterable["FailureRecord"]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value
                for record in records
                for value in record.affected_module_errors
            },
            key=lambda item: (item.split(":", 1)[0], item),
        )
    )


def module_error_cell(values: Iterable[str]) -> str:
    items = list(values or [])
    if not items:
        return "—"
    return "<br>".join(code(md_cell(value)) for value in items)


@dataclass(frozen=True)
class Family:
    family_id: str
    label: str
    component: str
    target: str
    priority: int
    family_material: str

    @property
    def signature(self) -> str:
        return sha256_text(self.family_material)


def generic_family_material(
    component: str,
    exception: str,
    message: str,
    kinds: tuple[str, ...],
    reasons: tuple[str, ...],
    failed_gates: tuple[str, ...],
) -> str:
    normalized = message
    normalized = re.sub(r"0x[0-9a-fA-F]+", "<addr>", normalized)
    normalized = re.sub(r"\bv_\d+\b", "<sid>", normalized)
    normalized = re.sub(r"\b[0-9a-fA-F]{32,64}\b", "<hash>", normalized)
    normalized = re.sub(r"\b\d+\b", "<n>", normalized)
    return "|".join(
        (
            component,
            one_line(exception),
            ",".join(kinds),
            ",".join(reasons),
            ",".join(failed_gates),
            one_line(normalized),
        )
    )


def classify_family(exception: str, message: str) -> Family:
    lowered = message.lower()
    kinds = diagnostic_kinds(message)
    reasons = normalized_reason_values(message)
    failed_gates = parse_list_literal(message, "failed_gates")
    component = component_name(message)

    if (
        "direct_join_matched_token_not_rendered_v50" in kinds
        or "missing canonical direct-join phi transitions" in lowered
    ):
        return Family(
            "FAM-DJ-DISPOSITION",
            "Emitter direct-join disposition",
            "PALemitter",
            "PALemitter.py",
            1,
            "PALemitter|direct_join_matched_token_not_rendered|"
            "matched token has no exclusive terminal disposition",
        )

    if (
        "last_emperor_cyclic_state_family_v35" in kinds
        or "first_rollout_requires_acyclic_state_epochs" in reasons
    ):
        return Family(
            "FAM-PHI-CYCLIC-EPOCH",
            "PHIfolder cyclic state epochs",
            "PALPHIfolder",
            "PALPHIfolder.py",
            3,
            "PALPHIfolder|last_emperor_cyclic_state_family|"
            "first_rollout_requires_acyclic_state_epochs",
        )

    if (
        "owner_definitely_assigned" in failed_gates
        or "no_incoming_transition_records" in reasons
        or "carried-state owner custody failed" in lowered
    ):
        return Family(
            "FAM-PHI-DEFINITION-AUTHORITY",
            "PHIfolder definition authority",
            "PALPHIfolder",
            "PALPHIfolder.py",
            2,
            "PALPHIfolder|last_emperor_family_audit|"
            "owner_definitely_assigned|definition authority",
        )

    if "condition custody audit failed" in lowered:
        return Family(
            "FAM-SGL-CONDITION-CUSTODY",
            "SGL condition custody",
            "PALSGL",
            "PALSGLdecomp.py / EdgeTruth producer",
            4,
            "PALSGL|condition_custody_audit_failed|"
            "condition/control ownership",
        )

    material = generic_family_material(
        component,
        exception,
        message,
        kinds,
        reasons,
        failed_gates,
    )
    digest = sha256_text(material)[:10].upper()
    safe_component = re.sub(r"[^A-Z0-9]+", "-", component.upper()).strip("-")
    return Family(
        f"FAM-{safe_component or 'UNKNOWN'}-{digest}",
        f"{component} unclassified family",
        component,
        f"{component} owner (manual resolution)",
        90,
        material,
    )


@dataclass
class ReportRecord:
    path: Path
    relative_path: str
    slot_id: str
    specimen: str
    binary_sha256: str
    report_sha256: str
    text: str
    failure_count: int = 0

    @property
    def binary_key(self) -> str:
        if re.fullmatch(r"[0-9a-fA-F]{64}", self.binary_sha256):
            return self.binary_sha256.lower()
        # Missing binary custody must never collapse unrelated reports.
        return f"missing:{self.report_sha256}"


@dataclass
class FailureRecord:
    report: ReportRecord
    function: str
    address: str
    exception: str
    message: str
    raw_bullet: str
    family: Family
    diagnostic_count: int
    affected_module_errors: tuple[str, ...]

    @property
    def occurrence_material(self) -> str:
        return "|".join(
            (
                one_line(self.function),
                one_line(self.address).lower(),
                one_line(self.exception),
                one_line(self.message),
            )
        )

    @property
    def occurrence_signature(self) -> str:
        return sha256_text(self.occurrence_material)


report_paths, discovery_policy = find_reports(failed_root)
if not report_paths:
    raise SystemExit(
        f"ERROR: no failed-function reports found below {failed_root}; "
        "expected REPORT.md"
    )

reports: list[ReportRecord] = []
failures: list[FailureRecord] = []
parse_warnings: list[str] = []

for path in report_paths:
    payload = path.read_bytes()
    text = payload.decode("utf-8", errors="replace")
    relative_path = path.relative_to(latest_root).as_posix()
    report = ReportRecord(
        path=path,
        relative_path=relative_path,
        slot_id=path.parent.name,
        specimen=metadata_value(text, "Specimen") or path.parent.name,
        binary_sha256=metadata_value(text, "Binary SHA-256"),
        report_sha256=sha256_bytes(payload),
        text=text,
    )

    bullets = failed_function_bullets(text)
    if not bullets:
        parse_warnings.append(f"{relative_path}: no ## Failed functions bullets")

    for bullet in bullets:
        match = FAILURE_RE.match(bullet)
        if match:
            function = one_line(match.group("function"))
            address = one_line(match.group("address"))
            exception = one_line(match.group("exception"))
            message = one_line(match.group("message"))
        else:
            function = "Unparsed failure"
            address = "unknown"
            exception = "Unparsed"
            message = bullet
            parse_warnings.append(
                f"{relative_path}: failure bullet did not match canonical grammar"
            )

        family = classify_family(exception, message)
        module_errors = affected_module_errors(message, family.component)
        kind_count = len(
            re.findall(r"['\"]kind['\"]\s*:", message, flags=re.IGNORECASE)
        )
        failures.append(
            FailureRecord(
                report=report,
                function=function,
                address=address,
                exception=exception,
                message=message,
                raw_bullet=bullet,
                family=family,
                diagnostic_count=max(1, kind_count),
                affected_module_errors=module_errors,
            )
        )

    report.failure_count = len(bullets)
    reports.append(report)

if not failures:
    raise SystemExit(
        f"ERROR: {len(reports)} reports were found, but no failed-function "
        "records were parsed"
    )


def unique_binary_record_count(records: Iterable[FailureRecord]) -> int:
    return len(
        {
            (record.report.binary_key, record.occurrence_signature)
            for record in records
        }
    )


def unique_binary_diagnostic_count(records: Iterable[FailureRecord]) -> int:
    per_binary_occurrence: dict[tuple[str, str], int] = {}
    for record in records:
        key = (record.report.binary_key, record.occurrence_signature)
        per_binary_occurrence[key] = max(
            per_binary_occurrence.get(key, 0),
            record.diagnostic_count,
        )
    return sum(per_binary_occurrence.values())


by_occurrence: dict[str, list[FailureRecord]] = defaultdict(list)
by_family: dict[str, list[FailureRecord]] = defaultdict(list)
for record in failures:
    by_occurrence[record.occurrence_signature].append(record)
    by_family[record.family.signature].append(record)

family_rows = sorted(
    by_family.items(),
    key=lambda item: (
        min(record.family.priority for record in item[1]),
        item[1][0].family.family_id,
        item[0],
    ),
)
occurrence_rows = sorted(
    by_occurrence.items(),
    key=lambda item: (
        item[1][0].family.priority,
        item[1][0].function,
        item[1][0].address,
        item[0],
    ),
)
failure_rows = sorted(
    failures,
    key=lambda record: (
        record.family.priority,
        record.occurrence_signature,
        record.report.slot_id,
    ),
)

binary_groups: dict[str, list[ReportRecord]] = defaultdict(list)
for report in reports:
    binary_groups[report.binary_key].append(report)

raw_diagnostics = sum(record.diagnostic_count for record in failures)
unique_binary_records = unique_binary_record_count(failures)
unique_binary_diagnostics = unique_binary_diagnostic_count(failures)
all_affected_module_errors = aggregate_module_errors(failures)
known_binary_hashes = {
    report.binary_key
    for report in reports
    if not report.binary_key.startswith("missing:")
}
missing_binary_hashes = sum(
    1 for report in reports if report.binary_key.startswith("missing:")
)

now_local = datetime.now().astimezone()
now_utc = datetime.now(timezone.utc)

lines: list[str] = []


def emit(value: str = "") -> None:
    lines.append(value)


emit("# PAL Bug Matrix Report")
emit()
emit(
    "> Clean per-failure convergence view for the latest all-EXE matrix run. "
    "Whole-report hashes are provenance only; they are never used as bug "
    "signatures."
)
emit()
emit("## Convergence")
emit()
emit("```text")
emit(f"{len(failures)} raw failed-function records")
emit(f"→ {unique_binary_records} records after identical-binary de-duplication")
emit(f"→ {len(by_occurrence)} exact occurrence clusters")
emit(f"→ {len(by_family)} runtime bug families")
emit("```")
emit()
emit("| Measurement | Raw matrix | Unique-binary view |")
emit("|---|---:|---:|")
emit(f"| Named slots / report files | {len(reports)} | {len(binary_groups)} |")
emit(
    f"| Failed-function records | {len(failures)} | "
    f"{unique_binary_records} |"
)
emit(
    f"| Diagnostic instances | {raw_diagnostics} | "
    f"{unique_binary_diagnostics} |"
)
emit(f"| Exact occurrence clusters | {len(by_occurrence)} | {len(by_occurrence)} |")
emit(f"| Runtime families | {len(by_family)} | {len(by_family)} |")
emit(
    f"| Affected module/error keys | {len(all_affected_module_errors)} | "
    f"{len(all_affected_module_errors)} |"
)
emit()

emit("## Report metadata")
emit()
emit("| Field | Value |")
emit("|---|---|")
emit(f"| Reporter build | {code(build)} |")
emit(f"| Generated UTC | {code(now_utc.strftime('%Y-%m-%dT%H:%M:%SZ'))} |")
emit(
    f"| Generated local | "
    f"{code(now_local.strftime('%Y-%m-%d %H:%M:%S %z'))} |"
)
emit(f"| Latest matrix root | {code(md_cell(latest_root))} |")
emit(f"| Failed-report root | {code(md_cell(failed_root))} |")
emit(f"| Output | {code(md_cell(final_output))} |")
emit(f"| Report discovery | {code(discovery_policy)} |")
emit(f"| Report files parsed | {len(reports)} |")
emit(f"| Binary SHA-256 values present | {len(known_binary_hashes)} |")
emit(f"| Reports missing binary SHA-256 | {missing_binary_hashes} |")
emit()

emit("## Affected module-error aggregation")
emit()
emit(
    "These values come only from keyed error fields (`kind`, `reason`, "
    "`gate`, `failed_gates`, and their explicit variants). They are evidence "
    "dimensions and do not increase failed-function or diagnostic counts."
)
emit()
emit(
    "| Affected module error | Raw records | Unique binaries | "
    "Exact sites | Runtime families |"
)
emit("|---|---:|---:|---:|---:|")
module_error_records: dict[str, list[FailureRecord]] = defaultdict(list)
for record in failures:
    for value in record.affected_module_errors:
        module_error_records[value].append(record)
for value, records in sorted(module_error_records.items(), key=lambda item: item[0]):
    emit(
        f"| {code(md_cell(value))} | {len(records)} | "
        f"{len({record.report.binary_key for record in records})} | "
        f"{len({record.occurrence_signature for record in records})} | "
        f"{len({record.family.signature for record in records})} |"
    )
emit()

emit("## Runtime-family convergence")
emit()
emit(
    "| Priority | Family | Layer | Raw records | Unique binaries | "
    "Raw diagnostics | Unique-binary diagnostics | Exact sites | "
    "Affected module errors | Patch target | Family signature |"
)
emit("|---:|---|---|---:|---:|---:|---:|---:|---|---|---|")
for family_signature, records in family_rows:
    representative = records[0].family
    emit(
        "| {priority} | {family} | {layer} | {raw} | {unique} | "
        "{raw_diag} | {unique_diag} | {sites} | {module_errors} | "
        "{target} | {signature} |".format(
            priority=representative.priority,
            family=code(representative.family_id),
            layer=md_cell(representative.label),
            raw=len(records),
            unique=unique_binary_record_count(records),
            raw_diag=sum(record.diagnostic_count for record in records),
            unique_diag=unique_binary_diagnostic_count(records),
            sites=len({record.occurrence_signature for record in records}),
            module_errors=module_error_cell(aggregate_module_errors(records)),
            target=code(representative.target),
            signature=code(family_signature[:12]),
        )
    )
emit()

emit("## Exact occurrence clusters")
emit()
emit(
    "| # | Occurrence signature | Family | Function / site | Raw records | "
    "Unique binaries | Raw diagnostics | Unique-binary diagnostics | "
    "Affected module errors | Specimens |"
)
emit("|---:|---|---|---|---:|---:|---:|---:|---|---|")
for ordinal, (occurrence_signature, records) in enumerate(occurrence_rows, 1):
    representative = records[0]
    specimens = ", ".join(
        code(md_cell(value))
        for value in sorted({record.report.specimen for record in records})
    )
    emit(
        "| {ordinal} | {signature} | {family} | {function} at {address} | "
        "{raw} | {unique} | {raw_diag} | {unique_diag} | "
        "{module_errors} | {specimens} |".format(
            ordinal=ordinal,
            signature=code(occurrence_signature[:12]),
            family=code(representative.family.family_id),
            function=code(md_cell(representative.function)),
            address=code(md_cell(representative.address)),
            raw=len(records),
            unique=len({record.report.binary_key for record in records}),
            raw_diag=sum(record.diagnostic_count for record in records),
            unique_diag=unique_binary_diagnostic_count(records),
            module_errors=module_error_cell(aggregate_module_errors(records)),
            specimens=specimens,
        )
    )
emit()

emit("## Patch execution order")
emit()
emit(
    "The reporter orders known families by the established dependency boundary; "
    "unknown families are retained and placed after known targets for manual "
    "triage."
)
emit()
emit(
    "| Priority | Joined set | Current payoff | Affected module errors | "
    "Required target |"
)
emit("|---:|---|---|---|---|")
for family_signature, records in family_rows:
    representative = records[0].family
    emit(
        f"| {representative.priority} | {code(representative.family_id)} — "
        f"{md_cell(representative.label)} | {len(records)} raw / "
        f"{unique_binary_record_count(records)} unique-binary records | "
        f"{module_error_cell(aggregate_module_errors(records))} | "
        f"{code(representative.target)} |"
    )
emit()

emit("## Binary custody")
emit()
emit(
    "A repeated binary hash is shown as one unique binary, even when several "
    "named slots executed it. Slot names are not accepted as compiler/flag "
    "proof."
)
emit()
emit(
    "| Binary SHA-256 | Named slots | Failed-function records | "
    "Affected module errors | Specimens | Status |"
)
emit("|---|---:|---:|---|---|---|")
for binary_key, grouped_reports in sorted(
    binary_groups.items(),
    key=lambda item: (
        -len(item[1]),
        item[0],
    ),
):
    grouped_failures = [
        record for record in failures if record.report.binary_key == binary_key
    ]
    specimens = ", ".join(
        code(md_cell(value))
        for value in sorted({report.specimen for report in grouped_reports})
    )
    status = (
        "missing binary hash; isolated"
        if binary_key.startswith("missing:")
        else "duplicate slot binary"
        if len(grouped_reports) > 1
        else "single slot"
    )
    visible_hash = (
        "missing:" + binary_key.split(":", 1)[1][:12]
        if binary_key.startswith("missing:")
        else binary_key[:12]
    )
    emit(
        f"| {code(visible_hash)} | {len(grouped_reports)} | "
        f"{len(grouped_failures)} | "
        f"{module_error_cell(aggregate_module_errors(grouped_failures))} | "
        f"{specimens} | {status} |"
    )
emit()

emit("## Per-failure bug matrix")
emit()
emit(
    "| # | Slot | Specimen | Binary | Failed function | Exception | Family | "
    "Affected module errors | Occurrence | Family signature | "
    "Occurrence clones | Source report |"
)
emit("|---:|---|---|---|---|---|---|---|---|---|---:|---|")
for ordinal, record in enumerate(failure_rows, 1):
    emit(
        "| {ordinal} | {slot} | {specimen} | {binary} | {function} at "
        "{address} | {exception} | {family} | {module_errors} | "
        "{occurrence} | {family_signature} | {clones} | {source} |".format(
            ordinal=ordinal,
            slot=code(md_cell(record.report.slot_id)),
            specimen=code(md_cell(record.report.specimen)),
            binary=code(record.report.binary_key[:12]),
            function=code(md_cell(record.function)),
            address=code(md_cell(record.address)),
            exception=md_cell(record.exception),
            family=code(record.family.family_id),
            module_errors=module_error_cell(record.affected_module_errors),
            occurrence=code(record.occurrence_signature[:12]),
            family_signature=code(record.family.signature[:12]),
            clones=len(by_occurrence[record.occurrence_signature]),
            source=code(md_cell(record.report.relative_path)),
        )
    )
emit()

emit("## Exact occurrence evidence")
emit()
for ordinal, (occurrence_signature, records) in enumerate(occurrence_rows, 1):
    representative = records[0]
    emit()
    emit(
        f"### {ordinal:02d}. {code(occurrence_signature[:12])} — "
        f"{code(md_cell(representative.function))} at "
        f"{code(md_cell(representative.address))}"
    )
    emit()
    emit("| Field | Value |")
    emit("|---|---|")
    emit(f"| Family | {code(representative.family.family_id)} |")
    emit(f"| Family signature | {code(representative.family.signature[:12])} |")
    emit(
        f"| Affected module errors | "
        f"{module_error_cell(aggregate_module_errors(records))} |"
    )
    emit(f"| Raw record count | {len(records)} |")
    emit(
        f"| Unique-binary count | "
        f"{len({record.report.binary_key for record in records})} |"
    )
    emit(
        f"| Source reports | "
        + ", ".join(
            code(md_cell(value))
            for value in sorted({record.report.relative_path for record in records})
        )
        + " |"
    )
    emit()
    emit("<details>")
    emit("<summary>Normalized failure record</summary>")
    emit()
    emit("~~~~text")
    emit(f"{representative.function} at {representative.address}: "
         f"{representative.exception} — {representative.message}")
    emit("~~~~")
    emit()
    emit("</details>")
emit()

emit("## Report provenance")
emit()
emit(
    "| # | Slot | Specimen | Binary SHA-256 | Report SHA-256 | "
    "Failure records | Affected module errors | Source |"
)
emit("|---:|---|---|---|---|---:|---|---|")
for ordinal, report in enumerate(
    sorted(reports, key=lambda item: item.relative_path),
    1,
):
    binary_value = report.binary_sha256 or "missing"
    report_failures = [
        record for record in failures if record.report is report
    ]
    emit(
        f"| {ordinal} | {code(md_cell(report.slot_id))} | "
        f"{code(md_cell(report.specimen))} | {code(binary_value)} | "
        f"{code(report.report_sha256)} | {report.failure_count} | "
        f"{module_error_cell(aggregate_module_errors(report_failures))} | "
        f"{code(md_cell(report.relative_path))} |"
    )
emit()

emit("## Custody warnings")
emit()
if parse_warnings:
    for warning in sorted(parse_warnings):
        emit(f"- {md_cell(warning)}")
else:
    emit("- All failed-function bullets matched the canonical parser.")
if missing_binary_hashes:
    emit(
        f"- {missing_binary_hashes} report(s) lack Binary SHA-256; each was "
        "isolated and never de-duplicated."
    )
duplicate_groups = [
    grouped_reports
    for grouped_reports in binary_groups.values()
    if len(grouped_reports) > 1
]
if duplicate_groups:
    emit(
        f"- {len(duplicate_groups)} binary hash group(s) are assigned to "
        "multiple named slots; review build receipts before treating those "
        "slots as independent coverage."
    )
emit(
    "- Source hash, compiler identity, exact command, optimization flags and "
    "`.text` hash are not present in these REPORT.md records; the reporter "
    "does not infer them from specimen names."
)
emit()

tmp_output.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(
    "Parsed reports:       "
    f"{len(reports)}\n"
    "Failure records:      "
    f"{len(failures)}\n"
    "Unique binaries:      "
    f"{len(binary_groups)}\n"
    "Occurrence clusters:  "
    f"{len(by_occurrence)}\n"
    "Runtime families:     "
    f"{len(by_family)}\n"
    "Raw diagnostics:      "
    f"{raw_diagnostics}\n"
    "Unique diagnostics:   "
    f"{unique_binary_diagnostics}\n"
    "Module/error keys:    "
    f"{len(all_affected_module_errors)}"
)
PY

mv "$TMP_OUTPUT" "$OUTPUT_MD"

printf 'PAL bug matrix report generated:\n  %s\n' "$OUTPUT_MD"
