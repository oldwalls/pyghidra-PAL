#!/usr/bin/env bash
set -Eeuo pipefail

# PAL MATRIX LOG TABLOID v1
# Human-first viewer for high-volume PAL matrix runs.
#
# Usage:
#   PAL_log_tabloid.sh [RUN_DIR|latest] [--failed-only] [--no-color]
#                       [--width N] [--tail N]
#
# Defaults:
#   RUN_DIR = PAL_ROOT/log_matrix/latest when available, otherwise
#             script_dir/log_matrix/latest.
#
# Always writes a plain-text copy to RUN_DIR/TABLOID.txt.

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
    pwd -P
)"
PAL_ROOT="${PAL_ROOT:-$SCRIPT_DIR}"
TARGET=""
FAILED_ONLY=0
COLOR=1
WIDTH=""
TAIL_LINES=18

while [[ $# -gt 0 ]]; do
    case "$1" in
        --failed-only)
            FAILED_ONLY=1
            shift
            ;;
        --no-color)
            COLOR=0
            shift
            ;;
        --width)
            [[ $# -ge 2 ]] || {
                printf 'ERROR: --width requires an integer\n' >&2
                exit 2
            }
            WIDTH="$2"
            shift 2
            ;;
        --tail)
            [[ $# -ge 2 ]] || {
                printf 'ERROR: --tail requires an integer\n' >&2
                exit 2
            }
            TAIL_LINES="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '1,18p' "$0"
            exit 0
            ;;
        -*)
            printf 'ERROR: unknown option: %s\n' "$1" >&2
            exit 2
            ;;
        *)
            [[ -z "$TARGET" ]] || {
                printf 'ERROR: multiple run directories supplied\n' >&2
                exit 2
            }
            TARGET="$1"
            shift
            ;;
    esac
done

[[ "$TAIL_LINES" =~ ^[0-9]+$ ]] || {
    printf 'ERROR: --tail must be a non-negative integer\n' >&2
    exit 2
}
if [[ -n "$WIDTH" ]]; then
    [[ "$WIDTH" =~ ^[0-9]+$ ]] || {
        printf 'ERROR: --width must be a positive integer\n' >&2
        exit 2
    }
fi

if [[ -z "$TARGET" || "$TARGET" == "latest" ]]; then
    TARGET="$PAL_ROOT/log_matrix/latest"
fi

if [[ -L "$TARGET" ]]; then
    TARGET="$(readlink -f -- "$TARGET")"
elif [[ -d "$TARGET" ]]; then
    TARGET="$(
        cd -- "$TARGET"
        pwd -P
    )"
else
    printf 'ERROR: PAL matrix run not found: %s\n' "$TARGET" >&2
    exit 1
fi

python3 - \
    "$TARGET" \
    "$FAILED_ONLY" \
    "$COLOR" \
    "${WIDTH:-0}" \
    "$TAIL_LINES" <<'PAL_TABLOID_PY'
from __future__ import annotations

import csv
import datetime
import json
import os
import shutil
import sys
import textwrap
from pathlib import Path

run_dir = Path(sys.argv[1]).resolve()
failed_only = bool(int(sys.argv[2]))
requested_color = bool(int(sys.argv[3]))
width_arg = int(sys.argv[4])
tail_lines = int(sys.argv[5])

tty_color = requested_color and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
terminal_width = width_arg or shutil.get_terminal_size((150, 40)).columns
width = max(96, min(int(terminal_width), 220))
plain_lines: list[str] = []

class C:
    reset = "\033[0m" if tty_color else ""
    bold = "\033[1m" if tty_color else ""
    dim = "\033[2m" if tty_color else ""
    red = "\033[31m" if tty_color else ""
    green = "\033[32m" if tty_color else ""
    yellow = "\033[33m" if tty_color else ""
    cyan = "\033[36m" if tty_color else ""
    magenta = "\033[35m" if tty_color else ""
    white = "\033[97m" if tty_color else ""

def strip_ansi(text: str) -> str:
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", text)

def emit(text: str = "") -> None:
    print(text)
    plain_lines.append(strip_ansi(text))

def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {} if default is None else default

def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values

def human_bytes(value) -> str:
    try:
        amount = float(int(value or 0))
    except Exception:
        return "-"
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit = "B"
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024
    if unit == "B":
        return f"{int(amount)}B"
    return f"{amount:.1f}{unit}" if amount >= 10 else f"{amount:.2f}{unit}"

def clip(value, limit: int) -> str:
    text = str(value if value not in (None, "") else "-")
    if len(text) <= limit:
        return text
    return text[: max(limit - 1, 1)] + "…"

def color_status(status: str) -> str:
    status = str(status or "-").upper()
    if status == "PASS":
        return f"{C.green}{C.bold}{status}{C.reset}"
    if status in {"FAIL", "BROKEN", "ABORTED"}:
        return f"{C.red}{C.bold}{status}{C.reset}"
    if status in {"DEGRADED", "INCOMPLETE", "STALE"}:
        return f"{C.yellow}{C.bold}{status}{C.reset}"
    return f"{C.cyan}{status}{C.reset}"

def rule(char="═") -> str:
    return char * width

def center(text: str, fill=" ") -> str:
    return str(text).center(width, fill)

def card(title: str, rows: list[tuple[str, str]], accent=C.cyan) -> None:
    emit(f"{accent}{C.bold}┌─ {title} {'─' * max(width-len(title)-4, 0)}┐{C.reset}")
    key_width = min(28, max([len(k) for k, _ in rows] + [8]))
    for key, value in rows:
        wrapped = textwrap.wrap(str(value), max(width - key_width - 7, 20)) or [""]
        first = f"│ {key.ljust(key_width)} │ {wrapped[0]}"
        emit(first.ljust(width - 1) + "│")
        for continuation in wrapped[1:]:
            line = f"│ {' '.ljust(key_width)} │ {continuation}"
            emit(line.ljust(width - 1) + "│")
    emit(f"{accent}{C.bold}└{'─' * (width-2)}┘{C.reset}")

summary_path = run_dir / "summary.json"
summary_tsv = run_dir / "summary.tsv"
summary = read_json(summary_path, {})
rows: list[dict] = []

if isinstance(summary.get("specimens"), list):
    rows = [dict(item) for item in summary["specimens"]]
elif summary_tsv.is_file():
    with summary_tsv.open("rt", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))

status_values = read_env(run_dir / "run.status")
env = read_env(run_dir / "environment.txt")
counts = dict(summary.get("counts") or {})
attempted = int(counts.get("attempted", len(rows)) or 0)
passed = int(counts.get("passed", sum(r.get("status") == "PASS" for r in rows)) or 0)
failed = int(counts.get("failed", sum(r.get("status") == "FAIL" for r in rows)) or 0)
aborted = bool(summary.get("aborted")) or status_values.get("status") == "ABORTED"
overall = status_values.get("status") or (
    "ABORTED" if aborted else "FAIL" if failed else "PASS"
)

started = env.get("run_started_utc", "-")
finished = status_values.get("finished_utc", "-")
run_name = run_dir.name

emit(f"{C.magenta}{C.bold}{rule('═')}{C.reset}")
emit(f"{C.magenta}{C.bold}{center('PAL MATRIX TABLOID // FRONT PAGE')}{C.reset}")
emit(f"{C.magenta}{C.bold}{center(run_name)}{C.reset}")
emit(f"{C.magenta}{C.bold}{rule('═')}{C.reset}")

headline = (
    "ALL SPECIMENS CLEARED"
    if overall == "PASS"
    else "RUN INTERRUPTED"
    if overall == "ABORTED"
    else f"{failed} SPECIMEN{'S' if failed != 1 else ''} FAILED PUBLICATION"
)
emit(
    f"{color_status(overall)}  "
    f"{C.bold}{headline}{C.reset}  "
    f"// attempted={attempted} passed={passed} failed={failed}"
)
emit(f"{C.dim}started={started}  finished={finished}{C.reset}")
emit()

cwd_agrees = (
    env.get("matrix_process_pwd") == env.get("pal_root")
    and env.get("pyghidra_child_cwd") == env.get("pal_root")
)
card(
    "LAUNCH ROOT CUSTODY",
    [
        ("PAL root", env.get("pal_root", "-")),
        ("caller directory", env.get("caller_pwd", "-")),
        ("matrix process cwd", env.get("matrix_process_pwd", "-")),
        ("PyGhidra child cwd", env.get("pyghidra_child_cwd", "-")),
        (
            "custody verdict",
            "LOCKED TO PAL_ROOT" if cwd_agrees else "CWD DISAGREEMENT",
        ),
        ("Ghidra project", f"{env.get('ghidra_project_path', '-')}/{env.get('ghidra_project_name', '-')}"),
    ],
    C.green if cwd_agrees else C.red,
)
emit()

display_rows = [row for row in rows if not failed_only or row.get("status") == "FAIL"]
name_width = min(34, max([len(str(r.get("specimen") or "")) for r in display_rows] + [12]))
columns = [
    ("#", 4),
    ("STATE", 7),
    ("SPECIMEN", name_width),
    ("PY/AUD", 7),
    ("SEC", 6),
    ("MANIFEST", 11),
    ("DEC/FAIL", 9),
    ("FILES", 7),
    ("SIZE", 9),
    ("DIAGNOSTIC", max(20, width - (4+7+name_width+7+6+11+9+7+9+18))),
]

header = " ".join(name.ljust(size) for name, size in columns)
emit(f"{C.bold}{rule('─')}{C.reset}")
emit(f"{C.bold}RUN LEDGER{C.reset}")
emit(f"{C.bold}{header}{C.reset}")
emit(rule("─"))

for row in display_rows:
    status = str(row.get("status") or "-")
    py_aud = f"{row.get('pyghidra_exit', '-')}/{row.get('audit_exit', '-')}"
    dec_fail = f"{row.get('decompiled', '0')}/{row.get('failed', '0')}"
    values = [
        clip(row.get("ordinal"), columns[0][1]).rjust(columns[0][1]),
        clip(status, columns[1][1]).ljust(columns[1][1]),
        clip(row.get("specimen"), columns[2][1]).ljust(columns[2][1]),
        clip(py_aud, columns[3][1]).ljust(columns[3][1]),
        clip(row.get("elapsed_seconds"), columns[4][1]).rjust(columns[4][1]),
        clip(row.get("manifest_status"), columns[5][1]).ljust(columns[5][1]),
        clip(dec_fail, columns[6][1]).ljust(columns[6][1]),
        clip(row.get("publish_files"), columns[7][1]).rjust(columns[7][1]),
        clip(human_bytes(row.get("publish_bytes")), columns[8][1]).rjust(columns[8][1]),
        clip(row.get("diagnostic"), columns[9][1]).ljust(columns[9][1]),
    ]
    line = " ".join(values)
    if status == "PASS":
        emit(f"{C.green}{line}{C.reset}")
    else:
        emit(f"{C.red}{C.bold}{line}{C.reset}")

emit(rule("─"))
emit()

failure_rows = [row for row in rows if row.get("status") == "FAIL"]
if failure_rows:
    emit(f"{C.red}{C.bold}{center('BREAKING FAILURES', '═')}{C.reset}")
    for row in failure_rows:
        specimen = str(row.get("specimen") or "unknown")
        stream_authority = (
            row.get("pyghidra_log")
            or row.get("pipeline_full_transcript")
            or ""
        )
        prefix = Path(str(stream_authority)).parent
        diag_path = prefix / "publish.custody.diagnostic.json"
        diag = read_json(diag_path, {})
        classification = diag.get("classification") or "unclassified_failure"
        if (
            str(row.get("pyghidra_exit")) == "0"
            and str(row.get("audit_exit")) != "0"
            and str(row.get("manifest_status")) == "missing"
        ):
            news = "CLEAN OUTER EXIT — PUBLISH TREE ABSENT"
        elif str(row.get("pyghidra_exit")) != "0":
            news = "PYGHIDRA PROCESS FAILURE"
        else:
            news = "PUBLISHED BUNDLE REJECTED BY AUDIT"

        card(
            f"{row.get('ordinal', '?')}. {specimen} // {news}",
            [
                ("classification", classification),
                ("PyGhidra / audit", f"{row.get('pyghidra_exit')}/{row.get('audit_exit')}"),
                ("manifest", row.get("manifest_status", "-")),
                ("decompiled / failed", f"{row.get('decompiled', 0)}/{row.get('failed', 0)}"),
                ("child cwd", diag.get("child_cwd", "-")),
                ("cwd agrees", diag.get("cwd_agrees_with_pal_root", "-")),
                (
                    "misplaced trees",
                    ", ".join(
                        item.get("publish_dir", "-")
                        for item in list(diag.get("misplaced_publish_trees") or [])
                    )
                    or "none",
                ),
                ("pipeline transcript", row.get("pipeline_full_transcript", "-")),
                ("failed report", row.get("failed_report_dir", "-")),
                ("archive", row.get("failed_report_archive", "-")),
            ],
            C.red,
        )

        excerpt = Path(str(row.get("failed_report_dir") or "")) / "error_excerpt.txt"
        if tail_lines and excerpt.is_file():
            lines = excerpt.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            selected = lines[-tail_lines:]
            emit(f"{C.yellow}{C.bold}LATEST EVIDENCE ({len(selected)} lines){C.reset}")
            for line in selected:
                emit("  " + clip(line, width - 2))
            emit()
else:
    emit(f"{C.green}{C.bold}{center('NO FAILURE DESK — CLEAN RUN', '═')}{C.reset}")
    emit()

slowest = sorted(
    rows,
    key=lambda item: int(item.get("elapsed_seconds") or 0),
    reverse=True,
)[:5]
largest = sorted(
    rows,
    key=lambda item: int(item.get("publish_bytes") or 0),
    reverse=True,
)[:5]

card(
    "NUMBERS DESK",
    [
        (
            "slowest specimens",
            "; ".join(
                f"{item.get('specimen')}={item.get('elapsed_seconds')}s"
                for item in slowest
            )
            or "-",
        ),
        (
            "largest publish trees",
            "; ".join(
                f"{item.get('specimen')}={human_bytes(item.get('publish_bytes'))}"
                for item in largest
            )
            or "-",
        ),
        ("master log", str(run_dir / "master.log")),
        ("summary JSON", str(run_dir / "summary.json")),
        ("failure index", str(run_dir / "failures.txt")),
    ],
    C.cyan,
)

emit()
emit(f"{C.magenta}{C.bold}{rule('═')}{C.reset}")
emit(
    f"{C.magenta}{C.bold}{center('END OF EDITION // RAW AUTHORITIES REMAIN UNMODIFIED')}{C.reset}"
)
emit(f"{C.magenta}{C.bold}{rule('═')}{C.reset}")

plain_path = run_dir / "TABLOID.txt"
plain_path.write_text("\n".join(plain_lines) + "\n", encoding="utf-8")
print(f"\nTABLOID FILE: {plain_path}")
PAL_TABLOID_PY
