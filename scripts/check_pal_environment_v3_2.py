#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

BUILD = "pal_root_environment_v3.2_pipeline_runner_authority"


def find_root() -> Path:
    explicit = os.environ.get("PAL_ROOT")
    probes = [Path(explicit)] if explicit else []
    probes.extend([Path(__file__).resolve().parent.parent, Path.cwd().resolve()])
    for probe in probes:
        if (probe / "pal").is_file() and (probe / "pipeline").is_dir():
            return probe.resolve()
    raise RuntimeError("PAL root not found")


def is_runner(path: Path) -> bool:
    if not path.is_file():
        return False
    if "report" in path.name.casefold():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return (
        re.search(r"pyghidra", text, re.I) is not None
        and "CRYSTAL_BATCH" in text
        and (
            "PAL ALL-EXE IMPORT + PUBLISH MATRIX" in text
            or "audit_publish_bundle" in text
            or "SUMMARY_TSV" in text
        )
    )


def main() -> int:
    root = find_root()
    launcher = root / "pal"
    text = launcher.read_text(encoding="utf-8", errors="replace")
    checks = {
        "launcher build": BUILD in text,
        "pipeline crystal batch": (root / "pipeline" / "crystal_batch.py").is_file(),
        "project root": (root / "project").is_dir(),
        "stack root": (root / "stack").is_dir(),
        "interface root": (root / "interface").is_dir(),
        "open suffix filter": "PAL SUFFIX FILTER" in text,
        "runner fingerprint gate": "_is_publish_matrix_runner" in text,
        "reporter separation": "_find_matrix_reporter" in text,
        "latest-link custody": "_update_latest_matrix_link" in text,
        "exec hoist": (root / "interface" / "PALExecHoist.py").is_file(),
    }
    runner_candidates = [
        root / "scripts" / "PAL_stack_debug.sh",
        root / "PAL_stack_debug.sh",
        root / "scripts" / "PAL_import_publish_all_exe_matrix.sh",
        root / "PAL_import_publish_all_exe_matrix.sh",
    ]
    checks["publication runner"] = any(is_runner(path) for path in runner_candidates)

    failed = False
    print(f"PAL ENVIRONMENT CHECK: {BUILD}")
    print(f"PAL root: {root}")
    for label, ok in checks.items():
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        failed |= not ok
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
