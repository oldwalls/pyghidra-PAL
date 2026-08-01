#!/usr/bin/env python3
# ============================================================
# PAL EXPLICIT PYGHIDRA API DRIVER
# BUILD: pal_pyghidra_driver_v1_explicit_run_script_api
#
# Replaces ambiguous console-entry parsing with a direct call to
# pyghidra.run_script().  This driver is the sole owner of binary/script/
# project argument placement.
# ============================================================

from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import traceback
from typing import Any, Dict, Optional


DRIVER_BUILD = "pal_pyghidra_driver_v1_explicit_run_script_api"
RECEIPT_SCHEMA = "pal_pyghidra_driver_receipt_v1"


def _utc_now() -> str:
    return (
        _datetime.datetime.now(_datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Optional[Path], payload: Dict[str, Any]) -> None:
    if path is None:
        return
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _bool_text(value: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError(
        "expected one of: 1/0, true/false, yes/no, on/off"
    )


def _load_pyghidra():
    import pyghidra  # Imported only after the driver-entry breadcrumb.

    run_script = getattr(pyghidra, "run_script", None)
    if not callable(run_script):
        raise RuntimeError(
            "installed pyghidra package exposes no callable run_script API"
        )
    return pyghidra, run_script


def _api_identity(pyghidra, run_script) -> Dict[str, Any]:
    module_path = Path(getattr(pyghidra, "__file__", "") or "")
    try:
        signature = str(inspect.signature(run_script))
    except Exception:
        signature = "<signature unavailable>"
    return {
        "module": str(module_path.resolve()) if module_path else None,
        "version": getattr(pyghidra, "__version__", None),
        "run_script_signature": signature,
        "python": sys.version,
        "python_executable": sys.executable,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one PAL crystal_batch.py through the explicit "
            "pyghidra.run_script Python API."
        )
    )
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--binary")
    parser.add_argument("--script")
    parser.add_argument("--project-location")
    parser.add_argument("--project-name")
    parser.add_argument("--program-name")
    parser.add_argument("--pal-root")
    parser.add_argument("--receipt")
    parser.add_argument(
        "--nested-project-location",
        type=_bool_text,
        default=True,
    )
    parser.add_argument(
        "--analyze",
        type=_bool_text,
        default=True,
    )
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    started = _utc_now()

    print(
        "PAL PYGHIDRA DRIVER ENTER:",
        f"build={DRIVER_BUILD}",
        f"cwd={os.getcwd()}",
        f"python={sys.executable}",
        flush=True,
    )

    pyghidra, run_script = _load_pyghidra()
    api = _api_identity(pyghidra, run_script)

    print(
        "PAL PYGHIDRA API READY:",
        f"module={api['module']}",
        f"version={api['version']}",
        flush=True,
    )
    print(
        "PAL PYGHIDRA RUN_SCRIPT SIGNATURE:",
        api["run_script_signature"],
        flush=True,
    )

    if args.probe:
        print(
            json.dumps(
                {
                    "schema": "pal_pyghidra_api_probe_v1",
                    "driver_build": DRIVER_BUILD,
                    "api": api,
                },
                indent=2,
                sort_keys=True,
            ),
            flush=True,
        )
        return 0

    required = {
        "--binary": args.binary,
        "--script": args.script,
        "--project-location": args.project_location,
        "--project-name": args.project_name,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise SystemExit(
            "missing required explicit-driver arguments: "
            + ", ".join(missing)
        )

    binary = Path(args.binary).expanduser().resolve()
    script = Path(args.script).expanduser().resolve()
    project_location = (
        Path(args.project_location).expanduser().resolve()
    )
    pal_root = (
        Path(args.pal_root).expanduser().resolve()
        if args.pal_root
        else script.parent.resolve()
    )
    receipt_path = (
        Path(args.receipt).expanduser().resolve()
        if args.receipt
        else None
    )

    if not binary.is_file():
        raise FileNotFoundError(f"binary not found: {binary}")
    if not script.is_file():
        raise FileNotFoundError(f"script not found: {script}")
    if not pal_root.is_dir():
        raise NotADirectoryError(f"PAL root not found: {pal_root}")
    project_location.mkdir(parents=True, exist_ok=True)

    os.chdir(pal_root)
    os.environ["PAL_ROOT"] = str(pal_root)
    os.environ["PAL_SNAPSHOT_ROOT"] = str(pal_root)
    if str(pal_root) not in sys.path:
        sys.path.insert(0, str(pal_root))

    program_name = args.program_name or binary.name
    receipt: Dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "driver_build": DRIVER_BUILD,
        "status": "entered",
        "started_utc": started,
        "finished_utc": None,
        "cwd": os.getcwd(),
        "pal_root": str(pal_root),
        "binary": str(binary),
        "binary_sha256": _sha256_file(binary),
        "script": str(script),
        "script_sha256": _sha256_file(script),
        "project_location": str(project_location),
        "project_name": str(args.project_name),
        "program_name": str(program_name),
        "nested_project_location": bool(
            args.nested_project_location
        ),
        "analyze": bool(args.analyze),
        "api": api,
        "exception": None,
    }
    _atomic_json(receipt_path, receipt)

    kwargs = {
        "binary_path": str(binary),
        "script_path": str(script),
        "project_location": str(project_location),
        "project_name": str(args.project_name),
        "program_name": str(program_name),
        "nested_project_location": bool(
            args.nested_project_location
        ),
        "analyze": bool(args.analyze),
        "verbose": bool(args.verbose),
    }

    print(
        "PAL PYGHIDRA RUN_SCRIPT BEGIN:",
        f"binary={binary}",
        f"script={script}",
        f"project={project_location}/{args.project_name}",
        f"program={program_name}",
        f"nested={args.nested_project_location}",
        flush=True,
    )

    try:
        result = run_script(**kwargs)
    except Exception as exc:
        receipt["status"] = "failed"
        receipt["finished_utc"] = _utc_now()
        receipt["exception"] = {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc().splitlines(),
        }
        _atomic_json(receipt_path, receipt)
        print(
            "PAL PYGHIDRA DRIVER FAILURE:",
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )
        traceback.print_exc()
        return 1

    receipt["status"] = "complete"
    receipt["finished_utc"] = _utc_now()
    receipt["run_script_return_type"] = type(result).__name__
    receipt["run_script_return_repr"] = repr(result)[:2048]
    _atomic_json(receipt_path, receipt)

    print(
        "PAL PYGHIDRA DRIVER EXIT:",
        "status=complete",
        f"return_type={type(result).__name__}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
