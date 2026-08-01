# ============================================================
# PAL PYGHIDRA GROUPED BATCH ENTRYPOINT
# BUILD: crystal_batch_v5_pipeline_bootstrap_flat_import_plane
# LOCATION AUTHORITY: PAL/pipeline/crystal_batch.py
#
# PyGhidra injects ``currentProgram`` into this script's globals.  The script
# remains physically grouped under pipeline/ while presenting PAL's historical
# flat absolute-import namespace across pipeline/, stack/, interface/, and root.
# ============================================================

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path


CRYSTAL_BATCH_BUILD = "crystal_batch_v5_pipeline_bootstrap_flat_import_plane"


def _real(path):
    return os.path.realpath(os.path.abspath(os.fspath(path)))


def _resolve_pal_root():
    override = os.environ.get("PAL_ROOT") or os.environ.get("PAL_SNAPSHOT_ROOT")
    if override:
        return _real(os.path.expanduser(override)), "PAL_ROOT"
    # This file is PAL/pipeline/crystal_batch.py; its parent is PAL root.
    return _real(os.path.dirname(os.path.dirname(__file__))), "pipeline_parent"


def _install_flat_import_plane(root):
    # Grouped directories are import peers.  Pipeline comes first because this
    # entrypoint owns PALBatchDecompiler; root remains the compatibility tail.
    ordered = [
        _real(os.path.join(root, "pipeline")),
        _real(os.path.join(root, "stack")),
        _real(os.path.join(root, "interface")),
        _real(root),
    ]
    missing = [path for path in ordered[:-1] if not os.path.isdir(path)]
    if missing:
        raise RuntimeError(
            "PAL grouped import plane is incomplete; missing: %s"
            % ", ".join(missing)
        )
    admitted = set(ordered)
    retained = []
    for entry in sys.path:
        try:
            resolved = _real(entry or os.getcwd())
        except Exception:
            retained.append(entry)
            continue
        if resolved not in admitted:
            retained.append(entry)
    sys.path[:] = ordered + retained
    return tuple(ordered)


def _program_name(program):
    for method_name in ("getName", "getExecutablePath"):
        method = getattr(program, method_name, None)
        if callable(method):
            try:
                value = method()
            except Exception:
                value = None
            if value:
                return os.path.basename(str(value))
    return "unknown_program"


def _write_receipt(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp.%d" % os.getpid())
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def main():
    root, root_authority = _resolve_pal_root()
    import_plane = _install_flat_import_plane(root)
    os.chdir(root)

    try:
        program = currentProgram
    except NameError as exc:
        raise RuntimeError(
            "pipeline/crystal_batch.py must be launched by PyGhidra; "
            "currentProgram was not injected"
        ) from exc
    if program is None:
        raise RuntimeError("PyGhidra supplied no currentProgram")

    program_name = _program_name(program)
    project_root = Path(root) / "project"
    target_root = project_root / program_name
    project_root.mkdir(parents=True, exist_ok=True)
    target_root.mkdir(parents=True, exist_ok=True)
    receipt_path = target_root / ".PAL_BATCH_BOOTSTRAP.json"

    receipt = {
        "schema": "pal_batch_bootstrap_receipt_v2",
        "status": "entered",
        "build": CRYSTAL_BATCH_BUILD,
        "pid": os.getpid(),
        "entrypoint": _real(__file__),
        "pal_root": root,
        "root_authority": root_authority,
        "program_name": program_name,
        "project_root": str(project_root),
        "target_root": str(target_root),
        "import_plane": list(import_plane),
    }
    _write_receipt(receipt_path, receipt)

    print("=== PAL PIPELINE BATCH BOOTSTRAP ===", flush=True)
    print("crystal build :", CRYSTAL_BATCH_BUILD, flush=True)
    print("entrypoint    :", _real(__file__), flush=True)
    print("PAL root      :", root, flush=True)
    print("root authority:", root_authority, flush=True)
    print("program       :", program_name, flush=True)
    print("target        :", target_root, flush=True)
    print("import plane  :", os.pathsep.join(import_plane), flush=True)

    try:
        from PALBatchDecompiler import decompile_program
        import PALBatchDecompiler as batch_module

        batch_path = _real(getattr(batch_module, "__file__", ""))
        expected_batch = _real(os.path.join(root, "pipeline", "PALBatchDecompiler.py"))
        if batch_path != expected_batch:
            raise RuntimeError(
                "PALBatchDecompiler escaped pipeline authority: expected %s, loaded %s"
                % (expected_batch, batch_path)
            )

        receipt.update({
            "status": "batch_imported",
            "batch_module": batch_path,
            "batch_build": getattr(batch_module, "BATCH_BUILD", None),
        })
        _write_receipt(receipt_path, receipt)
        print("batch module  :", batch_path, flush=True)
        print("batch build   :", receipt["batch_build"], flush=True)
        print("====================================", flush=True)

        result = decompile_program(
            program,
            output_root=root,
            include_external=False,
            ensure_projection_pair=True,
            freeze_icecubes=True,
            write_readable_files=False,
            keep_success_logs=True,
            mirror_pipeline_stdio=True,
            progress=True,
            pipeline_entrypoint="run_all",
        )

        manifest_path = target_root / "PAL_function_manifest.json"
        if not manifest_path.is_file():
            raise RuntimeError(
                "PALBatchDecompiler returned without project manifest: %s"
                % manifest_path
            )
        receipt_path.unlink(missing_ok=True)
        return result
    except Exception as exc:
        receipt.update({
            "status": "failed_before_or_during_batch",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "traceback": traceback.format_exc().splitlines(),
        })
        try:
            _write_receipt(receipt_path, receipt)
        except Exception:
            pass
        print("\n=== PAL PROJECT-SCOPE BATCH FAILURE ===", flush=True)
        traceback.print_exc()
        raise


# PyGhidra script execution does not guarantee ``__name__ == '__main__'``.
# Invoke unconditionally so project publication cannot silently be skipped.
main()
