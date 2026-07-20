# ============================================================
# PAL ONE-CLICK BATCH ENTRYPOINT
# BUILD: crystal_batch_v2d_explicit_stdio_overlay_authority
# Run as a PyGhidra script; currentProgram is injected by PyGhidra.
# ============================================================

import importlib.util
import os
import sys
import traceback


CRYSTAL_BATCH_BUILD = "crystal_batch_v2d_explicit_stdio_overlay_authority"
EXPECTED_BATCH_BUILD = "batch_v2d_explicit_stdio_overlay_authority"

# The operator may explicitly select a complete PAL snapshot:
#
#     PAL_SNAPSHOT_ROOT=/path/to/PAL
#
# Otherwise a valid PAL snapshot in the current working directory is
# authoritative. This permits validation from a customer-facing checkout even
# when PyGhidra was launched through an older script path. The script directory
# remains the fallback for ordinary one-click use.
_ROOT_SENTINELS = (
    "PALBatchDecompiler.py",
    "PALDecompilerPipeline.py",
    "PALemitter.py",
)


def _real_path(path):
    return os.path.realpath(os.path.abspath(os.fspath(path)))


def _is_pal_snapshot_root(path):
    root = _real_path(path)
    return all(os.path.isfile(os.path.join(root, name))
               for name in _ROOT_SENTINELS)


def _resolve_pal_snapshot_root():
    override = os.environ.get("PAL_SNAPSHOT_ROOT")
    cwd_root = _real_path(os.getcwd())
    script_root = _real_path(os.path.dirname(__file__))

    if override:
        selected = _real_path(os.path.expanduser(override))
        authority = "PAL_SNAPSHOT_ROOT"
    elif _is_pal_snapshot_root(cwd_root):
        selected = cwd_root
        authority = "current_working_directory"
    else:
        selected = script_root
        authority = "crystal_batch_script_directory"

    if not _is_pal_snapshot_root(selected):
        missing = [
            name for name in _ROOT_SENTINELS
            if not os.path.isfile(os.path.join(selected, name))
        ]
        raise RuntimeError(
            "PAL snapshot root is incomplete: %s; missing: %s"
            % (selected, ", ".join(missing))
        )

    return selected, authority


def _path_entry_real(entry):
    try:
        return _real_path(entry or os.getcwd())
    except Exception:
        return None


def _evict_file_backed_pal_modules():
    """
    Remove PAL modules cached by an earlier PyGhidra script run.

    PyGhidra may retain one interpreter across launches. Reloading only
    PALBatchDecompiler is insufficient because it can retain imported classes
    and functions from a different PAL tree. At this entry boundary no PAL
    pipeline objects have been constructed yet, so a complete file-backed PAL
    namespace reset is safe and deterministic.
    """
    evicted = []
    for name, module in list(sys.modules.items()):
        if not (name == "PAL" or name.startswith("PAL")):
            continue
        module_file = getattr(module, "__file__", None)
        if not module_file:
            continue
        evicted.append((name, _real_path(module_file)))
        del sys.modules[name]
    return evicted


def _put_snapshot_first(root):
    root = _real_path(root)
    retained = [
        entry for entry in sys.path
        if _path_entry_real(entry) != root
    ]
    sys.path[:] = [root] + retained


def _load_exact_batch_module(root):
    module_path = _real_path(os.path.join(root, "PALBatchDecompiler.py"))

    _put_snapshot_first(root)
    evicted = _evict_file_backed_pal_modules()

    spec = importlib.util.spec_from_file_location(
        "PALBatchDecompiler", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(
            "Could not create exact PALBatchDecompiler import spec: %s"
            % module_path
        )

    module = importlib.util.module_from_spec(spec)
    # Register before execution so the module's own imports observe the same
    # canonical identity and cannot create a second batch module object.
    sys.modules["PALBatchDecompiler"] = module
    spec.loader.exec_module(module)

    loaded_path = _real_path(getattr(module, "__file__", ""))
    if loaded_path != module_path:
        raise RuntimeError(
            "PAL batch import escaped snapshot root: expected %s, loaded %s"
            % (module_path, loaded_path)
        )

    loaded_build = getattr(module, "BATCH_BUILD", None)
    if loaded_build != EXPECTED_BATCH_BUILD:
        raise RuntimeError(
            "PAL batch build mismatch at %s: expected %r, loaded %r"
            % (module_path, EXPECTED_BATCH_BUILD, loaded_build)
        )

    return module, evicted


def _trace_enabled():
    value = os.environ.get("PAL_BATCH_IMPORT_TRACE", "OFF")
    return str(value).strip().upper() in {
        "1", "TRUE", "YES", "Y", "ON", "ENABLE", "ENABLED",
    }


PAL_ROOT, PAL_ROOT_AUTHORITY = _resolve_pal_snapshot_root()
_BATCH_MODULE, _EVICTED_PAL_MODULES = _load_exact_batch_module(PAL_ROOT)
decompile_program = _BATCH_MODULE.decompile_program


def _print_import_trace():
    if not _trace_enabled():
        return
    print("=== PAL SNAPSHOT IMPORT LOCK ===")
    print("crystal build :", CRYSTAL_BATCH_BUILD)
    print("root authority:", PAL_ROOT_AUTHORITY)
    print("snapshot root :", PAL_ROOT)
    print("batch module  :", _BATCH_MODULE.__file__)
    print("batch build   :", _BATCH_MODULE.BATCH_BUILD)
    print("PAL modules evicted:", len(_EVICTED_PAL_MODULES))
    for name, path in _EVICTED_PAL_MODULES:
        print("  evicted %s <- %s" % (name, path))
    print("================================")


def main():
    # ``currentProgram`` is deliberately supplied by the PyGhidra script
    # environment. Running this file with ordinary CPython is unsupported.
    try:
        program = currentProgram
    except NameError:
        raise RuntimeError(
            "crystal_batch.py must be launched as a PyGhidra process; "
            "currentProgram was not injected"
        )
    if program is None:
        raise RuntimeError("PyGhidra supplied no currentProgram")

    _print_import_trace()

    return decompile_program(
        program,
        output_root=PAL_ROOT,
        include_external=False,
        ensure_projection_pair=True,
        freeze_icecubes=True,
        write_readable_files=False,
        keep_success_logs=False,
        progress=True,
        pipeline_entrypoint="run_all",
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("\n=== PAL BATCH UNHANDLED EXCEPTION ===")
        traceback.print_exc()
        raise
