# ============================================================
# PAL ONE-CLICK BATCH ENTRYPOINT
# BUILD: crystal_batch_v2_pyghidra_process
# Run as a PyGhidra script; currentProgram is injected by PyGhidra.
# ============================================================

import os
import sys
import traceback


# PyGhidra may be launched from a directory other than PAL. Anchor imports
# and generated artifacts to the directory containing this script.
PAL_ROOT = os.path.dirname(os.path.abspath(__file__))
if PAL_ROOT not in sys.path:
    sys.path.insert(0, PAL_ROOT)

from PALBatchDecompiler import decompile_program


def main():
    # ``currentProgram`` is deliberately supplied by the PyGhidra script
    # environment. Running this file with ordinary CPython is unsupported.
    try:
        program = currentProgram
    except NameError:
        raise RuntimeError(
            "crystal_batch_v2.py must be launched as a PyGhidra process; "
            "currentProgram was not injected"
        )
    if program is None:
        raise RuntimeError("PyGhidra supplied no currentProgram")


	

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
