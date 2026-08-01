"""PAL grouped-layout bootstrap with a flat legacy import plane."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, Iterable

ENVIRONMENT_VERSION = "pal_root_environment_v2.3"
PAL_ROOT = Path(__file__).resolve().parent
PAL_PATHS: Dict[str, Path] = {
    "root": PAL_ROOT,
    "stack": PAL_ROOT / "stack",
    "pipeline": PAL_ROOT / "pipeline",
    "interface": PAL_ROOT / "interface",
    "scripts": PAL_ROOT / "scripts",
    "project": PAL_ROOT / "project",
    "specimens": PAL_ROOT / "specimens",
    "specimens_c": PAL_ROOT / "specimens" / "c",
    "specimens_o0": PAL_ROOT / "specimens" / "o0",
    "specimens_o3": PAL_ROOT / "specimens" / "o3",
}


def _prepend_unique(paths: Iterable[Path]) -> None:
    values = [str(path.resolve()) for path in paths if path.is_dir()]
    for value in reversed(values):
        while value in sys.path:
            sys.path.remove(value)
        sys.path.insert(0, value)


def configure(*, change_to_root: bool = False) -> Dict[str, str]:
    """Expose grouped PAL modules as one flat absolute-import namespace."""
    _prepend_unique((
        PAL_PATHS["root"],
        PAL_PATHS["stack"],
        PAL_PATHS["pipeline"],
        PAL_PATHS["interface"],
    ))
    environment = {
        "PAL_ROOT": PAL_PATHS["root"],
        "PAL_STACK_ROOT": PAL_PATHS["stack"],
        "PAL_PIPELINE_ROOT": PAL_PATHS["pipeline"],
        "PAL_INTERFACE_ROOT": PAL_PATHS["interface"],
        "PAL_SCRIPTS_ROOT": PAL_PATHS["scripts"],
        "PAL_PROJECT_ROOT": PAL_PATHS["project"],
        "PAL_SPECIMENS_ROOT": PAL_PATHS["specimens"],
        "PAL_SPECIMENS_C_ROOT": PAL_PATHS["specimens_c"],
        "PAL_SPECIMENS_O0_ROOT": PAL_PATHS["specimens_o0"],
        "PAL_SPECIMENS_O3_ROOT": PAL_PATHS["specimens_o3"],
    }
    for name, path in environment.items():
        os.environ.setdefault(name, str(path))
    os.environ.setdefault("PAL_ENVIRONMENT_VERSION", ENVIRONMENT_VERSION)
    if change_to_root:
        os.chdir(PAL_ROOT)
    return {name: str(path) for name, path in PAL_PATHS.items()}


def require_root_cwd() -> None:
    if Path.cwd().resolve() != PAL_ROOT:
        raise RuntimeError(
            f"PAL operation requires root cwd {PAL_ROOT}; current={Path.cwd().resolve()}"
        )


configure()

__all__ = [
    "ENVIRONMENT_VERSION", "PAL_ROOT", "PAL_PATHS", "configure",
    "require_root_cwd",
]
