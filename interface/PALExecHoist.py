#!/usr/bin/env python3
"""Root-custody bridge for PALExecInterface in the grouped PAL tree.

PALExecInterface historically uses one ``pal_root`` for two different jobs:

1. discovering ``project/<specimen>`` trees; and
2. opening/copying live PAL modules as ``pal_root/PAL*.py``.

The grouped repository intentionally stores those modules under ``stack/``,
``pipeline/`` and ``interface/``.  This bridge keeps project discovery rooted
at the real repository while giving only PALExecPublisher a temporary flattened
read-only module view.  No compatibility files are created in the PAL root.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Sequence

BUILD = "pal_exec_hoist_v1_grouped_root_and_module_custody"
_REQUIRED_DIRS = ("project", "stack", "pipeline", "interface")


def _candidate_ancestors(path: Path) -> Iterable[Path]:
    current = path.expanduser().resolve()
    if current.is_file():
        current = current.parent
    yield current
    yield from current.parents


def _looks_like_pal_root(path: Path) -> bool:
    path = Path(path)
    return (
        all((path / name).is_dir() for name in _REQUIRED_DIRS)
        and (path / "pal").is_file()
        and (
            (path / "interface" / "PALExecInterface.py").is_file()
            or (path / "PALExecInterface.py").is_file()
        )
    )


def resolve_pal_root() -> Path:
    probes: list[Path] = []
    explicit = os.environ.get("PAL_ROOT")
    if explicit:
        probes.append(Path(explicit))
    probes.extend(_candidate_ancestors(Path(__file__)))
    probes.extend(_candidate_ancestors(Path.cwd()))

    seen: set[str] = set()
    for probe in probes:
        try:
            resolved = probe.expanduser().resolve()
        except OSError:
            continue
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        if _looks_like_pal_root(resolved):
            return resolved
    raise RuntimeError(
        "PAL root not found; expected project/, stack/, pipeline/, interface/, and pal"
    )


def install_import_plane(root: Path) -> None:
    # Final priority: PAL root, stack, pipeline, interface.
    ordered = [root, root / "stack", root / "pipeline", root / "interface"]
    for directory in reversed(ordered):
        text = str(directory.resolve())
        while text in sys.path:
            sys.path.remove(text)
        sys.path.insert(0, text)


def _link(target: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        return
    destination.symlink_to(target.resolve(), target_is_directory=target.is_dir())


def build_module_hoist(root: Path, destination: Path) -> dict[str, object]:
    destination.mkdir(parents=True, exist_ok=True)

    # Preserve repository-relative lookups used by completion and publication.
    linked_directories: list[str] = []
    directory_targets = {
        "project": Path(os.environ.get("PAL_PROJECT_ROOT", root / "project")),
        "projects": root / "projects",
        "specimens": root / "specimens",
        "stack": root / "stack",
        "pipeline": root / "pipeline",
        "interface": root / "interface",
        "scripts": root / "scripts",
    }
    for name, target in directory_targets.items():
        if target.is_dir():
            _link(target, destination / name)
            linked_directories.append(name)

    # Flatten Python modules using the same authority order as PYTHONPATH.
    linked_modules: list[str] = []
    origins: dict[str, str] = {}
    for source_root in (root, root / "stack", root / "pipeline", root / "interface"):
        if not source_root.is_dir():
            continue
        for source in sorted(source_root.glob("*.py"), key=lambda p: p.name.lower()):
            target = destination / source.name
            if target.exists() or target.is_symlink():
                continue
            _link(source, target)
            linked_modules.append(source.name)
            origins[source.name] = str(source.resolve())

    receipt = {
        "build": BUILD,
        "real_pal_root": str(root),
        "hoist_root": str(destination),
        "linked_directories": linked_directories,
        "linked_module_count": len(linked_modules),
        "module_origins": origins,
    }
    (destination / "PAL_EXEC_HOIST.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return receipt


def load_exec_interface(path: Path):
    spec = importlib.util.spec_from_file_location("PALExecInterface", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load PALExecInterface: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _strip_user_root(argv: Sequence[str]) -> list[str]:
    # The root launcher owns repository custody.  Remove conflicting direct
    # --root values while preserving every other PALExecInterface argument.
    result: list[str] = []
    index = 0
    values = list(argv)
    while index < len(values):
        value = values[index]
        if value == "--root":
            index += 2
            continue
        if value.startswith("--root="):
            index += 1
            continue
        result.append(value)
        index += 1
    return result


def main(argv: Sequence[str] | None = None) -> int:
    root = resolve_pal_root()
    install_import_plane(root)

    interface_path = Path(
        os.environ.get(
            "PAL_EXEC_INTERFACE_PATH",
            root / "interface" / "PALExecInterface.py",
        )
    ).expanduser().resolve()
    if not interface_path.is_file():
        raise RuntimeError(f"PALExecInterface is missing: {interface_path}")

    print(f"PAL EXEC HOIST BUILD: {BUILD}")
    print(f"PAL root authority:  {root}")
    print(f"Project authority:   {Path(os.environ.get('PAL_PROJECT_ROOT', root / 'project')).resolve()}")
    print(f"Interface module:    {interface_path}")

    with tempfile.TemporaryDirectory(prefix="pal-exec-hoist-") as temporary:
        hoist = Path(temporary).resolve()
        receipt = build_module_hoist(root, hoist)
        os.environ["PAL_REAL_ROOT"] = str(root)
        os.environ["PAL_EXEC_HOIST_ROOT"] = str(hoist)

        module = load_exec_interface(interface_path)
        publisher = getattr(module, "PALExecPublisher", None)
        interface = getattr(module, "PALExecInterface", None)
        if publisher is None or interface is None:
            raise RuntimeError(
                "PALExecInterface module lacks PALExecPublisher/PALExecInterface"
            )

        original_publisher_init = publisher.__init__

        def hoisted_publisher_init(self, _pal_root, project_root):
            # Project resolution remains on the real interface root.  Only the
            # publisher's historical flat-module authority is redirected.
            original_publisher_init(self, hoist, project_root)

        publisher.__init__ = hoisted_publisher_init
        try:
            cleaned = _strip_user_root(list(argv if argv is not None else sys.argv[1:]))
            call_argv = ["--root", str(root), *cleaned]
            print(
                "Publisher module view: %s (%d Python modules)"
                % (hoist, int(receipt["linked_module_count"]))
            )
            result = module.main(call_argv)
            return int(result or 0)
        finally:
            publisher.__init__ = original_publisher_init


if __name__ == "__main__":
    raise SystemExit(main())
