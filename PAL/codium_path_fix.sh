python - <<'PY'
from pathlib import Path
import json
import re
import shutil
import time

root = Path.cwd().resolve()

if not (root / "PALABI.py").is_file():
    raise SystemExit(
        f"ERROR: PALABI.py not found in expected PAL root: {root}"
    )

vscode = root / ".vscode"
vscode.mkdir(exist_ok=True)

stamp = time.strftime("%Y%m%d_%H%M%S")


def backup(path: Path) -> None:
    if path.exists():
        target = path.with_name(f"{path.name}.pre_pal_{stamp}.bak")
        shutil.copy2(path, target)
        print(f"BACKUP: {target}")


def strip_jsonc(text: str) -> str:
    """Remove JSONC comments without damaging quoted strings."""
    output = []
    index = 0
    in_string = False
    escaped = False

    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""

        if in_string:
            output.append(char)

            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False

            index += 1
            continue

        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue

        if char == "/" and following == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue

        if char == "/" and following == "*":
            index += 2
            while index + 1 < len(text):
                if text[index] == "*" and text[index + 1] == "/":
                    index += 2
                    break
                index += 1
            continue

        output.append(char)
        index += 1

    cleaned = "".join(output)
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


def load_jsonc(path: Path, default):
    if not path.exists():
        return default

    try:
        return json.loads(strip_jsonc(path.read_text(encoding="utf-8")))
    except Exception as exc:
        backup(path)
        print(f"WARNING: could not merge {path}: {exc}")
        return default


def write_json(path: Path, payload) -> None:
    path.write_text(
        json.dumps(payload, indent=4) + "\n",
        encoding="utf-8",
    )


# ------------------------------------------------------------
# Python extension environment: applies to all Python debugging
# configurations in this workspace unless explicitly overridden.
# ------------------------------------------------------------

env_path = root / ".env"
backup(env_path)

existing_env = []
if env_path.exists():
    existing_env = [
        line
        for line in env_path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
        if not line.lstrip().startswith("PYTHONPATH=")
    ]

existing_env.append(f"PYTHONPATH={root}")
env_path.write_text(
    "\n".join(existing_env).rstrip() + "\n",
    encoding="utf-8",
)


# ------------------------------------------------------------
# Workspace settings.
# ------------------------------------------------------------

settings_path = vscode / "settings.json"
backup(settings_path)
settings = load_jsonc(settings_path, {})

settings["python.envFile"] = "${workspaceFolder}/.env"
settings["python.terminal.activateEnvironment"] = True

extra_paths = list(settings.get("python.analysis.extraPaths") or [])
if "${workspaceFolder}" not in extra_paths:
    extra_paths.insert(0, "${workspaceFolder}")
settings["python.analysis.extraPaths"] = extra_paths

terminal_env = dict(
    settings.get("terminal.integrated.env.linux") or {}
)
terminal_env["PYTHONPATH"] = (
    "${workspaceFolder}:${env:PYTHONPATH}"
)
settings["terminal.integrated.env.linux"] = terminal_env

write_json(settings_path, settings)


# ------------------------------------------------------------
# Project-aware current-file debugger.
#
# For:
#   project/<program>/execute/functions/function.py
#
# ${fileDirname}/.. resolves to the execute directory.
# ------------------------------------------------------------

launch_path = vscode / "launch.json"
backup(launch_path)

launch = load_jsonc(
    launch_path,
    {
        "version": "0.2.0",
        "configurations": [],
    },
)

launch.setdefault("version", "0.2.0")
configurations = list(launch.get("configurations") or [])

pal_configuration = {
    "name": "PAL: Current file (project-aware)",
    "type": "debugpy",
    "request": "launch",
    "program": "${file}",
    "cwd": "${workspaceFolder}",
    "console": "integratedTerminal",
    "justMyCode": False,
    "env": {
        "PYTHONPATH": (
            "${workspaceFolder}:"
            "${fileDirname}:"
            "${fileDirname}/..:"
            "${fileDirname}/../runtime:"
            "${fileDirname}/../shims:"
            "${env:PYTHONPATH}"
        )
    }
}

configurations = [
    item
    for item in configurations
    if item.get("name") != pal_configuration["name"]
]
configurations.insert(0, pal_configuration)

launch["configurations"] = configurations
write_json(launch_path, launch)

print()
print("PAL VSCodium debugger environment installed.")
print(f"PAL root: {root}")
print(f"Settings: {settings_path}")
print(f"Launch:   {launch_path}")
print(f"Env:      {env_path}")
PY
