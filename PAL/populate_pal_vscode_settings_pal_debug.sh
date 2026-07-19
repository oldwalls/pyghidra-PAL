#!/usr/bin/env bash
# ============================================================
# PAL CODIUM WORKSPACE SETTINGS POPULATOR — PAL-DEBUG ENV
#
# Creates:
#   ~/gh/PAL/project/<specimen>.exe/execute/.vscode/settings.json
#
# The generated Codium settings:
#   - bind Python analysis/debugging to Conda env "pal-debug"
#   - activate pal-debug automatically in integrated terminals
#   - expose PAL runtime, shims, functions, and execute root
#
# Optional overrides:
#   PAL_ROOT=/path/to/PAL
#   PAL_DEBUG_ENV=other-conda-env
#   PAL_DEBUG_PYTHON=/absolute/path/to/python
#   CONDA_EXE=/absolute/path/to/conda
#
# Usage:
#   chmod +x populate_pal_vscode_settings_pal_debug.sh
#   ./populate_pal_vscode_settings_pal_debug.sh
# ============================================================

set -euo pipefail

PAL_ROOT="${PAL_ROOT:-$HOME/gh/PAL}"
PROJECT_ROOT="$PAL_ROOT/project"
PAL_DEBUG_ENV="${PAL_DEBUG_ENV:-pal-debug}"

if [[ -n "${CONDA_EXE:-}" ]]; then
    CONDA_BIN="$CONDA_EXE"
elif command -v conda >/dev/null 2>&1; then
    CONDA_BIN="$(command -v conda)"
elif [[ -x "$HOME/miniconda/bin/conda" ]]; then
    CONDA_BIN="$HOME/miniconda/bin/conda"
elif [[ -x "$HOME/anaconda3/bin/conda" ]]; then
    CONDA_BIN="$HOME/anaconda3/bin/conda"
else
    CONDA_BIN=""
fi

resolve_debug_python() {
    if [[ -n "${PAL_DEBUG_PYTHON:-}" ]]; then
        printf '%s\n' "$PAL_DEBUG_PYTHON"
        return
    fi

    if [[ -n "$CONDA_BIN" ]]; then
        local resolved
        resolved="$(
            "$CONDA_BIN" run -n "$PAL_DEBUG_ENV" \
                python -c 'import sys; print(sys.executable)' \
                2>/dev/null | tail -n 1
        )" || true

        if [[ -n "$resolved" && -x "$resolved" ]]; then
            printf '%s\n' "$resolved"
            return
        fi
    fi

    local miniconda_candidate="$HOME/miniconda/envs/$PAL_DEBUG_ENV/bin/python"
    local anaconda_candidate="$HOME/anaconda3/envs/$PAL_DEBUG_ENV/bin/python"

    if [[ -x "$miniconda_candidate" ]]; then
        printf '%s\n' "$miniconda_candidate"
    elif [[ -x "$anaconda_candidate" ]]; then
        printf '%s\n' "$anaconda_candidate"
    else
        printf '%s\n' "$miniconda_candidate"
    fi
}

DEBUG_PYTHON="$(resolve_debug_python)"

SPECIMENS=(
    "alpha_two.exe"
    "o3_alpha_two.exe"
    "alpha_four.exe"
    "o3_alpha_four.exe"
    "alpha_corpo.exe"
    "o3_alpha_corpo.exe"
    "PALexec.exe"
    "o3_PALexec.exe"
)

updated=0
skipped=0

printf 'PAL root:          %s\n' "$PAL_ROOT"
printf 'Project root:      %s\n' "$PROJECT_ROOT"
printf 'Conda environment: %s\n' "$PAL_DEBUG_ENV"
printf 'Conda executable:  %s\n' "${CONDA_BIN:-not found}"
printf 'Debug interpreter: %s\n\n' "$DEBUG_PYTHON"

if [[ ! -x "$DEBUG_PYTHON" ]]; then
    printf 'ERROR: pal-debug Python interpreter was not found or is not executable:\n' >&2
    printf '  %s\n\n' "$DEBUG_PYTHON" >&2
    printf 'Create it first:\n' >&2
    printf '  conda create -n %s python=3.12 pip -y\n' "$PAL_DEBUG_ENV" >&2
    printf '  conda run -n %s python -m pip install --upgrade debugpy\n\n' "$PAL_DEBUG_ENV" >&2
    exit 1
fi

for specimen in "${SPECIMENS[@]}"; do
    execute_dir="$PROJECT_ROOT/$specimen/execute"
    vscode_dir="$execute_dir/.vscode"
    settings_file="$vscode_dir/settings.json"
    temp_file="$settings_file.tmp"

    if [[ ! -d "$execute_dir" ]]; then
        printf 'SKIP    %s\n' "$execute_dir"
        skipped=$((skipped + 1))
        continue
    fi

    mkdir -p "$vscode_dir"

    cat > "$temp_file" <<EOF
{
    "python.defaultInterpreterPath": "$DEBUG_PYTHON",
    "python.condaPath": "${CONDA_BIN:-$HOME/miniconda/bin/conda}",
    "python.terminal.activateEnvironment": true,
    "python.terminal.activateEnvInCurrentTerminal": true,

    "python.analysis.extraPaths": [
        "\${workspaceFolder}",
        "\${workspaceFolder}/runtime",
        "\${workspaceFolder}/shims",
        "\${workspaceFolder}/functions"
    ],
    "python.analysis.autoSearchPaths": true,
    "python.analysis.indexing": true,

    "terminal.integrated.cwd": "\${workspaceFolder}",
    "terminal.integrated.env.linux": {
        "PYTHONPATH": "\${workspaceFolder}/runtime:\${workspaceFolder}/shims:\${workspaceFolder}/functions:\${workspaceFolder}",
        "PAL_DEBUG_ENV": "$PAL_DEBUG_ENV",
        "PAL_DEBUG_PYTHON": "$DEBUG_PYTHON"
    }
}
EOF

    mv -f "$temp_file" "$settings_file"
    printf 'WRITE   %s\n' "$settings_file"
    updated=$((updated + 1))
done

printf '\nDone. Updated=%d  Missing/skipped=%d\n' "$updated" "$skipped"

if (( skipped > 0 )); then
    printf 'Missing execute trees were skipped; publish those projects first.\n'
fi

printf '\nOpen a specimen with:\n'
printf '  cd "%s/o3_PALexec.exe/execute" && codium .\n' "$PROJECT_ROOT"
printf '\nIn Codium, open a new integrated terminal and verify:\n'
printf '  python -c "import sys; print(sys.executable)"\n'
