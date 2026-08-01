#!/usr/bin/env bash
# PAL root environment v2.7. Source from anywhere:
#   source /path/to/PAL/pal_env.sh

_pal_source="${BASH_SOURCE[0]:-$0}"
PAL_ROOT="$(cd -- "$(dirname -- "$_pal_source")" && pwd -P)"
export PAL_ROOT
export PAL_STACK_ROOT="$PAL_ROOT/stack"
export PAL_INTERFACE_ROOT="$PAL_ROOT/interface"
export PAL_PIPELINE_ROOT="$PAL_ROOT/pipeline"
export PAL_SCRIPTS_ROOT="$PAL_ROOT/scripts"
export PAL_SPECIMENS_ROOT="$PAL_ROOT/specimens"
export PAL_SPECIMENS_C_ROOT="$PAL_SPECIMENS_ROOT/c"
export PAL_SPECIMENS_O0_ROOT="$PAL_SPECIMENS_ROOT/o0"
export PAL_SPECIMENS_O3_ROOT="$PAL_SPECIMENS_ROOT/o3"
export PAL_PROJECT_ROOT="$PAL_ROOT/project"

_pal_prepend_unique() {
    local variable="$1" value="$2" current item rebuilt=""
    current="${!variable-}"
    IFS=':' read -r -a _pal_parts <<< "$current"
    rebuilt="$value"
    for item in "${_pal_parts[@]}"; do
        [[ -n "$item" && "$item" != "$value" ]] || continue
        rebuilt+="${rebuilt:+:}$item"
    done
    printf -v "$variable" '%s' "$rebuilt"
    export "$variable"
}

# Flat compatibility plane for legacy absolute imports.
_pal_prepend_unique PYTHONPATH "$PAL_ROOT"
_pal_prepend_unique PYTHONPATH "$PAL_INTERFACE_ROOT"
_pal_prepend_unique PYTHONPATH "$PAL_STACK_ROOT"
_pal_prepend_unique PYTHONPATH "$PAL_PIPELINE_ROOT"
_pal_prepend_unique PATH "$PAL_SCRIPTS_ROOT"
_pal_prepend_unique PATH "$PAL_ROOT"

export PYTHONUNBUFFERED=1
export PAL_ENVIRONMENT_VERSION="pal_root_environment_v2.7"
unset _pal_source
unset -f _pal_prepend_unique
