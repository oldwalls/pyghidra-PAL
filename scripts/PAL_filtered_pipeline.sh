#!/usr/bin/env bash
# Compatibility entry point. Filtering authority now lives inside root ./pal.
set -euo pipefail
PAL_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec "$PAL_ROOT/pal" pipeline "$@"
