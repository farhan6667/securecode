#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || { echo "Python 3 is required. Use your approved enterprise package source."; exit 1; }
exec "$PY" "$ROOT/install-global.py"
