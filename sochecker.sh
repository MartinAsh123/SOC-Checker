#!/usr/bin/env bash
# Author: Martin. Bash entry point; parsing and process management use Python 3.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
command -v python3 >/dev/null 2>&1 || { echo 'Python 3.9+ is required.' >&2; exit 1; }
exec python3 "$script_dir/soc_checker.py" "$@"
