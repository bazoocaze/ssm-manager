#!/bin/bash
SCRIPT_DIR="$(dirname "$(realpath "$0")")"
SCRIPT_NAME="$(basename "$(realpath "$0")")"
ENTRYPOINT="${SCRIPT_DIR}/${SCRIPT_NAME%.sh}.py"

PYTHON="python3"
if ! which -s "$PYTHON" ; then
  PYTHON="python"
fi

# Load and export all vars from .env if it exists
[ -f "${SCRIPT_DIR}/.env" ] && set -a && source "${SCRIPT_DIR}/.env" && set +a

# Run the script
exec "${PYTHON}" "$ENTRYPOINT" "$@"
