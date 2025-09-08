#!/bin/bash
SCRIPT_DIR="$(dirname "$(realpath "$0")")"
SCRIPT_NAME="$(basename "$(realpath "$0")")"
ENTRYPOINT="${SCRIPT_DIR}/${SCRIPT_NAME%.sh}.py"
VENV_FILE="${SCRIPT_DIR}/.venv_path"

# Load and export all vars from .env if it exists
[ -f "${SCRIPT_DIR}/.env" ] && set -a && source "${SCRIPT_DIR}/.env" && set +a

# Generate or validate venv path cache
if [ ! -f "${VENV_FILE}" ] || [ ! -x "$(cat "${VENV_FILE}")/bin/python" ]; then
  export PIPENV_PIPFILE="${SCRIPT_DIR}/Pipfile"
  pipenv -q --venv > "${VENV_FILE}"
fi

VENV_PATH=$(<"${VENV_FILE}")

# Run the script using the venv's Python interpreter
exec "${VENV_PATH}/bin/python" "$ENTRYPOINT" "$@"
