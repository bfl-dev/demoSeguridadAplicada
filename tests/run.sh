#!/usr/bin/env bash
# Corre las pruebas de la demo en el host. Crea un venv con Flask si hace falta.
set -euo pipefail
cd "$(dirname "$0")/.."

VENV=".venv"
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --disable-pip-version-check Flask
fi

"$VENV/bin/python" tests/test_queue.py
exec "$VENV/bin/python" tests/test_demo.py
