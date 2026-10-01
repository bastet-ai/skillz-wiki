#!/usr/bin/env bash
set -euo pipefail

# The revision-date plugin needs the history for each published page.
if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
  git fetch --unshallow origin
fi

python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -q -r requirements.txt
.venv/bin/python scripts/check_duplicate_alert_ids.py --docs docs
.venv/bin/mkdocs build --strict --clean
