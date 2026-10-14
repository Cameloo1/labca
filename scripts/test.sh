#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python -m pytest -m "not ui" --cov=app --cov-report=term-missing --cov-report=xml:coverage.xml "$@"
