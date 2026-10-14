#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python -m black --check app tests alembic && python -m isort --check-only app tests alembic && python -m flake8 app tests alembic && python -m mypy
