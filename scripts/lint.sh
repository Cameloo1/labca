#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python -m black --check app tests alembic pki && python -m isort --check-only app tests alembic pki && python -m flake8 app tests alembic pki && python -m mypy && python -m mypy pki/ceremony/ceremony.py
