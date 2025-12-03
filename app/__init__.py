<<<<<<< HEAD
"""Compatibility shim so the application package lives at project_root/app.

The actual sources are stored under alembic/app because they were bundled with
migration assets. This module exposes them under the expected import path so
commands like `uvicorn app.main:app` and `alembic` continue to work.
"""
from __future__ import annotations

from pathlib import Path
import sys

_ALEMBIC_APP_PATH = Path(__file__).resolve().parent.parent / "alembic" / "app"
if not _ALEMBIC_APP_PATH.exists():
    raise ImportError(
        "Embedded application package not found at alembic/app; cannot expose it as `app`."
    )

_app_path_str = str(_ALEMBIC_APP_PATH)
if _app_path_str not in sys.path:
    sys.path.append(_app_path_str)

__path__ = [_app_path_str]
=======
__all__ = ["__version__"]

__version__ = "0.1.0"

>>>>>>> cd39ac5c7b9a44db3007118c8c18de9e2c893f42
