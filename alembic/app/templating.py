"""Centralized Jinja2 template loader.

Every router/error handler previously instantiated its own `Jinja2Templates`
pointed at ``app/templates`` which broke once the package was relocated under
``alembic/app``. This module resolves the real template directory relative to
the source tree and exposes a single cached `Jinja2Templates` instance so all
callers share the same loader.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from starlette.templating import Jinja2Templates


@lru_cache()
def get_templates() -> Jinja2Templates:
    template_dir = Path(__file__).resolve().parent / "templates"
    if not template_dir.exists():
        raise RuntimeError(f"Template directory not found: {template_dir}")
    return Jinja2Templates(directory=str(template_dir))


# Convenience alias so modules can import `templates` directly if desired.
templates = get_templates()
