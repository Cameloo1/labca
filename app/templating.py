"""Shared Jinja2 environment so every template can call csrf_input(request)."""

from __future__ import annotations

from fastapi.templating import Jinja2Templates

from app.security.csrf import csrf_input

templates = Jinja2Templates(directory="app/templates")
templates.env.globals["csrf_input"] = csrf_input
