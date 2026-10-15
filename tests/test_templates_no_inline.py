"""Templates must work under a CSP with no inline script or style."""

from __future__ import annotations

import re
from pathlib import Path

TEMPLATES = sorted(Path("app/templates").rglob("*.html"))


def test_templates_found():
    assert len(TEMPLATES) > 20


def test_no_inline_script_style_or_cdn():
    for path in TEMPLATES:
        text = path.read_text(encoding="utf-8")
        assert "<script" not in text, path
        assert "cdn.tailwindcss.com" not in text, path
        assert ' style="' not in text, path
        assert not re.search(r" on[a-z]+=\"", text), path


def test_base_links_local_stylesheet():
    base = Path("app/templates/base.html").read_text(encoding="utf-8")
    assert '<link rel="stylesheet" href="/static/css/app.css">' in base


def test_every_post_form_has_csrf_input():
    seen = 0
    for path in TEMPLATES:
        text = path.read_text(encoding="utf-8")
        # Any attribute order and case: <form action=... METHOD='post'> counts too.
        for match in re.finditer(r"""<form\b[^>]*\bmethod=["']?post\b""", text, re.IGNORECASE):
            seen += 1
            end = text.find("</form>", match.start())
            assert end != -1, path
            assert "csrf_input(request)" in text[match.start() : end], path
    assert seen >= 10
