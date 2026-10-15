"""docs/CONFIGURATION.md must list every Settings field and nothing else."""

from __future__ import annotations

import re
from pathlib import Path

from app.config import Settings

DOC = Path(__file__).resolve().parent.parent / "docs" / "CONFIGURATION.md"
ROW = re.compile(r"^\| `([A-Za-z0-9_]+)` \|", re.MULTILINE)


def _documented() -> set[str]:
    return set(ROW.findall(DOC.read_text(encoding="utf-8")))


def test_every_setting_has_a_row():
    missing = sorted(set(Settings.model_fields) - _documented())
    assert missing == [], f"docs/CONFIGURATION.md has no table row for: {missing}"


def test_every_row_names_a_real_setting():
    stale = sorted(_documented() - set(Settings.model_fields))
    assert stale == [], f"docs/CONFIGURATION.md lists unknown settings: {stale}"
