"""UI tests for home page and navigation."""

from __future__ import annotations

import pytest
from playwright.sync_api import Page

pytestmark = pytest.mark.ui


def test_home_page_title_and_links(page: Page, base_url: str) -> None:
    """Test that the home page loads with correct title and navigation links."""
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")

    # Assert page title contains "LabCA"
    assert "LabCA" in page.title()

    # Assert "Quick Certificate" link exists and goes to /quick-cert
    quick_cert_link = page.get_by_role("link", name="Generate a Quick Certificate")
    assert quick_cert_link.is_visible()
    href = quick_cert_link.get_attribute("href") or ""
    assert "/quick-cert" in href

    # Assert "Help & Examples" link exists and goes to /help
    help_link = page.get_by_role("link", name="View Help & Examples")
    assert help_link.is_visible()
    help_href = help_link.get_attribute("href") or ""
    assert "/help" in help_href


def test_help_page_content(page: Page, base_url: str) -> None:
    """Test that the help page loads with expected content."""
    page.goto(f"{base_url}/help")
    page.wait_for_load_state("networkidle")

    # Assert page title contains "LabCA" or "Help"
    title = page.title()
    assert "LabCA" in title or "Help" in title or "help" in title.lower()

    # Assert heading "What is a self-signed certificate" exists
    heading = page.get_by_role("heading", name="What is a self-signed certificate?")
    assert heading.is_visible(), "Expected heading 'What is a self-signed certificate?' not found"
