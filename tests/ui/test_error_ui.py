"""UI tests for error pages."""

from __future__ import annotations

import pytest
from playwright.sync_api import Page


def test_404_error_page(page: Page, base_url: str) -> None:
    """Test that 404 errors show a proper error page, not a raw traceback."""
    # Navigate to a non-existent route
    page.goto(f"{base_url}/nonexistent-route")
    page.wait_for_load_state("networkidle")
    
    # Assert error page is shown (not a raw traceback)
    page_content = page.content()
    
    # Should NOT contain Python traceback indicators
    traceback_indicators = [
        "Traceback (most recent call last)",
        "File \"",
        "line ",
        "Exception:",
        "Error:",
        "<class '",
    ]
    
    # Check that it's not a raw error page
    has_traceback = any(indicator in page_content for indicator in traceback_indicators)
    assert not has_traceback, "Page contains traceback, should show user-friendly error page"
    
    # Should contain error page content (404, not found, etc.)
    error_indicators = [
        "404",
        "not found",
        "page not found",
        "error",
    ]
    
    has_error_content = any(
        indicator.lower() in page_content.lower() for indicator in error_indicators
    )
    assert has_error_content, "Page should contain error message"
    
    # Assert a link back to / exists
    home_link = page.get_by_role("link", name="Go to Home")
    assert home_link.is_visible(), "Home link should be visible"
    href = home_link.get_attribute("href") or ""
    assert href == "/" or href.endswith("/")

