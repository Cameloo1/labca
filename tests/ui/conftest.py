"""Pytest configuration and fixtures for Playwright UI tests."""

from __future__ import annotations

import os
from typing import Generator

import pytest
from playwright.sync_api import Browser, BrowserContext, Page, Playwright, sync_playwright

# Base URL for the application - can be overridden via environment variable
BASE_URL = os.getenv("TEST_BASE_URL", "http://localhost:8000")


@pytest.fixture(scope="session")
def playwright() -> Generator[Playwright, None, None]:
    """Create a Playwright instance for the test session."""
    with sync_playwright() as playwright_instance:
        yield playwright_instance


@pytest.fixture(scope="session")
def browser_type_launch_args(playwright: Playwright) -> dict:
    """Browser launch arguments."""
    return {
        "headless": os.getenv("PLAYWRIGHT_HEADLESS", "true").lower() == "true",
    }


@pytest.fixture(scope="session")
def browser(playwright: Playwright, browser_type_launch_args: dict) -> Generator[Browser, None, None]:
    """Launch a browser instance for the test session."""
    browser_instance = playwright.chromium.launch(**browser_type_launch_args)
    yield browser_instance
    browser_instance.close()


@pytest.fixture(scope="function")
def context(browser: Browser) -> Generator[BrowserContext, None, None]:
    """Create a new browser context for each test."""
    context_instance = browser.new_context(
        viewport={"width": 1280, "height": 720},
        ignore_https_errors=True,
    )
    yield context_instance
    context_instance.close()


@pytest.fixture(scope="function")
def page(context: BrowserContext) -> Generator[Page, None, None]:
    """Create a new page for each test."""
    page_instance = context.new_page()
    yield page_instance
    page_instance.close()


@pytest.fixture(scope="function")
def base_url() -> str:
    """Return the base URL for the application."""
    return BASE_URL
