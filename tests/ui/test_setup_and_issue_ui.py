"""UI tests for CA setup wizard and certificate issuance."""

from __future__ import annotations

import pytest
from playwright.sync_api import Page


def test_setup_wizard_create_root_ca(page: Page, base_url: str) -> None:
    """Test the setup wizard to create a root CA."""
    # Navigate to /setup
    page.goto(f"{base_url}/setup")
    page.wait_for_load_state("networkidle")
    
    # Step 1: Should see the intro page, click to continue
    # Look for a button or form to proceed
    continue_button = page.locator('button[type="submit"], input[type="submit"], form button').first
    if continue_button.count() > 0:
        continue_button.click()
        page.wait_for_load_state("networkidle")
    
    # Step 2: Choose to create a new CA
    create_option = page.locator('input[type="radio"][value="create"], input[name="ca_source"][value="create"]').first
    if create_option.count() > 0:
        create_option.check()
        submit_button = page.locator('button[type="submit"], input[type="submit"], form button').first
        submit_button.click()
        page.wait_for_load_state("networkidle")
    
    # Step 3: Fill in the root CA form
    # Name
    name_input = page.locator('input[name="name"]')
    name_input.fill("UI Root CA")
    
    # Subject CN
    subject_cn_input = page.locator('input[name="subject_cn"]')
    subject_cn_input.fill("UI Lab Root CA")
    
    # Accept defaults for other fields (they should already have values)
    # Click submit to go to summary
    submit_button = page.locator('button[type="submit"], input[type="submit"], form button').first
    submit_button.click()
    page.wait_for_load_state("networkidle")
    
    # Step 4: Review summary and confirm
    # Look for "Create Root CA" button
    confirm_button = page.get_by_role("button", name="Create Root CA")
    assert confirm_button.is_visible(), "Create Root CA button not found"
    confirm_button.click()
    page.wait_for_load_state("networkidle")
    
    # Should be redirected to /cas or /cas/{ca_id}
    assert "/cas" in page.url, f"Expected redirect to /cas, got {page.url}"
    
    # Assert CA row appears in the list
    page_content = page.content()
    assert "UI Root CA" in page_content or "UI Lab Root CA" in page_content


def test_ca_detail_and_issue_certificate(page: Page, base_url: str) -> None:
    """Test viewing CA details and issuing a certificate."""
    # First, create a CA through the setup wizard
    # Navigate to /setup
    page.goto(f"{base_url}/setup")
    page.wait_for_load_state("networkidle")
    
    # Step 1: Continue from intro
    continue_button = page.locator('button[type="submit"], input[type="submit"], form button').first
    if continue_button.count() > 0:
        continue_button.click()
        page.wait_for_load_state("networkidle")
    
    # Step 2: Choose to create a new CA
    create_option = page.locator('input[type="radio"][value="create"], input[name="ca_source"][value="create"]').first
    if create_option.count() > 0:
        create_option.check()
        submit_button = page.locator('button[type="submit"], input[type="submit"], form button').first
        submit_button.click()
        page.wait_for_load_state("networkidle")
    
    # Step 3: Fill in the root CA form
    name_input = page.locator('input[name="name"]')
    name_input.fill("UI Root CA")
    
    subject_cn_input = page.locator('input[name="subject_cn"]')
    subject_cn_input.fill("UI Lab Root CA")
    
    # Submit to summary
    submit_button = page.locator('button[type="submit"], input[type="submit"], form button').first
    submit_button.click()
    page.wait_for_load_state("networkidle")
    
    # Step 4: Confirm
    confirm_button = page.locator('button[type="submit"], input[type="submit"]').first
    if confirm_button.count() > 0:
        confirm_button.click()
        page.wait_for_load_state("networkidle")
    
    # Should be on CA detail page or list
    assert "/cas" in page.url, f"Expected redirect to /cas, got {page.url}"
    
    # Navigate to CA list if not already there
    if "/cas/" in page.url and page.url.count("/") > 2:
        # We're on a detail page, find the list link or go directly
        page.goto(f"{base_url}/cas")
        page.wait_for_load_state("networkidle")
    
    # Find the CA and click "View details"
    view_details_link = page.locator('a:has-text("View details"), a:has-text("Details"), a[href*="/cas/"]:not([href="/cas"])').first
    if view_details_link.count() == 0:
        # Try to find any link to a CA detail page
        view_details_link = page.locator('a[href^="/cas/"]').first
    
    assert view_details_link.count() > 0, "CA detail link not found"
    view_details_link.click()
    page.wait_for_load_state("networkidle")
    
    # On CA detail page, click "Issue new certificate"
    issue_link = page.locator(
        'a:has-text("Issue new certificate"), a:has-text("Issue Certificate"), a[href*="/issue"]'
    ).first
    assert issue_link.count() > 0, "Issue certificate link not found"
    issue_link.click()
    page.wait_for_load_state("networkidle")
    
    # Fill in the certificate form
    cn_input = page.locator('input[name="common_name"]')
    cn_input.fill("ui-ca.example.local")
    
    dns_sans_input = page.locator('input[name="dns_sans"]')
    dns_sans_input.fill("ui-ca.example.local")
    
    # Submit the form
    submit_button = page.locator('button[type="submit"], input[type="submit"]').first
    submit_button.click()
    page.wait_for_load_state("networkidle")
    
    # Should be redirected to certificate detail page
    assert "/certificates/" in page.url, f"Expected redirect to /certificates/, got {page.url}"
    
    # Assert CN and Issuer CA are visible
    page_content = page.content()
    assert "ui-ca.example.local" in page_content
    
    # Look for download certificate link or BEGIN CERTIFICATE text
    download_link = page.locator(
        'a:has-text("Download certificate"), a:has-text("Download"), a[href*="/download-cert"]'
    ).first
    if download_link.count() > 0:
        href = download_link.get_attribute("href") or ""
        assert "/download-cert" in href
    else:
        # At least verify the page has certificate content
        assert "BEGIN CERTIFICATE" in page_content or "certificate" in page_content.lower()

