#!/usr/bin/env python3
"""API smoke test script for LabCA.

Tests API endpoints using HTTP requests and validates responses.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
ADMIN_SECRET = os.getenv("ADMIN_SECRET") or os.getenv("API_TOKEN_CREATION_SECRET", "CHANGE_ME")
API_TOKEN = os.getenv("API_TOKEN")  # Optional: use existing token


def print_section(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{'=' * 60}")
    print(f">>> {title}")
    print(f"{'=' * 60}")


def test_health() -> dict:
    """Test the health endpoint."""
    print_section("Health Check")
    response = requests.get(f"{BASE_URL}/health", timeout=10)
    response.raise_for_status()
    data = response.json()
    print(json.dumps(data, indent=2))
    return data


def create_api_token() -> str:
    """Create an API token and return the token value."""
    print_section("Create API Token")
    
    payload = {
        "name": "api-test-script-token",
        "permissions": {
            "issue": True,
            "read": True,
            "revoke": False,
        },
    }
    
    headers = {
        "X-LabCA-Admin-Secret": ADMIN_SECRET,
        "Content-Type": "application/json",
    }
    
    response = requests.post(
        f"{BASE_URL}/api/v1/tokens",
        json=payload,
        headers=headers,
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    print(json.dumps(data, indent=2))
    
    token = data.get("token")
    if not token:
        raise ValueError("Token not found in response")
    
    token_prefix = data.get("token_prefix", "unknown")
    print(f"\n✓ API token created (prefix: {token_prefix})")
    return token


def issue_self_signed_certificate(api_token: str) -> dict:
    """Issue a self-signed certificate via API."""
    print_section("Issue Self-Signed Certificate")
    
    payload = {
        "issuer_ca_id": None,
        "common_name": "api.example.local",
        "dns_sans": ["api.example.local"],
        "ip_sans": [],
        "key_algorithm": "RSA",
        "key_size": 2048,
        "hash_algorithm": "SHA256",
        "validity_days": 30,
        "usage_preset": "server_tls",
        "return_private_key": True,
    }
    
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    
    response = requests.post(
        f"{BASE_URL}/api/v1/certificates",
        json=payload,
        headers=headers,
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    print(json.dumps(data, indent=2))
    
    # Validate certificate PEM
    cert_pem = data.get("certificate_pem")
    if not cert_pem:
        raise ValueError("certificate_pem not found in response")
    
    # Parse and validate certificate
    certificate = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    
    # Extract CN
    cn_attrs = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attrs[0].value if cn_attrs else None
    
    # Check validity
    now = datetime.now(timezone.utc)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    
    print(f"\n✓ Certificate issued successfully")
    print(f"  Certificate ID: {data.get('certificate_id')}")
    print(f"  Common Name: {cn}")
    print(f"  Valid from: {not_before}")
    print(f"  Valid until: {not_after}")
    print(f"  Currently valid: {not_before <= now <= not_after}")
    
    if not (not_before <= now <= not_after):
        raise ValueError("Certificate is not currently valid")
    
    return data


def get_certificate(api_token: str, certificate_id: str) -> dict:
    """Retrieve a certificate by ID."""
    print_section(f"Get Certificate (ID: {certificate_id})")
    
    headers = {
        "Authorization": f"Bearer {api_token}",
    }
    
    response = requests.get(
        f"{BASE_URL}/api/v1/certificates/{certificate_id}",
        headers=headers,
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    print(json.dumps(data, indent=2))
    
    # Validate certificate PEM
    cert_pem = data.get("certificate_pem")
    if not cert_pem:
        raise ValueError("certificate_pem not found in GET response")
    
    print(f"\n✓ Certificate retrieved successfully")
    return data


def print_summary(results: dict) -> None:
    """Print a summary of test results."""
    print_section("Test Summary")
    print(json.dumps(results, indent=2, default=str))


def main() -> int:
    """Run all API tests."""
    try:
        results = {
            "base_url": BASE_URL,
            "tests": {},
        }
        
        # Health check
        health_data = test_health()
        results["tests"]["health"] = {"status": "passed", "data": health_data}
        
        # Create or use existing token
        if API_TOKEN:
            print_section("Using Existing API Token")
            api_token = API_TOKEN
            print("✓ Using API_TOKEN from environment")
        else:
            api_token = create_api_token()
            results["tests"]["create_token"] = {"status": "passed"}
        
        # Issue certificate
        cert_data = issue_self_signed_certificate(api_token)
        certificate_id = cert_data.get("certificate_id")
        results["tests"]["issue_certificate"] = {
            "status": "passed",
            "certificate_id": certificate_id,
            "common_name": cert_data.get("metadata", {}).get("common_name"),
        }
        
        # Get certificate
        if certificate_id:
            get_data = get_certificate(api_token, certificate_id)
            results["tests"]["get_certificate"] = {
                "status": "passed",
                "certificate_id": certificate_id,
            }
        
        # Print summary
        print_summary(results)
        
        print("\n" + "=" * 60)
        print(">>> All API tests passed!")
        print("=" * 60)
        
        return 0
        
    except requests.exceptions.ConnectionError as e:
        print(f"\n✗ Connection failed: {e}")
        print(f"  Make sure the LabCA server is running at {BASE_URL}")
        print(f"  Start it with: uvicorn app.main:app --reload")
        return 1
    except requests.exceptions.RequestException as e:
        print(f"\n✗ API request failed: {e}")
        if hasattr(e, "response") and e.response is not None:
            print(f"  Status: {e.response.status_code}")
            try:
                error_detail = e.response.json().get("detail", "")
                print(f"  Response: {e.response.text}")
                if "admin secret" in error_detail.lower() or e.response.status_code == 403:
                    print(f"\n  NOTE: Make sure API_TOKEN_CREATION_SECRET is set in the server environment.")
                    print(f"        You can set it via environment variable or .env file.")
            except Exception:
                pass
        return 1
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

