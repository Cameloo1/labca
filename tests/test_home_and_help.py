from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_home_page_loads() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "LabCA" in response.text


def test_help_page_has_sections() -> None:
    response = client.get("/help")
    assert response.status_code == 200
    assert "What is a self-signed certificate?" in response.text


def test_quick_cert_placeholder() -> None:
    response = client.get("/quick-cert")
    assert response.status_code == 200
    assert "Generate a self-signed certificate" in response.text
