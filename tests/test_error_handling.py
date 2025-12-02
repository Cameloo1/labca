from __future__ import annotations

from fastapi import HTTPException

from app.main import app


@app.get("/force-error")
def trigger_error():
    raise ValueError("boom")


@app.get("/api/v1/force-error")
def trigger_api_error():
    raise HTTPException(status_code=500, detail="boom")


@app.get("/api/v1/force-server-error")
def trigger_api_server_error():
    raise ValueError("kaboom")


def test_html_404_template(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert "doesn't exist" in response.text.lower() or "doesn’t exist" in response.text.lower()


def test_api_404_json(client):
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    payload = response.json()
    assert payload["detail"] == "Not Found"
    assert payload["status"] == 404
    assert payload["error_code"] == "HTTP_404"


def test_html_500_handler(client):
    response = client.get("/force-error")
    assert response.status_code == 500
    assert "Something went wrong" in response.text


def test_api_500_handler(client):
    response = client.get("/api/v1/force-error")
    assert response.status_code == 500
    payload = response.json()
    assert payload["detail"] == "boom"
    assert payload["status"] == 500
    assert payload["error_code"] == "HTTP_500"


def test_api_server_exception_handler(client):
    response = client.get("/api/v1/force-server-error")
    assert response.status_code == 500
    payload = response.json()
    assert payload["detail"] == "Internal server error"
    assert payload["status"] == 500
    assert payload["error_code"] == "SERVER_ERROR"
