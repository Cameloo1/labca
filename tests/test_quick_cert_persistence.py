from __future__ import annotations

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.dependencies import get_db
from app.main import app
from app.models import Base, Certificate

client = TestClient(app)


@pytest.fixture()
def session_factory():
    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, future=True)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield SessionLocal
    app.dependency_overrides.clear()


def test_quick_cert_can_be_persisted(session_factory):
    payload = {
        "mode": "simple",
        "common_name": "persist.local",
        "dns_sans": "persist.local",
        "ip_sans": "",
        "organization": "",
        "organizational_unit": "",
        "country": "",
        "state": "",
        "locality": "",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "curve": "P-256",
        "hash_algorithm": "SHA256",
        "validity_days": "30",
        "usage_preset": "server_tls",
        "output_pem_cert": "true",
        "output_pem_key": "true",
        "output_combined_pem": "",
        "output_pfx": "",
        "pfx_password": "",
        "pfx_password_confirm": "",
        "label": "Quick Persist",
        "store_in_labca": "true",
    }

    response = client.post("/quick-cert", data=payload, follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/certificates/")
    assert "source=quick" in location

    detail = client.get(location)
    assert detail.status_code == 200
    assert "View in Issued Certificates" in detail.text

    SessionLocal = session_factory
    with SessionLocal() as session:
        records = session.query(Certificate).all()
        assert len(records) == 1
        record = records[0]
        assert record.common_name == "persist.local"
        assert record.environment_tags == ["quick-cert"]
        assert record.ca_id is None
