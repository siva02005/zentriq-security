"""Shared pytest fixtures for ZENTRIQ tests."""
import os
import sys

# Ensure the zentriq root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Override env before any app imports
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["API_KEY_AUTH_ENABLED"] = "true"
os.environ["ZENTRIQ_API_KEY"] = "zentriq-local-dev-key"
os.environ["RATE_LIMIT_ENABLED"] = "false"

import pytest
from fastapi.testclient import TestClient

# Import AFTER env overrides
from backend.app.db.base import Base
from backend.app.db.session import engine, SessionLocal, get_db, init_db
import backend.app.models.policy  # noqa: F401
import backend.app.models.audit   # noqa: F401
from backend.app.main import app as fastapi_app


@pytest.fixture(autouse=True)
def _reset_db():
    """Recreate all tables before every test for isolation."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    """Provide a raw DB session for direct queries in tests."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client() -> TestClient:
    with TestClient(fastapi_app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture()
def auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer zentriq-local-dev-key"}
