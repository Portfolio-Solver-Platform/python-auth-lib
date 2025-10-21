import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from psp_auth import Auth, AuthConfig
from psp_auth.fastapi import FastAPIAuth
from psp_auth.testing import TestAuth


@pytest.fixture
def auth(auth_base):
    auth = FastAPIAuth(auth_base)
    yield auth


@pytest.fixture
def tauth(auth_base, monkeypatch):
    test_auth = TestAuth(monkeypatch)
    yield test_auth


@pytest.fixture
def auth_base():
    """Test auth"""
    auth = Auth(
        AuthConfig(
            client_id="test_client",
        )
    )

    yield auth


@pytest.fixture
def client(app):
    """Test client"""
    with TestClient(app) as client:
        yield client


@pytest.fixture
def app(auth):
    """Test app"""
    app = FastAPI()
    auth.add_docs(app)
    yield app
