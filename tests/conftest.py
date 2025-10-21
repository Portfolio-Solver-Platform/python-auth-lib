import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from psp_auth import Auth, AuthConfig
from psp_auth.fastapi import FastAPIAuth
from tests.auth import mock_auth


@pytest.fixture
def auth(auth_base):
    auth = FastAPIAuth(auth_base)
    yield auth


@pytest.fixture
def auth_base(monkeypatch):
    """Test auth"""
    auth = Auth(
        config=AuthConfig(
            client_id="test_client",
            well_known_endpoint="http://local/api/user/v1/.well-known/openid-configuration",
        )
    )

    mock_auth(auth, monkeypatch)

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
