import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from psp_auth import Auth, AuthConfig
from psp_auth.fastapi import FastAPIAuth
from psp_auth.testing import MockAuth


@pytest.fixture
def fauth(auth):
    """
    FastAPIAuth instance
    """
    return FastAPIAuth(auth)


@pytest.fixture
def mauth(auth_config: AuthConfig, monkeypatch):
    test_auth = MockAuth(auth_config.client_id, monkeypatch)
    return test_auth


@pytest.fixture
def auth_config():
    config = AuthConfig(client_id="test_client", client_secret="some_secret")
    return config


@pytest.fixture
def auth(auth_config: AuthConfig):
    """Test auth"""
    return Auth(auth_config)


@pytest.fixture
def client(app):
    """Test client"""
    with TestClient(app) as client:
        yield client


@pytest.fixture
def app(fauth):
    """Test app"""
    app = FastAPI()
    yield app
