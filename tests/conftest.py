import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from psp_auth import Auth, AuthConfig


@pytest.fixture
def auth():
    """Test auth"""
    yield Auth(
        config=AuthConfig(
            client_id="test_client",
            well_known_endpoint="http://local/api/user/v1/.well-known/openid-configuration",
        )
    )


@pytest.fixture
def client(app):
    """Test client"""
    with TestClient(app) as client:
        yield client


@pytest.fixture
def app(auth):
    """Test app"""
    app = FastAPI()
    yield app
