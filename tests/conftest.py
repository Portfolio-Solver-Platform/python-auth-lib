import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from psp_auth import Auth


@pytest.fixture
def auth():
    """Test auth"""
    yield Auth()


@pytest.fixture
def client(app):
    """Test client"""
    with TestClient(app) as client:
        yield client


@pytest.fixture
def app(auth):
    """Test app"""
    app = FastAPI()
    auth.enable(app, "secret-key")
    yield app
