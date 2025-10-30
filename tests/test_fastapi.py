from starlette.requests import Request
from typing import Annotated
from fastapi import Depends, Security, status
from psp_auth import Token, User
from psp_auth.testing import MockToken


def test_unvalid_token(client, app, fauth, mauth):
    token_value = "hellothere"

    @app.get("/")
    async def get_token(token: Annotated[str, Depends(fauth.unvalidated_token())]):
        assert token is not None
        assert token == token_value
        return "ok"

    response = client.get("/", headers=mauth.auth_header(token_value))
    assert response.status_code == status.HTTP_200_OK


def test_token(client, app, fauth, mauth):
    token_value = mauth.issue_token(MockToken())

    @app.get("/")
    async def get_token(token: Annotated[Token, Depends(fauth.token())]):
        assert token is not None
        return "ok"

    response = client.get("/", headers=mauth.auth_header(token_value))
    assert response.status_code == status.HTTP_200_OK


def test_user(client, app, fauth, mauth):
    token_value = mauth.issue_token(MockToken())

    @app.get("/")
    async def get_token(user: Annotated[User, Depends(fauth.user())]):
        assert user is not None
        return "ok"

    response = client.get("/", headers=mauth.auth_header(token_value))
    assert response.status_code == status.HTTP_200_OK


def test_has_required_non_namespaced_scopes(client, app, fauth, mauth):
    scopes = ["testscope1", "scopetest2"]
    token = mauth.issue_token(MockToken(scopes=scopes), is_resource_namespaced=False)

    @app.get(
        "/",
        dependencies=[
            Security(fauth.scopes(is_resource_namespaced=False), scopes=scopes)
        ],
    )
    async def route(request: Request):
        return "ok"

    response = client.get("/", headers=mauth.auth_header(token))
    assert response.status_code == status.HTTP_200_OK


def test_has_required_namespaced_scopes(client, app, auth_config, fauth, mauth):
    resource_scopes = [
        "testscope1",
        "scopetest2",
    ]

    token = mauth.issue_token(
        MockToken(scopes=resource_scopes), is_resource_namespaced=True
    )

    @app.get(
        "/",
        dependencies=[
            Security(fauth.scopes(is_resource_namespaced=True), scopes=resource_scopes)
        ],
    )
    async def route(request: Request):
        return "ok"

    response = client.get("/", headers=mauth.auth_header(token))
    assert response.status_code == status.HTTP_200_OK


def test_has_no_required_scopes(client, app, fauth, mauth):
    scopes = ["testscope1", "scopetest2"]
    token = MockToken()

    @app.get("/", dependencies=[Security(fauth.scopes(), scopes=scopes)])
    async def route(request: Request):
        return "ok"

    response = client.get("/", headers=mauth.auth_header(mauth.issue_token(token)))
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_has_namespaced_scope_but_not_scope_not_namespaced(client, app, fauth, mauth):
    scopes = ["testscope1", "scopetest2"]
    token = mauth.issue_token(MockToken(scopes=scopes), is_resource_namespaced=True)

    @app.get(
        "/",
        dependencies=[
            Security(fauth.scopes(is_resource_namespaced=False), scopes=scopes)
        ],
    )
    async def route(request: Request):
        return "ok"

    response = client.get("/", headers=mauth.auth_header(token))
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_has_some_required_scopes(client, app, fauth, mauth):
    scopes = ["testscope1", "scopetest2"]
    token = MockToken(scopes=[scopes[0]])

    @app.get("/", dependencies=[Security(fauth.scopes(), scopes=scopes)])
    async def route(request: Request):
        return "ok"

    response = client.get("/", headers=mauth.auth_header(mauth.issue_token(token)))
    assert response.status_code == status.HTTP_403_FORBIDDEN
