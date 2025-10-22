from starlette.requests import Request
from typing import Annotated
from fastapi import Depends
from psp_auth import Token


def test_add_docs(client, app, auth):
    assert True


def test_unvalid_token(client, app, auth, mauth):
    token_value = "hellothere"

    @app.get("/")
    async def get_token(token: Annotated[str, Depends(auth.unvalidated_token())]):
        assert token is not None
        assert token == token_value
        return "ok"

    response = client.get("/", headers=mauth.auth_header(token_value))
    assert response.status_code == 200


def test_token(client, app, auth, mauth):
    token_value = mauth.gen_token()

    @app.get("/")
    async def get_token(token: Annotated[Token, Depends(auth.token())]):
        assert token is not None
        assert token.issuer == "psp-auth-testing"
        return "ok"

    response = client.get("/", headers=mauth.auth_header(token_value))
    assert response.status_code == 200


# def test_require_role(client, app, auth):
#     @app.get("/", dependencies=[auth.require_roles(["admin"])])
#     async def valid_token(request: Request):
#         return "ok"
#
#     response = client.get("/")
#     assert response.status_code == 200
