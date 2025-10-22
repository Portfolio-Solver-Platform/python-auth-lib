from starlette.requests import Request
from typing import Annotated
from fastapi import Depends
from psp_auth import Token
from psp_auth.testing import MockToken, MockUser


def test_user_info(client, app, auth, mauth):
    mock_user = MockUser(given_name="Jan", family_name="Doener")
    mock_token = MockToken(user=mock_user)

    @app.get("/")
    async def get_token(token: Annotated[Token, Depends(auth.token())]):
        user = token.user

        assert user.id == mock_user.id
        assert user.given_name == mock_user.given_name
        assert user.family_name == mock_user.family_name
        assert user.full_name == mock_user.full_name
        assert user.username == mock_user.username
        assert user.email == mock_user.email
        assert user.is_email_verified == mock_user.is_email_verified
        assert user.principal_name == mock_user.principal_name

        return "ok"

    response = client.get("/", headers=mauth.auth_header(mauth.issue_token(mock_token)))
    assert response.status_code == 200
