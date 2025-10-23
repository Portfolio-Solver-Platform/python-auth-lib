from typing import Annotated
from fastapi import Depends
from psp_auth import Token
from psp_auth.testing import MockToken


def test_token_info(client, app, fauth, mauth):
    mock_token = MockToken()
    mock_user = mock_token.user

    @app.get("/")
    async def route(token: Annotated[Token, Depends(fauth.token())]):
        assert token.issuer == mock_token.issuer
        assert token.expires_at == mock_token.expires_at
        assert token.issued_at == mock_token.issued_at
        assert token.token_id == mock_token.token_id
        assert token.authorized_party == mock_token.authorized_party
        assert token.audience == (mock_token.audience + [mauth._client_id])
        assert token.allowed_origins == mock_token.allowed_origins
        assert token.scopes == mock_token.scopes
        assert token.session_id == mock_token.session_id
        assert token.authentication_class == mock_token.authentication_class

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
