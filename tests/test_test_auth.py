from starlette.requests import Request
from typing import Annotated
from fastapi import Depends
from psp_auth import Token
from psp_auth.testing import TestUser


def test_user_info(client, app, auth, tauth):
    test_user = TestUser(given_name="Jan", family_name="Doener")
    # given_name = "Jan"
    # family_name = "Doener"

    @app.get("/")
    async def get_token(token: Annotated[Token, Depends(auth.token())]):
        user = token.user()

        assert user.id() == test_user.id
        assert user.given_name() == test_user.given_name
        assert user.family_name() == test_user.family_name
        assert user.full_name() == f"{test_user.given_name} {test_user.family_name}"
        # assert user.email()
        # assert user.is_email_verified()
        # assert user.principal_name()
        # assert user.username()

        return "ok"

    response = client.get(
        "/", headers=tauth.auth_header(tauth.gen_token(user=test_user))
    )
    assert response.status_code == 200
