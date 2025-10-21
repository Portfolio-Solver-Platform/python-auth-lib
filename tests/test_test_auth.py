from starlette.requests import Request
from typing import Annotated
from fastapi import Depends
from psp_auth import Token


def test_user_info(client, app, auth, tauth):
    given_name = "Jan"
    family_name = "Doener"

    @app.get("/")
    async def get_token(token: Annotated[Token, Depends(auth.token())]):
        user = token.user()

        # assert user.id()
        assert user.given_name() == given_name
        assert user.family_name() == family_name
        assert user.full_name() == f"{given_name} {family_name}"
        # assert user.email()
        # assert user.is_email_verified()
        # assert user.principal_name()
        # assert user.username()

        return "ok"

    response = client.get(
        "/", headers=tauth.auth_header(tauth.gen_token(given_name, family_name))
    )
    assert response.status_code == 200
