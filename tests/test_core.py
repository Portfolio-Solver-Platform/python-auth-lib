from psp_auth import Auth

from starlette.requests import Request
from authlib.integrations.starlette_client.apps import StarletteOAuth2App


def test_get_client(client, app, auth):
    @app.get("/")
    async def get_client(request: Request):
        client = auth.client()
        assert type(client) is StarletteOAuth2App
        return "ok"

    response = client.get("/")
    assert response.status_code == 200
