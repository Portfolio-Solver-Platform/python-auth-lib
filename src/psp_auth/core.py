from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request

from .config import AuthConfig
from .endpoints import OidcEndpoints
from .logging import PrintLogger
from .token import Token

from authlib.integrations.starlette_client import OAuth


class Auth:
    """
    Implements authentication and authorisation.
    """

    config: AuthConfig
    logger: any
    oauth: OAuth

    def __init__(self, config: AuthConfig | None = None, logger: any = None):
        """
        If config is None, then it uses a default configuration.
        """
        self.config = config if config is not None else AuthConfig()
        self.logger = logger if logger is not None else PrintLogger()

        self.oauth = OAuth()
        self.oauth.register(
            name=self.config._client_name,
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            server_metadata_url=self.config.well_known_endpoint,
            client_kwargs={"scope": "openid email profile"},
        )

    def enable(self, app: Starlette, secret_key: str) -> None:
        app.add_middleware(SessionMiddleware, secret_key=secret_key)

    async def get_token(self, request: Request) -> Token:
        """
        Authorizes the token and returns it.
        """
        return await self.client().authorize_access_token(request)

    def client(self):
        return oauth.create_client("psp")

    def _update_endpoints(self):
        response = requests.get(
            self.config.well_known_endpoint, timeout=self.config.request_timeout
        )
        if response.status_code != 200:
            logger.error("Failed to get .well-known")
            return
        self.endpoints.set_from_well_known(response.json())

    def has_role(role: str):
        raise NotImplemented()

    def require_role(role: str):
        raise NotImplemented()

    def has_permission(permission: str):
        raise NotImplemented()

    def require_permission(permission: str):
        raise NotImplemented()

    def get_token():
        raise NotImplemented()

    def get_user_id():
        raise NotImplemented()

    def verify_token(token):
        raise NotImplemented()
