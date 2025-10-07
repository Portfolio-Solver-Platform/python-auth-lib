from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from joserfc import jwt
from joserfc.jwk import KeySet

from .config import AuthConfig
from .cache import CachedGetter
from .endpoints import OidcEndpoints
from .logging import PrintLogger
from .token import Token

from authlib.integrations.starlette_client import OAuth


def get_signing_cert(url: str) -> dict:
    certs = requests.get(url).json()
    signing_certs = filter(lambda key: key.use == "sig", certs["keys"])
    return signing_certs[0]


class Auth:
    """
    Implements authentication and authorisation.
    """

    config: AuthConfig
    logger: any
    oauth: OAuth
    _endpoints: CachedGetter
    _certs: CachedGetter

    def __init__(self, config: AuthConfig | None = None, logger: any = None):
        """
        If config is None, then it uses a default configuration.
        """
        self.config = config if config is not None else AuthConfig()
        self.logger = logger if logger is not None else PrintLogger()
        self._endpoints = OidcEndpoints(self.config.well_known_endpoint)
        self._signing_cert = CachedGetter(
            lambda: get_signing_cert(self._endpoints.signing_cert()), 60 * 60
        )

        self.oauth = OAuth()
        self.oauth.register(
            name=self.config._client_name,
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            server_metadata_url=self.config.well_known_endpoint,
            client_kwargs={"scope": "openid email profile"},
        )

    def certs(self) -> dict:
        return requests.get(self._endpoints.certs()).json()

    def signing_cert(self) -> dict:
        return self._signing_cert.get()

    def enable(self, app: Starlette, secret_key: str) -> None:
        app.add_middleware(SessionMiddleware, secret_key=secret_key)

    def get_token(self, request: Request) -> jwt.Token:
        """
        Authorizes the token locally and returns it.
        """
        token = self.get_unverified_token(request)
        key_set = KeySet.import_key_set(self.certs())
        return jwt.decode(token, key_set)

    def get_unverified_token(self, request: Request):
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            raise HTTPException(status_code=401, detail="Missing Authorization header")

        # Extract token from "Bearer <token>"
        parts = auth_header.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid Authorization header")

        return parts[1]

    async def get_verified_token(self, request: Request) -> Token:
        """
        Authorizes the token remotely to verify that it has not been revoked and returns it.
        """
        raise NotImplemented()

    def client(self):
        return self.oauth.create_client("psp")

    def require_role(role: str):
        raise NotImplemented()

    def require_permission(permission: str):
        raise NotImplemented()
