from starlette.requests import Request
from fastapi import HTTPException
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry
from functools import wraps
from typing import Callable
import requests

from .config import AuthConfig
from .cache import CachedGetter
from .endpoints import OidcEndpoints
from .logging import PrintLogger
from .token import Token


class Auth:
    """
    Implements authentication and authorisation.
    """

    config: AuthConfig
    logger: any
    _endpoints: OidcEndpoints
    _certs: CachedGetter

    def __init__(self, config: AuthConfig, logger: any = None):
        """
        Args:
            config: The auth configuration.
        """
        self.config = config
        self.logger = logger if logger is not None else PrintLogger()
        self._endpoints = OidcEndpoints(
            self.config.well_known_endpoint, self.config.request_timeout
        )

    def _resource(self) -> str:
        return self.config.client_id

    def token_certs(self) -> dict:
        return requests.get(
            self._endpoints.certs(), timeout=self.config.request_timeout
        ).json()

    def token_issuer(self) -> str:
        return self._endpoints.issuer()

    def validate_token(self, token: str) -> Token:
        """
        Authorizes the token locally and returns it.
        """
        key_set = KeySet.import_key_set(self.token_certs())
        token = jwt.decode(token, key_set)
        claims_requests = JWTClaimsRegistry(
            iss={"essential": True, "value": self.token_issuer()},
            aud={"essential": True, "value": self._resource()},
        )
        claims_requests.validate(token.claims)
        return Token(token, self._resource())

    def get_token(self, auth_header: str) -> str:
        """
        Raises:
        - If `auth_header` has incorrect format, it will raise an HTTPException.
        """
        # Extract token from "Bearer <token>"
        parts = auth_header.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid Authorization header")

        return parts[1]

    async def validate_token_remotely(self, token: Token):
        """
        Authorizes the token remotely to verify that it has not been revoked.
        """
        raise NotImplementedError()
