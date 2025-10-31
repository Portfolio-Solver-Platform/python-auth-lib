from fastapi import HTTPException
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry
import requests
import httpx
import logging

from .config import AuthConfig
from .endpoints import OidcEndpoints
from .token import Token

logger = logging.getLogger(__name__)


class Auth:
    """
    Implements authentication and authorisation.
    """

    config: AuthConfig
    logger: any
    _endpoints: OidcEndpoints

    def __init__(self, config: AuthConfig):
        """
        Args:
            config: The auth configuration.
        """
        self.config = config
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

    async def _make_introspection_request(self, url: str, data: dict) -> dict:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                url, data, auth=(self.config.client_id, self.config.client_secret)
            )
        if response.status_code == 401:
            logger.error("Invalid client credentials")
        elif response.status_code == 403:
            logger.error("You don't have permission to validate/introspect tokens")

        response.raise_for_status()
        return response.json()

    async def validate_token_remotely(self, token: Token) -> bool:
        """
        Authorizes the token remotely to verify that it has not been revoked.
        This is also called token introspection.
        """
        timeout = httpx.Timeout(10.0, connect=5.0)
        url = self._endpoints.introspection()
        data = {
            "token": token._token,
            "token_type_hint": "access_token",
        }
        response = self._make_introspection_request(url, data)

        if "active" not in response:
            logger.warning("'active' was not in the introspection response")
            return False

        return response.get("active", False) is True
