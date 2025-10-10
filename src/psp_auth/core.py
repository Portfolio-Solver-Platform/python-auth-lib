from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware
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
        self._endpoints = OidcEndpoints(self.config.well_known_endpoint)

    def _resource(self) -> str:
        return self.config.client_id

    def certs(self) -> dict:
        return requests.get(self._endpoints.certs()).json()

    def get_token(self, request: Request) -> Token:
        """
        Authorizes the token locally and returns it.
        """
        token = self.get_unverified_token(request)
        key_set = KeySet.import_key_set(self.certs())
        token = jwt.decode(token, key_set)
        claims_requests = JWTClaimsRegistry(
            iss={"essential": True, "value": self._endpoints.issuer()},
        )
        claims_requests.validate(token.claims)
        return Token(token, self._resource())

    def get_unverified_token(self, request: Request) -> str:
        """
        Raises:
        - If there is no authorization header, then it will raise a HTTPException.
        - If the token has incorrect format, it will raise an HTTPException.
        """
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            raise HTTPException(status_code=401, detail="Missing Authorization header")

        # Extract token from "Bearer <token>"
        parts = auth_header.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid Authorization header")

        return parts[1]

    async def verify_token_remotely(self, token: Token):
        """
        Authorizes the token remotely to verify that it has not been revoked.
        """
        raise NotImplemented()

    def _get_request_from_func(func, *args, **kwargs) -> Request:
        request_arg_name = "request"
        request = kwargs.get(request_arg_name)
        if request is None:
            raise ValueError(
                f"There must be a Request object in the parameters called '{request_arg_name}'"
            )
        elif not isinstance(request, Request):
            raise ValueError(f"The '{request_arg_name}' is not of type Request")

        return request

    def _token_decorator(self, action: Callable[[Token], None]):
        """
        A helper for creating decorators that require a valid `Token`.
        It validates the token before passing it to `action`.

        Requires that the function that it's decorated on has a Request object, named "request", as a parameter.

        Returns:
            A decorator that performs the given `action` on the token in the request.
        """

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                request = Auth._get_request_from_func(func, *args, **kwargs)

                token = self.get_token(request)
                action(token)

                return await func(*args, **kwargs)

            return wrapper

        return decorator

    def require_role(self, role: str):
        """
        Decorator that requires that the access token has the `role`.
        Requires that the function that it's decorated on has a Request object, named "request", as a parameter.

        Args:
            role: The role that the token should have.

        Raises:
            HTTPException: If they do not have the `role`, or something is wrong with the token.
        """

        def check(token: Token) -> None:
            if not token.user().has_role(roles):
                raise HTTPException(status_code=403)

        return self._token_decorator(check)

    def require_any_role(self, roles: list[str]):
        """
        Decorator that requires that the access token has one of the `roles`.
        Requires that the function that it's decorated on has a Request object, named "request", as a parameter.

        Args:
            roles: The roles that the token should have one of.

        Raises:
            HTTPException: If they do not have one of the roles, or something is wrong with the token.
        """

        def check(token: Token) -> None:
            if not token.user().has_any_role(roles):
                raise HTTPException(status_code=403)

        return self._token_decorator(check)

    def require_all_roles(self, roles: list[str]):
        """
        Decorator that requires that the access token has all of the `roles`.
        Requires that the function that it's decorated on has a Request object, named "request", as a parameter.

        Args:
            roles: The roles that the token should have.

        Raises:
            HTTPException: If they do not have the roles, or something is wrong with the token.
        """

        def check(token: Token) -> None:
            if not token.user().has_all_roles(roles):
                raise HTTPException(status_code=403)

        return self._token_decorator(check)

    def require_any_resource_role(self, resource: str, roles: list[str]):
        """
        Decorator that requires that the access token has one of the given roles on the given resource.
        Requires that the function that it's decorated on has a Request object, named "request", as a parameter.

        Args:
            resource: The resource that the token should have a role for. If `resource == "global"`, then it will check for global roles.
            roles: The roles that the token should have one of.

        Raises:
            HTTPException: If they do not have one of the roles, or something is wrong with the token.
        """

        def check(token: Token) -> None:
            if not token.user().has_any_resource_role(resource, roles):
                raise HTTPException(status_code=403)

        return self._token_decorator(check)

    def require_resource_role(self, resource: str, role: str):
        """
        Decorator that requires that the access token has the given role on the given resource.
        Requires that the function that it's decorated on has a Request object, named "request", as a parameter.

        Args:
            resource: The resource that the token should have a role for. If `resource == "global"`, then it will check for global roles.
            role: The role that the token should have.

        Raises:
            HTTPException: If they do not have the role, or something is wrong with the token.
        """

        return self.require_any_role(resource, [role])

    def require_all_resource_roles(self, resource: str, roles: list[str]):
        """
        Decorator that requires that the access token has all of the given roles on the given resource.
        Requires that the function that it's decorated on has a Request object, named "request", as a parameter.

        Args:
            resource: The resource that the token should have roles for. If `resource == "global"`, then it will check for global roles.
            roles: The roles that the token should have.

        Raises:
            HTTPException: If they do not have the roles, or something is wrong with the token.
        """

        def check(token: Token) -> None:
            if not token.user().has_all_roles(resource, roles):
                raise HTTPException(status_code=403)

        return self._token_decorator(check)
