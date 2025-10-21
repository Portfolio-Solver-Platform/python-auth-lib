from typing import Annotated
from fastapi import FastAPI, Request, Depends, HTTPException, Security
from fastapi.security import SecurityScopes
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from ..core import Auth
from ..token import Token
from ..user import User

_security = HTTPBearer(bearerFormat="JWT", description="Access token")

# TODO: Stop using HTTPBearer, and replace with previous implementation of using Auth class.

_SECURITY_SCHEME_NAME = "HTTPBearer"


class FastAPIAuth:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def add_docs(self, app: FastAPI):
        """
        Adds the authentication scheme to the `app` openapi documentation.
        """
        original_schema = app.openapi()
        schema_set = False

        def custom_openapi():
            global schema_set
            if schema_set:
                return app.openapi_schema
            schema_set = True

            schema = original_schema
            schema["components"]["securitySchemes"] = {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "jwt",
                    "description": "JWT access token",
                }
            }

            app.openapi_schema = schema
            return app.openapi_schema

        app.openapi = custom_openapi

    def scope_docs(scopes: list[str]):
        return ({"security": [{_SECURITY_SCHEME_NAME: scopes}]},)

    def token(self):
        def decorator(
            credentials: Annotated[HTTPAuthorizationCredentials, Security(_security)],
        ) -> Token:
            return self._auth.validate_token(credentials.credentials)

        return decorator

    def user(self):
        def decorator(token: Annotated[Token, Depends(self.token())]) -> User:
            return token.user()

        return decorator

    def user_scopes(self):
        def decorator(
            security_scopes: SecurityScopes, user: Annotated[User, Depends(self.user())]
        ):
            if not user.has_all_roles(security_scopes.scopes):
                raise HTTPException(status_code=403)

        return decorator

    def require_roles(self, roles: list[str]):
        def decorator(
            security_scopes: SecurityScopes, user: Annotated[User, Depends(self.user())]
        ):
            if not user.has_all_roles(security_scopes.scopes):
                raise HTTPException(status_code=403)

        return Security(decorator, scopes=roles)
