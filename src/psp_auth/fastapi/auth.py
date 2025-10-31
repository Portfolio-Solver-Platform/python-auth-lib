from typing import Annotated
from fastapi import FastAPI, Request, Depends, HTTPException, Security
from fastapi.security import SecurityScopes
from ..core import Auth
from ..token import Token
from ..user import User

_SECURITY_SCHEME_NAME = "JWT"


def _security_scheme_docs(scheme_name: str) -> dict:
    return {
        scheme_name: {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "jwt",
            "description": "JWT access token in the Authorization bearer format",
        }
    }


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
            nonlocal schema_set
            if schema_set:
                return app.openapi_schema
            schema_set = True

            nonlocal original_schema
            schema = original_schema
            schema["security"] = {_SECURITY_SCHEME_NAME: []}
            if "components" not in schema:
                schema["components"] = {}
            schema["components"] |= {
                "securitySchemes": _security_scheme_docs(_SECURITY_SCHEME_NAME)
            }

            app.openapi_schema = schema
            return app.openapi_schema

        app.openapi = custom_openapi

    def scope_docs(self, scopes: list[str], is_resource_namespaced: bool = True):
        if is_resource_namespaced:
            scopes = [f"{self._auth.config.client_id}:{scope}" for scope in scopes]

        return {"security": [{_SECURITY_SCHEME_NAME: scopes}]}

    def unvalidated_token(self):
        """
        Dependency for the unvalidated token.
        Generally, you should use the validated token instead with the `FastAPIAuth.token` dependency instead.
        """
        # Note that it is named "unvalidated" instead of "invalidated" because
        # "invalid" means that it has been valid before, and became invalid.
        # "unvalid" instead means that it hasn't been checked whether it is valid.

        def dependency(request: Request) -> str:
            auth_header = request.headers.get("Authorization")
            if auth_header is None:
                raise HTTPException(status_code=401)
            return self._auth.get_token(auth_header)

        return dependency

    def token(self):
        def decorator(
            token: Annotated[str, Depends(self.unvalidated_token())],
        ) -> Token:
            return self._auth.validate_token(token)

        return decorator

    def user(self):
        def decorator(token: Annotated[Token, Depends(self.token())]) -> User:
            return token.user

        return decorator

    def _scopes(self, is_resource_namespaced: bool = True):
        def decorator(
            security_scopes: SecurityScopes,
            token: Annotated[Token, Depends(self.token())],
        ):
            if not token.has_scopes(
                security_scopes.scopes, is_resource_namespaced=is_resource_namespaced
            ):
                raise HTTPException(status_code=403)

        return decorator

    def require_scopes(self, scopes: list[str], is_resource_namespaced: bool = True):
        return Security(
            self._scopes(is_resource_namespaced=is_resource_namespaced), scopes=scopes
        )
