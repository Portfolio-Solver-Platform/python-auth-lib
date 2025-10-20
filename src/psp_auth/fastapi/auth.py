from typing import Annotated
from fastapi import Request, Depends, HTTPException, Security
from fastapi.security import SecurityScopes
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from ..core import Auth
from ..token import Token
from ..user import User

_security = HTTPBearer(description="Access token")


class FastAPIAuth:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

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
