from typing import Annotated
from fastapi import Request, Depends, HTTPException, Security
from fastapi.security import SecurityScopes
from ..core import Auth
from ..token import Token
from ..user import User


class FastAPIAuth:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def token(self):
        def decorator(request: Request) -> Token:
            auth_header = request.headers.get("Authorization")
            token = self._auth.get_token(auth_header)
            return self._auth.validate_token(token)

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
