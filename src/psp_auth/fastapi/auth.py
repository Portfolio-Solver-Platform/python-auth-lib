from typing import Annotated
from fastapi import Request, Depends
from ..core import Auth
from ..token import Token
from ..user import User


class FastAPIAuth:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def token(self):
        @depends
        def decorator(request: Request) -> Token:
            auth_header = request.headers.get("Authorization")
            token = self._auth.get_token(auth_header)
            return self._auth.validate_token(token)

        return decorator

    def user(self):
        @depends
        def decorator(token: Annotated[Token, Depends(self.token())]) -> User:
            return token.user()

        raise decorator

    def require_role(self, role: str):
        @depends
        def decorator(user: Annotated[User, Depends(self.user())]):
            if not token.user().has_role(role):
                raise HTTPException(status_code=403)

        return decorator
