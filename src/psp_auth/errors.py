from enum import Enum


class AuthExceptionType(Enum):
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    TOKEN_EXPIRED = "token_expired"


class AuthException(Exception):
    def __init__(self, type: AuthExceptionType, detail: str):
        self.type = type
        self.detail = detail

        super().__init__(self.detail)

    def __str__(self):
        return f"[{self.type}] {self.detail}"
