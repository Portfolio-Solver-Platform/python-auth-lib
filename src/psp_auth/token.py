from joserfc import jwt
from .user import User


class Token:
    _token: jwt.Token
    _resource: str

    def __init__(self, _token: jwt.Token, _resource: str):
        self._token = _token
        self._resource = _resource

    def claims(self) -> dict:
        return self._token.claims

    def issuer(self) -> str:
        return self.claims().get("iss")

    def user(self) -> User:
        return User(self.claims(), self._resource)

    def expires_at(self) -> int:
        return self.claims()["exp"]

    def issued_at(self) -> int:
        return self.claims()["iat"]

    def token_id(self) -> str:
        """
        Returns the ID of this token.
        """
        # Note that this function is explicitly called "token_id", instead of just "id",
        # to avoid users accidentally using token.id() instead of token.user().id().
        return self.claims()["jti"]

    def authorized_party(self) -> str:
        """
        Returns which client requested the token.
        """
        return self.claims()["azp"]

    def audience(self) -> list[str]:
        """
        Returns which clients are authorized to use the token.
        """
        return self.claims()["aud"]

    def allowed_origins(self) -> list[str]:
        return self.claims()["allowed_origins"]

    def scopes(self) -> list[str]:
        return self.claims()["scope"].split(" ")

    def session_id(self) -> str:
        return self.claims()["sid"]

    def authentication_class(self) -> str:
        """
        Returns the authentication class used.

        Values have the following meanings:
        "0": Anonymous authentication
        "1": Basic authentication (username/password)
        "2": Multi-factor authentication
        There may be other custom values as well.
        """
        return self.claims()["acr"]
