from joserfc import jwt
from .user import User


class Token:
    _token: jwt.Token
    _resource: str

    def __init__(self, _token: jwt.Token, _resource: str):
        self._token = _token
        self._resource = _resource

    @property
    def claims(self) -> dict:
        return self._token.claims

    @property
    def issuer(self) -> str:
        return self.claims.get("iss")

    @property
    def user(self) -> User:
        return User(self.claims, self._resource)

    @property
    def expires_at(self) -> int:
        return self.claims["exp"]

    @property
    def issued_at(self) -> int:
        return self.claims["iat"]

    @property
    def token_id(self) -> str:
        """
        Returns the ID of this token.
        """
        # Note that this function is explicitly called "token_id", instead of just "id",
        # to avoid users accidentally using token.id instead of token.user.id.
        return self.claims["jti"]

    @property
    def authorized_party(self) -> str:
        """
        Returns which client requested the token.
        """
        return self.claims["azp"]

    @property
    def audience(self) -> list[str]:
        """
        Returns which clients are authorized to use the token.
        """
        return self.claims["aud"]

    @property
    def allowed_origins(self) -> list[str]:
        return self.claims["allowed_origins"]

    @property
    def scopes(self) -> list[str]:
        scopes = self.claims["scope"]
        if scopes == "":
            return []
        else:
            return self.claims["scope"].split(" ")

    @property
    def session_id(self) -> str:
        return self.claims["sid"]

    @property
    def authentication_class(self) -> str:
        """
        Returns the authentication class used.

        Values have the following meanings:
        "0": Anonymous authentication
        "1": Basic authentication (username/password)
        "2": Multi-factor authentication
        There may be other custom values as well.
        """
        return self.claims["acr"]

    def has_scopes(
        self, scopes: list[str], is_resource_namespaced: bool = True
    ) -> bool:
        token_scopes = self.scopes
        if is_resource_namespaced:
            scopes = map(lambda scope: f"{self._resource}:{scope}", scopes)
        return all(scope in token_scopes for scope in scopes)
