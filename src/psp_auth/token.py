from joserfc import jwt
from dataclasses import dataclass


class Token:
    _token: jwt.Token

    def __init__(_token: jwt.Token):
        self._token = _token

    def claims(self) -> dict:
        return self._token.claims

    def issuer(self) -> str:
        return self.claims().get("iss")

    def user(self) -> str:
        return User(self.claims())

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


class User:
    _claims: dict

    def __init__(_claims: dict):
        self._claims = _claims

    def id(self) -> str:
        return self._claims["sub"]

    def principal_name(self) -> str:
        return self._claims["upn"]

    def email(self) -> str | None:
        return self._claims.get("email")

    def is_email_verified(self) -> bool | None:
        return self._claims.get("email_verified")

    def given_name(self) -> str | None:
        return self._claims.get("given_name")

    def family_name(self) -> str | None:
        return self._claims.get("family_name")

    def full_name(self) -> str | None:
        return self._claims.get("name")

    def username(self) -> str:
        """
        WARNING: Should _not_ be used as an identifier since it may change. Use `User.id` instead.
        """
        return self._claims["preferred_username"]

    def has_role(self, role: tuple[str, str]) -> bool:
        client, role = role
        if client == "global":
            return self.has_global_role(role)
        return self.has_client_role(client, role)

    def has_any_role(self, roles: list[tuple[str, str]]) -> bool:
        return any(self.has_role(role) for role in roles)

    def has_all_roles(self, roles: list[tuple[str, str]]) -> bool:
        return all(self.has_role(role) for role in roles)

    def has_global_role(self, role: str) -> bool:
        return role in self._claims["realm_access"]["roles"]

    def has_client_role(self, client: str, role: str) -> bool:
        resource_access = self._claims.get("resource_access")
        if resource_access is None:
            return False

        client_access = resource_access.get(client)
        if client_access is None:
            return False

        return role in client_access["roles"]

    def has_permission(self) -> bool:
        raise NotImplemented()
