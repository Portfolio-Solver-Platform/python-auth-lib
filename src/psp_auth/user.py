class User:
    _claims: dict

    def __init__(self, _claims: dict):
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

    def has_role(self, resource: str, role: str) -> bool:
        """
        Returns whether the user has the given role on the given resource.
        If resource == "global", then it will check for global roles.
        """
        if resource == "global":
            return self._has_global_role(role)

        access = self._claims.get("resource_access")
        if access is None:
            return False

        resource_access = access.get(resource)
        if resource_access is None:
            return False

        return role in resource_access["roles"]

    def has_any_role(self, resource: str, roles: list[str]) -> bool:
        return any(self.has_role(resource, role) for role in roles)

    def has_all_roles(self, resource: str, roles: list[str]) -> bool:
        return all(self.has_role(resource, role) for role in roles)

    def _has_global_role(self, role: str) -> bool:
        return role in self._claims["realm_access"]["roles"]
