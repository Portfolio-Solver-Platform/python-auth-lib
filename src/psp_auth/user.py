class User:
    _claims: dict
    _resource: str

    def __init__(self, _claims: dict, _resource: str):
        self._claims = _claims
        self._resource = _resource

    @property
    def id(self) -> str:
        return self._claims["sub"]

    @property
    def principal_name(self) -> str:
        return self._claims["upn"]

    @property
    def email(self) -> str | None:
        return self._claims.get("email")

    @property
    def is_email_verified(self) -> bool | None:
        return self._claims.get("email_verified")

    @property
    def given_name(self) -> str | None:
        return self._claims.get("given_name")

    @property
    def family_name(self) -> str | None:
        return self._claims.get("family_name")

    @property
    def full_name(self) -> str | None:
        return self._claims.get("name")

    @property
    def username(self) -> str:
        """
        WARNING: Should _not_ be used as an identifier since it may change. Use `User.id` instead.
        """
        return self._claims["preferred_username"]

    def has_resource_role(self, resource: str, role: str) -> bool:
        """
        Args:
            resource: The resource. If `resource == "global"`, then it will check for global roles.
            roles: The roles.

        Returns:
            Whether the user has the `role` on the `resource`.
        """
        return self.has_any_resource_role(resource, [role])

    def has_any_resource_role(self, resource: str, roles: list[str]) -> bool:
        """
        Args:
            resource: The resource. If `resource == "global"`, then it will check for global roles.
            roles: The roles.

        Returns:
            Whether the user has one of the `roles` on the `resource`.
        """

        resource_roles = self._get_resource_roles(resource)
        if resource_roles is None:
            return False

        return any(role in resource_roles for role in roles)

    def has_all_resource_roles(self, resource: str, roles: list[str]) -> bool:
        """
        Args:
            resource: The resource. If `resource == "global"`, then it will check for global roles.
            roles: The roles.

        Returns:
            Whether the user has all the `roles` on the `resource`.
        """

        resource_roles = self._get_resource_roles(resource)
        if resource_roles is None:
            return False

        return all(role in resource_roles for role in roles)

    def _get_resource_roles(self, resource: str) -> dict | None:
        if resource == "global":
            return self._claims["realm_access"]["roles"]

        access = self._claims.get("resource_access")
        if access is None:
            return None

        resource_access = access.get(resource)
        if resource_access is None:
            return None

        resource_roles = resource_access["roles"]
        if resource_roles is None:
            return None

        return resource_roles

    def has_role(self, role: str) -> bool:
        """
        Returns:
            Whether the user has the given role.
        """
        return self.has_resource_role(self._resource, role)

    def has_any_role(self, roles: list[str]) -> bool:
        """
        Returns:
            Whether the user has any of the given roles
        """
        return self.has_any_resource_role(self._resource, roles)

    def has_all_roles(self, roles: list[str]) -> bool:
        """
        Returns:
            Whether the user has all the given roles
        """
        return self.has_all_resource_roles(self._resource, roles)
