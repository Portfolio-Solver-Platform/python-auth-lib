class Auth:
    """
    Implements authentication and authorisation.
    """

    def __init__(self):
        self._update_endpoints()

    def _update_endpoints(self):
        raise NotImplemented()

    def has_role(role: str):
        raise NotImplemented()

    def require_role(role: str):
        raise NotImplemented()

    def has_permission(permission: str):
        raise NotImplemented()

    def require_permission(permission: str):
        raise NotImplemented()

    def get_token():
        raise NotImplemented()

    def get_user_id():
        raise NotImplemented()

    def verify_token(token):
        raise NotImplemented()
