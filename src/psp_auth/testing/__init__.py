from psp_auth.core import Auth
from joserfc import jwt
from joserfc.jwk import RSAKey
import time
from dataclasses import dataclass, field

DEFAULT_ISSUER = "https://auth.testing.psp.com/realms/psp"


@dataclass
class MockUser:
    id: str = "057144ec-9588-4cc8-a9d7-3b3a040080b5"
    given_name: str = "John"
    family_name: str = "Doe"
    username: str = "jandoener123"
    email: str = "john@doe.com"
    is_email_verified: bool = True
    principal_name: str = "john@doe.com"

    roles: list[str] = field(default_factory=list)

    """
    Resource roles should be in the form: resource -> list[roles].
    You can add global roles by defining roles for `resource == "global"`.
    """
    resource_roles: dict[str, list[str]] = field(default_factory=dict)

    @property
    def full_name(self) -> str:
        return f"{self.given_name} {self.family_name}"

    def _claims(self, default_resource: str) -> dict[str, any]:
        claims = {
            "sub": self.id,
            "upn": self.principal_name,
            "email": self.email,
            "email_verified": self.is_email_verified,
            "given_name": self.given_name,
            "family_name": self.family_name,
            "name": self.full_name,
            "preferred_username": self.username,
        }
        claims |= self._role_claims(default_resource)
        return claims

    def _role_claims(self, default_resource: str) -> dict[str, any]:
        def roles_dict(roles: list[str]) -> dict[str, list[str]]:
            return {"roles": roles}

        claims = {}

        global_roles = self.resource_roles.pop("global", None)
        if global_roles is not None:
            claims["realm_access"] = roles_dict(global_roles)

        resource_access = {}
        if self.roles:
            resource_access[default_resource] = roles_dict(self.roles)

        if self.resource_roles:
            for resource, roles in self.resource_roles:
                resource_access[resource] = roles_dict(roles)

        claims["resource_access"] = resource_access

        return claims


@dataclass
class MockToken:
    issuer: str = DEFAULT_ISSUER
    user: MockUser = field(default_factory=MockUser)
    scopes: list[str] = field(default_factory=list)
    issued_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = field(
        default_factory=lambda: int(time.time()) + 3600
    )  # Expires in 1 hour
    token_id: int = "onrtrt:00b4dfb6-ad71-24de-9db5-dc5e9383c14f"
    authorized_party: str = "users"
    audience: list[str] = field(default_factory=list)
    session_id: str = "4a31869d-dc4a-4727-b28a-be5c92a16f4b"
    """
    The security class at which the user has authenticated themselves.

    Values have the following meanings:
    "0": Anonymous authentication
    "1": Basic authentication (username/password)
    "2": Multi-factor authentication
    There may be other custom values as well.
    """
    authentication_class: str = "2"
    allowed_origins: list[str] = field(default_factory=lambda: ["/*"])

    def _claims(self, default_resource: str, extra_audience: list[str] = []) -> dict:
        claims = {
            "iss": self.issuer,
            "exp": self.expires_at,
            "iat": self.issued_at,
            "jti": self.token_id,
            "azp": self.authorized_party,
            "typ": "Bearer",
            "aud": (self.audience if self.audience else []) + extra_audience,
            "scope": " ".join(self.scopes if self.scopes else []),
            "sid": self.session_id,
            "acr": self.authentication_class,
            "allowed_origins": self.allowed_origins,
        }
        claims |= self.user._claims(default_resource)
        return claims


def _generate_private_key() -> RSAKey:
    return RSAKey.generate_key(2048, auto_kid=True)


def _public_certs_from_key(key: RSAKey) -> dict:
    public_jwk = key.as_dict(private=False)
    return {"keys": [public_jwk]}


class MockAuth:
    def __init__(self, client_id: str, monkeypatch, issuer: str = DEFAULT_ISSUER):
        self._issuer = issuer
        self._client_id = client_id
        self._private_key = _generate_private_key()
        self._public_certs = _public_certs_from_key(self._private_key)
        self._mock_auth(monkeypatch)

    def _mock_auth(self, monkeypatch) -> None:
        public_certs = self._public_certs
        issuer = self._issuer

        def mock_token_certs(self):
            nonlocal public_certs
            return public_certs

        def mock_token_issuer(self):
            nonlocal issuer
            return issuer

        monkeypatch.setattr(Auth, "token_certs", mock_token_certs)
        monkeypatch.setattr(Auth, "token_issuer", mock_token_issuer)

    def auth_header(self, token: str) -> dict:
        return {"Authorization": self.auth_header_value(token)}

    def auth_header_value(self, token: str) -> dict:
        return f"Bearer {token}"

    def issue_token(self, token: MockToken, add_client_as_audience: bool = True):
        token = jwt.encode(
            header={"alg": "RS256", "kid": self._private_key.kid, "typ": "JWT"},
            claims=token._claims(
                self._client_id,
                extra_audience=[self._client_id] if add_client_as_audience else [],
            ),
            key=self._private_key,
        )

        return token
