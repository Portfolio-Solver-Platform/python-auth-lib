from psp_auth.core import Auth
from joserfc import jwt
from joserfc.jwk import RSAKey, KeyParameters
import time
import pytest
from dataclasses import dataclass


@dataclass
class TestUser:
    id: str = "testuserid"
    given_name: str = "John"
    family_name: str = "Doe"
    username: str = "jandoener123"

    @property
    def full_name(self) -> str:
        return f"{self.given_name} + {self.family_name}"


def _generate_private_key() -> RSAKey:
    return RSAKey.generate_key(2048, auto_kid=True)


def _public_certs_from_key(key: RSAKey) -> dict:
    public_jwk = key.as_dict(private=False)
    return {"keys": [public_jwk]}


class TestAuth:
    def __init__(self, monkeypatch, issuer: str | None = None):
        self._issuer = issuer if issuer is not None else "psp-auth-testing"
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
        return {"Authorization": f"Bearer {token}"}

    def gen_token(self, user: TestUser = TestUser(), token_id: str = "testtokenid"):
        claims = {
            "iss": self._issuer,
            "sub": user.id,
            "name": user.full_name,
            "given_name": user.given_name,
            "family_name": user.family_name,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,  # expires in 1 hour
        }

        # Create the token
        token = jwt.encode(
            header={"alg": "RS256", "kid": self._private_key.kid},
            claims=claims,
            key=self._private_key,
        )

        return token
