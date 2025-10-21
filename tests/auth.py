from psp_auth.core import Auth

# TODO: Overwrite token_certs and token_issuer in Auth during testing


def public_private_key_pair() -> tuple[any, any]:
    from joserfc.jwk import RSAKey, KeyParameters
    import json

    # Generate key pair
    private_key = RSAKey.generate_key(2048, auto_kid=True)

    # Export public key as JWK (contains n and e)
    public_jwk = private_key.as_dict(private=False)

    # Create JWKS format (like Keycloak returns)
    jwks = {"keys": [public_jwk]}

    return (jwks, private_key)


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


public_certs, private_key = public_private_key_pair()
issuer = "psp-auth-testing"


def mock_auth(auth: Auth, monkeypatch) -> None:
    def mock_token_certs(self):
        global public_certs
        return public_certs

    def mock_token_issuer(self):
        global issuer
        return issuer

    monkeypatch.setattr(Auth, "token_certs", mock_token_certs)
    monkeypatch.setattr(Auth, "token_issuer", mock_token_issuer)


def gen_token():
    from joserfc import jwt
    from joserfc.jwk import OctKey
    import time

    global private_key, issuer

    # Define your payload
    payload = {
        "iss": issuer,
        "sub": "user123",
        "name": "John Doe",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # expires in 1 hour
    }

    # Create the token
    token = jwt.encode(
        header={"alg": "RS256", "kid": private_key.kid}, claims=payload, key=private_key
    )

    return token
