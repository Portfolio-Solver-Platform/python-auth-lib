import pytest
from psp_auth.testing import MockToken
from psp_auth.errors import AuthException, AuthExceptionType


def test_wrong_audience(client, app, auth, mauth):
    audience = ["mytestaudience"]
    mock_token = MockToken(audience=audience)
    token = mauth.issue_token(mock_token, add_client_as_audience=False)
    with pytest.raises(
        AuthException,
        match="The audience",
        check=lambda e: e.type == AuthExceptionType.FORBIDDEN,
    ):
        auth.validate_token(token)


def test_correct_audience(client, app, auth, mauth):
    mock_token = MockToken()
    token = mauth.issue_token(mock_token, add_client_as_audience=True)
    assert auth.validate_token(token)


def test_multiple_correct_audiences(client, app, auth, mauth):
    """
    Tests for multiple audiences, where one of them is the correct one.
    """
    audience = ["mytestaudience"]
    mock_token = MockToken(audience=audience)
    token = mauth.issue_token(mock_token, add_client_as_audience=True)
    assert auth.validate_token(token)


async def test_remote_token_validation_require_secret(client, app, auth, mauth):
    auth.config.client_secret = None
    token = mauth.issue_token(MockToken())

    with pytest.raises(ValueError, match="Client secret is required"):
        await auth.validate_token_remotely(token)
