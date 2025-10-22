import pytest
import joserfc
from psp_auth.testing import MockToken


def test_wrong_audience(client, app, auth, mauth):
    audience = ["mytestaudience"]
    mock_token = MockToken(audience=audience)
    token = mauth.issue_token(mock_token, add_client_as_audience=False)
    with pytest.raises(joserfc.errors.InvalidClaimError, match="Invalid claim: 'aud'"):
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
