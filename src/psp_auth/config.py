from dataclasses import dataclass


@dataclass
class AuthConfig:
    """Configuration for authentication.

    Most configuration options should be left at default, except `client_id` and `client_secret` if you need to validate a token remotely.

    Attributes:
        client_id: The client ID of this service.
            This is only used if you validate a token remotely.
        client_secret: The secret for the client with ID equal to `client_id`.
            This is only used if you validate a token remotely.
        well_known_endpoint: The URL endpoint for OpenID configuration discovery.
            Used to fetch authentication provider metadata.
        request_timeout: Connection and read timeout in seconds as a tuple.
            First value is connection timeout, second is read timeout.
    """

    client_id: str = None
    client_secret: str = None
    well_known_endpoint: str = (
        "http://user.psp.svc.cluster.local/.well-known/openid-configuration/internal"
    )
    request_timeout: tuple[int, int] = (1, 5)

    _client_name: str = "psp"
