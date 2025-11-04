from dataclasses import dataclass


@dataclass
class AuthConfig:
    """Configuration for authentication and authorization.

    Most optional configuration options should be left at default, except `client_secret` if you need to validate a token remotely.

    Attributes:
        client_id: The client ID of this service.
            This is used to namespace the role checks, for example, when you use `Auth.require_role("my-role")`, then it will check for "my-role" under the `resource`.
            This is also used to authorize any calls to the user provider if needed, for example, when you validate a token remotely.
        client_secret: The secret for the client with ID equal to `client_id`.
            This is used to authorize any calls to the user provider if needed, for example, when you validate a token remotely.
        well_known_endpoint: The URL endpoint for OpenID configuration discovery.
            Used to fetch authentication provider metadata.
        request_timeout: Connection and read timeout in seconds as a tuple.
            First value is connection timeout, second is read timeout.
    """

    client_id: str
    client_secret: str = None
    well_known_endpoint: str = (
        "http://user.psp.svc.cluster.local:8080/v1/.well-known/openid-configuration/internal"
    )
    request_timeout: tuple[int, int] = (1, 5)
