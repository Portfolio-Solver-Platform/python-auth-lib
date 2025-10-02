class AuthConfig:
    well_known_endpoint: str = "http://user.psp.svc.cluster.local/.well-known/intra"
    request_timeout: tuple[int, int] = (1, 5)
    client_id: str = ""
    client_secret: str = ""
    _client_name: str = "psp"
