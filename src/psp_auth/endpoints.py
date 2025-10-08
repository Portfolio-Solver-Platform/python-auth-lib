from .cache import CachedGetter
import requests


def _request_metadata(url: str) -> dict:
    response = requests.get(url)
    return response.json()


class OidcEndpoints:
    _metadata_response: CachedGetter
    token: str
    introspection: str
    userinfo: str
    end_session: str
    jwks_uri: str

    def __init__(self, server_metadata_url: str):
        self._metadata_response = CachedGetter(
            lambda: _request_metadata(server_metadata_url), 60 * 60
        )

    def update(self):
        self._metadata_response.update()

    def certs(self) -> dict:
        return self._metadata_response.get()["jwks_uri"]

    def issuer(self) -> str:
        return self._metadata_response.get()["issuer"]

    def set_from_well_known(self, well_known: any):
        self.token = well_known["token_endpoint"]
        self.introspection = well_known["introspection_endpoint"]
        self.userinfo = well_known["userinfo_endpoint"]
        self.end_session = well_known["end_session_endpoint"]
        self.jwks_uri = well_known["jwks_uri"]
