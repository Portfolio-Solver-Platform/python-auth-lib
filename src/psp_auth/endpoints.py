from .cache import CachedGetter
import requests


def _request_metadata(url: str, timeout: tuple[int, int]) -> dict:
    response = requests.get(url, timeout=timeout)
    return response.json()


class OidcEndpoints:
    def __init__(self, well_known_url: str, request_timeout: tuple[int, int]):
        self._well_known_response = CachedGetter(
            lambda: _request_metadata(well_known_url, request_timeout), 60 * 60
        )

    def _well_known(self) -> dict:
        return self._well_known_response.get()

    def update(self):
        self._well_known_response.update()

    def certs(self) -> dict:
        return self._well_known()["jwks_uri"]

    def issuer(self) -> str:
        return self._well_known()["issuer"]

    def introspection(self) -> str:
        return self._well_known()["introspection_endpoint"]
