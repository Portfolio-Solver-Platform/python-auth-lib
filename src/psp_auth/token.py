class Token:
    _token: dict

    def __init__(_token: dict):
        self._token = _token

    def userinfo(self) -> any:
        return _token["userinfo"]
