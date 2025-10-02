class OidcEndpoints:
    token: str
    introspection: str
    userinfo: str
    end_session: str
    jwks_uri: str

    def set_from_well_known(self, well_known: any):
        self.token = well_known["token_endpoint"]
        self.introspection = well_known["introspection_endpoint"]
        self.userinfo = well_known["userinfo_endpoint"]
        self.end_session = well_known["end_session_endpoint"]
        self.jwks_uri = well_known["jwks_uri"]
