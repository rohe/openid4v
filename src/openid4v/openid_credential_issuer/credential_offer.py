from idpyoidc.server import Endpoint


class CredentialOffer(Endpoint):
    def __init__(self, upstream_get, conf=None, **kwargs):
        Endpoint.__init__(self, upstream_get, conf=conf, **kwargs)
