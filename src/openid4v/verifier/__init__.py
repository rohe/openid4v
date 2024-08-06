from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server.claims import oidc

from openid4v import ServerEntity


class Verifier(ServerEntity):
    name = 'verifier'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}
    claims_class = oidc.Claims
