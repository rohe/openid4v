from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server.claims import oidc

from oidc4vci import ServerEntity


class Verifier(ServerEntity):
    name = 'wallet_provider'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}
    claims_class = oidc.Claims
