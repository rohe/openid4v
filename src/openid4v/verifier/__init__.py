from cryptojwt.key_jar import init_key_jar
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server.claims import oidc

from openid4v import ServerEntity
from openid4v.message import VerifierServiceMetadata


class Verifier(ServerEntity):
    name = 'verifier'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}
    claims_class = oidc.Claims

    def __init__(self, entity_type: str ="verifier_service", entity_id: str = "", **kwargs):
        self.entity_type = entity_type
        ServerEntity.__init__(self, **kwargs)
        self.metadata_schema = VerifierServiceMetadata
        self.oem_keyjar = init_key_jar(key_defs=[{"type": "EC", "crv": "P-256", "use": ["sig"]}])
        self.oem_keyjar.import_jwks(self.oem_keyjar.export_jwks(private=True), self.entity_id)
        self.entity_id = entity_id
