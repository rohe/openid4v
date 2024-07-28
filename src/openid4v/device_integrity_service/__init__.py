from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.key_jar import init_key_jar
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext

from openid4v import ServerEntity


class DeviceIntegrityService(ServerEntity):
    name = 'device_integrity_service'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}

    def __init__(self, **kwargs):
        ServerEntity.__init__(self, **kwargs)
        self.oem_keyjar = init_key_jar(key_defs=[{"type": "EC", "crv": "P-256", "use": ["sig"]}])
        self.oem_keyjar.import_jwks(self.oem_keyjar.export_jwks(private=True), self.entity_id)
        self.entity_id = kwargs.get("entity_id", "dummy")

    def get_oem_keyjar(self, *args):
        return self.oem_keyjar

    def get_metadata(self, *args):
        # static ! Should this be done dynamically ?
        return {self.name: self.context.provider_info}
