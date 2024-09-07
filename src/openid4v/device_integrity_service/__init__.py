from cryptojwt.key_jar import init_key_jar
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext

from openid4v import ServerEntity
from openid4v.message import DeviceIntegrityServiceMetadata


class DeviceIntegrityService(ServerEntity):
    name = 'device_integrity_service'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}

    def __init__(self, entity_type="device_integrity_service", **kwargs):
        self.entity_type = entity_type
        ServerEntity.__init__(self, **kwargs)
        self.metadata_schema = DeviceIntegrityServiceMetadata
        self.oem_keyjar = init_key_jar(key_defs=[{"type": "EC", "crv": "P-256", "use": ["sig"]}])
        self.oem_keyjar.import_jwks(self.oem_keyjar.export_jwks(private=True), self.entity_id)
        self.entity_id = kwargs.get("entity_id", "dummy")

    def get_oem_keyjar(self, *args):
        return self.oem_keyjar
