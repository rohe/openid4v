import json
from typing import Optional

from idpyoidc.message import Message
from idpyoidc.server import Endpoint
from idpyoidc.server.util import execute


class StatusAttestationService(object):

    def __init__(self, upstream_get, conf: Optional[dict] = None):
        self.upstream_get = upstream_get

    def __call__(self, **kwargs) -> Optional[dict]:
        # Verify the challenge
        return


class StatusAttestation(Endpoint):
    request_cls = Message
    response_cls = Message
    request_format = ""
    response_format = "json"
    name = "status_attestation"
    endpoint_type = "oauth2"
    endpoint_name = "status_attestation_endpoint"
    response_content_type = "application/json"

    def __init__(self, upstream_get, conf=None, **kwargs):
        Endpoint.__init__(self, upstream_get, conf=conf, **kwargs)
        if conf and "status_attestation_service" in conf:
            self.challenge_service = execute(conf["status_attestation_service"])
        else:
            self.challenge_service = StatusAttestationService(upstream_get=upstream_get)

    def process_request(self, request=None, **kwargs):
        # _context = self.upstream_get("context")
        # _msg = {"nonce": self.challenge_service()}
        return {"response_msg": "OK"}
