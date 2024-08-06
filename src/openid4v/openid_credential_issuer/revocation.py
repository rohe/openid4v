import json
from typing import Optional

from idpyoidc.message import Message
from idpyoidc.server import Endpoint
from idpyoidc.server.util import execute


class RevocationService(object):

    def __init__(self, upstream_get, conf: Optional[dict] = None):
        self.upstream_get = upstream_get

    def __call__(self, **kwargs) -> Optional[dict]:
        # Verify the challenge
        return


class Revocation(Endpoint):
    request_cls = Message
    response_cls = Message
    request_format = ""
    response_format = "json"
    name = "revocation"
    endpoint_type = "oauth2"
    endpoint_name = "revocation_endpoint"
    response_content_type = "application/json"

    def __init__(self, upstream_get, conf=None, **kwargs):
        Endpoint.__init__(self, upstream_get, conf=conf, **kwargs)
        if conf and "challenge_service" in conf:
            self.challenge_service = execute(conf["challenge_service"])
        else:
            self.challenge_service = RevocationService(upstream_get=upstream_get)

    def process_request(self, request=None, **kwargs):
        # _context = self.upstream_get("context")
        # _msg = {"nonce": self.challenge_service()}
        return {"response_msg": "OK"}
