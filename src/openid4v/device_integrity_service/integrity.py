import base64
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt.utils import as_bytes
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.server import Endpoint


class IntegrityAssertion(Endpoint):
    request_cls = Message
    response_cls = Message
    error_msg = ResponseMessage
    request_format = "urlencoded"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "integrity_endpoint"
    name = "integrity"
    endpoint_type = "oauth2"

    def __init__(self, upstream_get: Callable, **kwargs):
        super().__init__(upstream_get, **kwargs)
        self.lifetime = kwargs.get("lifetime", 86400)
        self.sign_alg = kwargs.get("sign_alg", "ES256")

    def process_request(self, request: Optional[Union[Message, dict]] = None, **kwargs) -> Union[Message, dict]:
        _oem_keyjar = self.upstream_get("oem_keyjar")
        # Assume a JWS to be returned
        _jws = JWT(
            _oem_keyjar,
            lifetime=self.lifetime,
            sign_alg=self.sign_alg,
        )
        _jws.with_jti = True
        _jws.iss = self.upstream_get('attribute', "entity_id")

        if not request:
            request = {"dummy_integrity_assertion": "qwerty"}

        _val = _jws.pack(payload=request)
        return {"integrity_assertion": base64.b64encode(as_bytes(_val))}
