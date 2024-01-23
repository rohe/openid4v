from typing import Callable
from typing import Optional
from typing import Union

from fedservice.entity.service import FederationService
from idpyoidc.client.configure import Configuration
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage

from openid4v.message import AppAttestationResponse


class AppAttestationService(FederationService):
    msg_type = Message
    response_cls = AppAttestationResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = "app_attestation"
    http_method = "GET"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        if conf is None:
            conf = {}
        FederationService.__init__(self, upstream_get, conf=conf)
        self.iccid = conf.get("iccid", "89470000000000000001")

    def construct(self, request_args=None, **kwargs) -> Message:
        return Message(iccid=self.iccid)