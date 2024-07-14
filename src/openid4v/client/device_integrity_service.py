from typing import Callable
from typing import Optional
from typing import Union

from fedservice.entity.service import FederationService
from idpyoidc.client.configure import Configuration
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage


class IntegrityService(FederationService):
    msg_type = Message
    response_cls = Message
    error_msg = ResponseMessage
    synchronous = True
    service_name = "integrity"
    http_method = "GET"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        if conf is None:
            conf = {}
        FederationService.__init__(self, upstream_get, conf=conf)

    def construct(self, request_args=None, **kwargs) -> Message:
        if request_args is None:
            return Message()
        elif isinstance(request_args, dict):
            return Message(**request_args)
        else:
            raise ValueError(f"Request arguments must be in the form of a dictionary not {request_args}")


class KeyAttestationService(FederationService):
    msg_type = Message
    response_cls = Message
    error_msg = ResponseMessage
    synchronous = True
    service_name = "key_attestation"
    http_method = "GET"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        if conf is None:
            conf = {}
        FederationService.__init__(self, upstream_get, conf=conf)

    def construct(self, request_args=None, **kwargs) -> Message:
        if request_args is None:
            return Message()
        elif isinstance(request_args, dict):
            return Message(**request_args)
        else:
            raise ValueError(f"Request arguments must be in the form of a dictionary not {request_args}")
