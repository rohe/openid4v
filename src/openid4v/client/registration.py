from typing import Callable
from typing import Optional
from typing import Union

from fedservice.entity.service import FederationService
from idpyoidc.client.configure import Configuration
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage

from openid4v.message import RegistrationRequest


class RegistrationService(FederationService):
    msg_type = RegistrationRequest
    response_cls = Message
    error_msg = ResponseMessage
    synchronous = True
    service_name = "registration"
    http_method = "POST"

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