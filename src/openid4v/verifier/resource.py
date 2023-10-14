from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.server.oauth2.authorization import Authorization


class Resource(Authorization):
    """The 'resource' endpoint."""

    request_cls = Message
    response_cls = AuthorizationRequest
    error_msg = ResponseMessage
    endpoint_name = "resource_endpoint"  # Used when handling metadata
    synchronous = True
    service_name = "resource"
    default_authn_method = ""
    http_method = "GET"
    request_format = "text"
    name = "resource"  # The name of this endpoint in the server context

    def __init__(self, upstream_get, **kwargs):
        Authorization.__init__(self, upstream_get, **kwargs)
