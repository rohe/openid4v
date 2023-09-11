"""Implements the service that talks to the Access Token endpoint."""
import logging

from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oauth2 import TokenErrorResponse
from idpyoidc.server import Endpoint

from oidc4vci import message

LOGGER = logging.getLogger(__name__)


class Token(Endpoint):
    """The access token service."""

    msg_type = message.AccessTokenRequest
    response_cls = message.AccessTokenResponse
    error_msg = ResponseMessage
    error_cls = TokenErrorResponse
    request_format = "urlencoded"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "token_endpoint"
    name = "token"
    default_capabilities = {"token_endpoint_auth_signing_alg_values_supported": None}
    endpoint_type = "oauth2"
    default_authn_method = "private_key_jwt"

    def __init__(self, upstream_get, conf=None, **kwargs):
        Endpoint.__init__(self, upstream_get, conf=conf, **kwargs)

