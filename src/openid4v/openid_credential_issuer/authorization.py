"""The service that talks to the OAuth2 Authorization endpoint."""
import logging

from idpyoidc.message import oauth2
from idpyoidc.server.oauth2 import authorization

from openid4v.message import AuthorizationRequest

LOGGER = logging.getLogger(__name__)


class Authorization(authorization.Authorization):
    """The service that talks to the credential issuers Authorization endpoint."""

    msg_type = AuthorizationRequest
    response_cls = oauth2.AuthorizationResponse
    error_msg = oauth2.AuthorizationErrorResponse

    _supports = {
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment"],
    }

    _callback_path = {
        "redirect_uris": {  # based on response_mode
            "query": "authz_cb",
            "fragment": "authz_im_cb",
            # "form_post": "form"
        }
    }

    def __init__(self, upstream_get, conf=None, **kwargs):
        authorization.Authorization.__init__(self, upstream_get, conf=conf, **kwargs)

    def get_assertion_issuer_info(self, iss):
        pass
