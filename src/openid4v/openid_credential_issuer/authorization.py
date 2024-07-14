"""The service that answers at the OAuth2 Authorization endpoint."""
import logging

from idpyoidc import metadata
from idpyoidc.message import oauth2
from idpyoidc.server.oauth2 import authorization
from idpyoidc.server.util import execute

from openid4v.message import AuthorizationRequest

LOGGER = logging.getLogger(__name__)


class Authorization(authorization.Authorization):
    """The service that talks to the credential issuers Authorization endpoint."""

    request_cls = AuthorizationRequest
    response_cls = oauth2.AuthorizationResponse
    error_msg = oauth2.AuthorizationErrorResponse
    service_name = "authorization"
    name = "authorization"

    _supports = {
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment"],
        "acr_values_supported": [],
        "scopes_supported": [],
        "authorization_signing_alg_values_supported": metadata.get_signing_algs(),
        "request_object_signing_alg_values_supported": metadata.get_signing_algs()
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

        auto_req_conf = kwargs.get("automatic_registration")
        if auto_req_conf:
            self.automatic_registration = execute(auto_req_conf, upstream_get=self.upstream_get)
        else:
            self.automatic_registration = None

    def get_assertion_issuer_info(self, iss):
        pass
