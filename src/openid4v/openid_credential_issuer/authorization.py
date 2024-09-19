"""The service that answers at the OAuth2 Authorization endpoint."""
import logging

from idpyoidc import alg_info
from idpyoidc.message import oauth2
from idpyoidc.node import topmost_unit
from idpyoidc.server.exception import ServiceError
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
        "token_endpoint_auth_methods_supported": [],
        "authorization_signing_alg_values_supported": alg_info.get_signing_algs(),
        "request_object_signing_alg_values_supported": alg_info.get_signing_algs(),
        "token_endpoint_auth_signing_alg_values_supported": alg_info.get_signing_algs()
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

        self.post_parse_request.append(self.verify_authorization_details)

    def get_assertion_issuer_info(self, iss):
        pass

    def match_authz_details(self, authz_det, cred_conf_supp):
        supports = []
        for _ad in authz_det:
            if _ad["type"] == "openid_credential":
                if _ad.get("credential_configuration_id", None) not in cred_conf_supp:
                    continue
                else:
                    supports.append(_ad)
        return supports

    def verify_authorization_details(self, request, client_id, context, **kwargs):
        # verify that the authorization_details actually describes something I can deal with
        _authz_details = request.get("authorization_details", None)
        if _authz_details:
            root = topmost_unit(self)
            # make sense only if there is a credential issuer part of this server
            cred_iss = root.get("openid_credential_issuer", None)
            if cred_iss:
                cred_conf_supp = cred_iss.context.claims.get_preference('credential_configurations_supported')
                supported = self.match_authz_details(_authz_details, cred_conf_supp)
                if supported == []:
                    raise ServiceError("I don't support what is asked for")

                request["authorization_details"] = supported
            else:  # might as well remove it or ?
                pass

        return request
