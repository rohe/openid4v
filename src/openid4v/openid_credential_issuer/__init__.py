from typing import Optional

from idpyoidc.message import Message
from idpyoidc.metadata import get_encryption_algs
from idpyoidc.metadata import get_encryption_encs
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server.claims import Claims

from openid4v import message
from openid4v import ServerEntity


class OpenidCredentialIssuerClaims(Claims):
    _supports = {
        "credential_issuer": None,
        "authorization_server": None,
        "credential_endpoint": None,
        "batch_credential_endpoint": None,
        "deferred_credential_endpoint": None,
        "credential_response_encryption_alg_values_supported": get_encryption_algs(),
        "credential_response_encryption_enc_values_supported": get_encryption_encs(),
        "require_credential_response_encryption": False,
        "credentials_supported": ["vp_token"],
        "display": None,
        "jwks": None
    }

    def provider_info(self, supports, schema: Optional[Message] = None):
        _info = {}
        if schema is None:
            schema = message.CredentialIssuerMetadata
        for key in schema.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val not in [None, []]:
                _info[key] = _val

        return _info


class OpenidCredentialIssuer(ServerEntity):
    name = 'openid_credential_issuer'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}
    claims_class = OpenidCredentialIssuerClaims


class AutomaticRegistration(object):

    def __init__(self, upstream_get):
        self.upstream_get = upstream_get

    def set(self, client_id: str, client_info: Optional[dict] = None):
        context = self.upstream_get("attribute", "context")
        context.cdb[client_id] = client_info or {}
