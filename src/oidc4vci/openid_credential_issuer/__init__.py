from idpyoidc.metadata import get_encryption_algs
from idpyoidc.metadata import get_encryption_encs
from idpyoidc.metadata import get_signing_algs
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server.claims import Claims

from oidc4vci import message
from oidc4vci import ServerEntity


class OpenidCredentialIssuerClaims(Claims):
    _supports = {
        "credential_issuer": None,
        "authorization_server": None,
        "credential_endpoint": None,
        "batch_credential_endpoint": None,
        "deferred_credential_endpoint": None,
        "credential_response_encryption_alg_values_supported": get_encryption_algs,
        "credential_response_encryption_enc_values_supported": get_encryption_encs,
        "require_credential_response_encryption": False,
        "credentials_supported": ["vp_token"],
        "display": None,
        "jwks": None
    }

    def provider_info(self, supports):
        _info = {}
        for key in message.CredentialIssuerMetadata.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val not in [None, []]:
                _info[key] = _val

        return _info


class OpenidCredentialIssuer(ServerEntity):
    name = 'openid_credential_issuer'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}
    claims_class = OpenidCredentialIssuerClaims

    def get_metadata(self, *args):
        # static ! Should this be done dynamically ?
        return {self.name: self.context.provider_info}
