from idpyoidc.metadata import get_signing_algs
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server.claims import Claims

from openid4v import message
from openid4v import ServerEntity


class WalletProviderClaims(Claims):
    _supports = {
        "attested_security_context_values_supported": [],
        "grant_types_supported": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
        "response_types_supported": ["vp_token"],
        "vp_formats_supported": {
            "jwt_vp_json": {
                "alg_values_supported": get_signing_algs
            },
            "jwt_vc_json": {
                "alg_values_supported": get_signing_algs
            }
        },
        "request_object_signing_alg_values_supported": get_signing_algs,
        "presentation_definition_uri_supported": False
    }

    def provider_info(self, supports):
        _info = {}
        for key in message.WalletProvider.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val not in [None, []]:
                _info[key] = _val

        return _info


class WalletProvider(ServerEntity):
    name = 'wallet_provider'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}
    claims_class = WalletProviderClaims

    def get_metadata(self, *args):
        # static ! Should this be done dynamically ?
        _metadata = self.context.provider_info
        if "jwks" not in _metadata:
            _metadata["jwks"] = self.context.keyjar.export_jwks()

        return {self.name: _metadata}
