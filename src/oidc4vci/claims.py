from idpyoidc.server.claims import Claims
from idpyoidc.metadata import get_signing_algs

from oidc4vci.message import WalletProvider


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
        for key in WalletProvider.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val not in [None, []]:
                _info[key] = _val

        return _info
