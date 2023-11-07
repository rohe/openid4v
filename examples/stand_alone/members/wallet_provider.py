from typing import List
from typing import Optional

from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.utils import make_federation_combo
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS


def main(entity_id: str,
         authority_hints: Optional[List[str]],
         trust_anchors: Optional[dict],
         preference: Optional[dict] = None):
    wp = make_federation_combo(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        key_config={"key_defs": DEFAULT_KEY_DEFS},
        endpoints=LEAF_ENDPOINTS,
        trust_anchors=trust_anchors,
        entity_type={
            "wallet_provider": {
                'class': 'openid4v.wallet_provider.WalletProvider',
                'kwargs': {
                    'config': {
                        "keys": {"key_defs": DEFAULT_KEY_DEFS},
                        "endpoint": {
                            "token": {
                                "path": "token",
                                "class": "openid4v.wallet_provider.token.Token",
                                "kwargs": {
                                    "client_authn_method": [
                                        "client_secret_post",
                                        "client_secret_basic",
                                        "client_secret_jwt",
                                        "private_key_jwt",
                                    ],
                                },
                            }
                        },
                        'preference': {
                            "policy_uri": "https://wallet-provider.example.org/privacy_policy",
                            "tos_uri": "https://wallet-provider.example.org/info_policy",
                            "logo_uri": "https://wallet-provider.example.org/logo.svg",
                            "attested_security_context":
                                "https://wallet-provider.example.org/LoA/basic",
                            "type": "WalletInstanceAttestation",
                            "authorization_endpoint": "eudiw:",
                            "response_types_supported": [
                                "vp_token"
                            ],
                            "vp_formats_supported": {
                                "jwt_vp_json": {
                                    "alg_values_supported": ["ES256"]
                                },
                                "jwt_vc_json": {
                                    "alg_values_supported": ["ES256"]
                                }
                            },
                            "request_object_signing_alg_values_supported": [
                                "ES256"
                            ],
                            "presentation_definition_uri_supported": False,
                        }
                    }
                }
            }
        }
    )

    return wp
