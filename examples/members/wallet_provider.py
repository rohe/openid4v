from typing import List
from typing import Optional

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS


def main(entity_id: str,
         authority_hints: Optional[List[str]],
         trust_anchors: Optional[dict],
         preference: Optional[dict] = None):
    entity = FederationEntityBuilder(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        key_conf={"key_defs": DEFAULT_KEY_DEFS}
    )
    entity.add_services()
    entity.add_functions()
    entity.add_endpoints({}, **LEAF_ENDPOINT)
    entity.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
        'trust_anchors'] = trust_anchors

    WalletProvider = {
        'entity_id': entity_id,
        # 'key_conf': {"key_defs": DEFAULT_KEY_DEFS},
        "federation_entity": {
            'class': FederationEntity,
            'kwargs': entity.conf
        },
        "wallet_provider": {
            'class': 'oidc4vci.wallet_provider.WalletProvider',
            'kwargs': {
                'config': {
                    "keys": {"key_defs": DEFAULT_KEY_DEFS},
                    "endpoint": {
                        "token": {
                            "path": "token",
                            "class": "oidc4vci.wallet_provider.token.Token",
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
    wp = FederationCombo(WalletProvider)
    for id, jwk in trust_anchors.items():
        wp["federation_entity"].keyjar.import_jwks(jwk, id)
    return wp
