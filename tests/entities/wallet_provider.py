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
                        "keys": {"key_defs": DEFAULT_KEY_DEFS, "uri_path": "jwks.json"},
                        "endpoint": {
                            "token": {
                                "path": "token",
                                "class": "openid4v.wallet_provider.token.Token",
                                "kwargs": {
                                    "client_authn_method": [
                                        "client_secret_basic",
                                        "client_secret_post",
                                        "client_secret_jwt",
                                        "private_key_jwt",
                                    ]
                                },
                            },
                            "challenge": {
                                "path": "challenge",
                                "class": "openid4v.wallet_provider.challenge.Challenge"
                            },
                            "registration": {
                                "path": "registration",
                                "class": "openid4v.wallet_provider.registration.Registration"
                            }
                        },
                        'preference': {
                            "policy_uri": "https://wallet-provider.example.org/privacy_policy",
                            "tos_uri": "https://wallet-provider.example.org/info_policy",
                            "logo_uri": "https://wallet-provider.example.org/logo.svg",
                            "aal_values_supported": [
                                "https://wallet-provider.example.org/LoA/basic",
                                "https://wallet-provider.example.org/LoA/medium",
                                "https://wallet-provider.example.org/LoA/high"
                            ],
                            "grant_types_supported": [
                                "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"
                            ],
                            "token_endpoint_auth_methods_supported": [
                                "private_key_jwt"
                            ],
                            "token_endpoint_auth_signing_alg_values_supported": [
                                "ES256",
                                "ES384",
                                "ES512"
                            ]
                        }
                    }
                }
            },
            "device_integrity_service": {
                "class": "openid4v.device_integrity_service.DeviceIntegrityService",
                "kwargs": {
                    'config': {
                        "keys": {"key_defs": DEFAULT_KEY_DEFS, "uri_path": "dis_jwks.json"},
                        "endpoint": {
                            "integrity": {
                                "path": "integrity",
                                "class": "openid4v.device_integrity_service.integrity.IntegrityAssertion",
                            },
                            "key_attest": {
                                "path": "key_attest",
                                "class": "openid4v.device_integrity_service.key_attest.KeyAttestation"
                            }
                        }
                    }
                }
            }
        }
    )

    return wp
