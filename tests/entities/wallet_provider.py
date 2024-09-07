from typing import List
from typing import Optional

from fedservice.defaults import federation_services
from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.utils import make_federation_combo
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

WALLET_PROVIDER_CONF = {
    "keys": {"key_defs": DEFAULT_KEY_DEFS},
    "metadata_schema": "openid4v.message.WalletProviderMetadata",
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
                ],
                "lifetime": 3600,
                "sign_alg": "ES256"
            },
        },
        "challenge": {
            "path": "challenge",
            "class": "openid4v.wallet_provider.challenge.Challenge",
            "kwargs": {
                "challenge_service": {
                    "class": "openid4v.wallet_provider.challenge.ChallengeService",
                    "kwargs": {
                        "crypt_config": {
                            "key_defs": [
                                {"type": "OCT", "use": ["enc"], "kid": "password"},
                                {"type": "OCT", "use": ["enc"], "kid": "salt"},
                            ]
                        },
                        "nonce_lifetime": 86400
                    }
                }
            }
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
        "attested_security_context": "https://wallet-provider.example.org/LoA/basic",
        "type": "WalletInstanceAttestation",
        "authorization_endpoint": "eudiw:",
        "response_types_supported": [
            "vp_token"
        ],
        "vp_formats_supported": {
            "jwt_vp_json": {
                "alg_values_supported": [
                    "ES256"
                ]
            },
            "jwt_vc_json": {
                "alg_values_supported": [
                    "ES256"
                ]
            }
        },
        "request_object_signing_alg_values_supported": [
            "ES256"
        ],
        "presentation_definition_uri_supported": False
    }
}

DEVICE_INTEGRITY_SERVICE_CONF = {
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


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None,
         entity_type_config: Optional[dict] = None,
         endpoints: Optional[list] = None,
         key_config: Optional[dict] = None,
         services: Optional[list] = None
         ):
    if preference is None:
        preference = {
            "organization_name": "The WAllet Provider",
        }
    if endpoints is None:
        endpoints = LEAF_ENDPOINTS
    if not key_config:
        key_config = {"key_defs": DEFAULT_KEY_DEFS}
    if not services:
        services = federation_services("entity_configuration", "entity_statement")

    if entity_type_config is None:
        entity_type_config = {
            "wallet_provider": WALLET_PROVIDER_CONF,
            "device_integrity_service": DEVICE_INTEGRITY_SERVICE_CONF
        }
    else:
        if "wallet_provider" not in entity_type_config:
            entity_type_config["wallet_provider"] = WALLET_PROVIDER_CONF
        if "device_integrity_service" not in entity_type_config:
            entity_type_config["device_integrity_service"] = DEVICE_INTEGRITY_SERVICE_CONF

    wp = make_federation_combo(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        key_config=key_config,
        endpoints=endpoints,
        trust_anchors=trust_anchors,
        services=services,
        entity_type={
            "wallet_provider": {
                'class': 'openid4v.wallet_provider.WalletProvider',
                'kwargs': {
                    'config': entity_type_config["wallet_provider"]
                }
            },
            "device_integrity_service": {
                "class": "openid4v.device_integrity_service.DeviceIntegrityService",
                "kwargs": {
                    'config': entity_type_config["device_integrity_service"]
                }
            }
        }
    )

    return wp
