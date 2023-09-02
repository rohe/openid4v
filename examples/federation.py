from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from oidc4vci.wallet_provider import ServerEntity
from oidc4vci.wallet_provider.token import Token

#              TA
#          +------|---+
#          |          |
#         IM1        IM2
#          |          |
#    WalletProvider   +--+--+
#                     |     |
#                    RP  PIDProvider

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
WP_ID = "https://wp.example.org"
IM1_ID = "https://im1.example.org"
IM2_ID = "https://im2.example.org"

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()

SESSION_PARAMS = {
    "encrypter": {
        "kwargs": {
            "keys": {
                "key_defs": [
                    {"type": "OCT", "use": ["enc"], "kid": "password"},
                    {"type": "OCT", "use": ["enc"], "kid": "salt"},
                ]
            },
            "iterations": 1,
        }
    }
}


def federation_setup():
    # TRUST ANCHOR

    TA = FederationEntityBuilder(
        TA_ID,
        preference={
            "organization_name": "The example federation operator",
            "homepage_uri": "https://ta.example.com",
            "contacts": "operations@ta.example.com"
        },
        key_conf={"key_defs": DEFAULT_KEY_DEFS}
    )
    TA.add_endpoints(None, **TA_ENDPOINTS)
    ta = FederationEntity(**TA.conf)

    ANCHOR = {TA_ID: ta.keyjar.export_jwks()}

    ##################
    # intermediate 1
    ##################

    INT = FederationEntityBuilder(
        IM1_ID,
        preference={
            "organization_name": "Intermediate 1",
            "homepage_uri": "https://im1.example.com",
            "contacts": "operations@example.com"
        },
        key_conf={"key_defs": DEFAULT_KEY_DEFS},
        authority_hints=[TA_ID]
    )
    INT.add_services()
    INT.add_functions()
    INT.add_endpoints()

    im1 = FederationEntity(**INT.conf)

    ##################
    # intermediate 2
    ##################

    INT = FederationEntityBuilder(
        IM2_ID,
        preference={
            "organization_name": "Intermediate 2",
            "homepage_uri": "https://im2.example.com",
            "contacts": "operations@example.com"
        },
        key_conf={"key_defs": DEFAULT_KEY_DEFS},
        authority_hints=[TA_ID]
    )
    INT.add_services()
    INT.add_functions()
    INT.add_endpoints()

    im2 = FederationEntity(**INT.conf)

    ########################################
    # Leaf WALLET RP
    ########################################

    RP_FE = FederationEntityBuilder(
        RP_ID,
        preference={
            "organization_name": "The RP",
            "homepage_uri": "https://rp.example.com",
            "contacts": "operations@rp.example.com"
        },
        authority_hints=[IM1_ID],
        key_conf={"key_defs": DEFAULT_KEY_DEFS}
    )
    RP_FE.add_services()
    RP_FE.add_functions()
    RP_FE.add_endpoints({}, **LEAF_ENDPOINT)
    RP_FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
        'trust_anchors'] = ANCHOR

    rp = FederationEntity(**RP_FE.conf)

    ########################################
    # Wallet provider
    ########################################

    WP_FE = FederationEntityBuilder(
        WP_ID,
        preference={
            "organization_name": "The Wallet Provider",
            "homepage_uri": "https://wp.example.com",
            "contacts": "operations@wp.example.com"
        },
        authority_hints=[IM2_ID],
        key_conf={"key_defs": DEFAULT_KEY_DEFS}
    )
    WP_FE.add_services()
    WP_FE.add_functions()
    WP_FE.add_endpoints({}, **LEAF_ENDPOINT)
    WP_FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
        'trust_anchors'] = ANCHOR

    WalletProvider = {
        'entity_id': WP_ID,
        # 'key_conf': {"key_defs": DEFAULT_KEY_DEFS},
        "federation_entity": {
            'class': FederationEntity,
            'kwargs': WP_FE.conf
        },
        "wallet_provider": {
            'class': ServerEntity,
            'kwargs': {
                'config': {
                    "keys": {"key_defs": DEFAULT_KEY_DEFS, "uri_path": "static/jwks.json"},
                    "endpoint": {
                        "token": {
                            "path": "token",
                            "class": Token,
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
                        "attested_security_context": "https://wallet-provider.example.org/LoA/basic",
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

    # Wallet

    # Setup subordinates

    ta.server.subordinate[IM1_ID] = {
        "jwks": im1.keyjar.export_jwks(),
        'authority_hints': [TA_ID]

    }

    ta.server.subordinate[IM2_ID] = {
        "jwks": im2.keyjar.export_jwks(),
        'authority_hints': [TA_ID]

    }

    im2.server.subordinate[WP_ID] = {
        "jwks": wp['federation_entity'].keyjar.export_jwks(),
        'authority_hints': [IM2_ID]

    }

    im1.server.subordinate[RP_ID] = {
        "jwks": rp.keyjar.export_jwks(),
        'authority_hints': [IM1_ID]
    }

    return {
        "ta": ta,
        "im1": im1,
        "im2": im2,
        "wp": wp,
        "rp": rp
    }
