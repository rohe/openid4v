import json
import os

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.oauth2 import Client
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import ClientSecretBasic
from idpyoidc.server.client_authn import ClientSecretPost
from idpyoidc.server.oauth2.pushed_authorization import PushedAuthorization
from idpyoidc.server.user_info import UserInfo

import oidc4vci
from oidc4vci.client.client_authn import ClientAssertion as client_ClientAssertion
from oidc4vci.client.pid_eaa_consumer import PidEaaHandler
from oidc4vci.client.wallet_instance_attestation import WalletInstanceAttestation
from oidc4vci.openid_credential_issuer import OpenidCredentialIssuer
from oidc4vci.openid_credential_issuer.authorization import Authorization
from oidc4vci.openid_credential_issuer.client_authn import ClientAssertion as srv_ClientAssertion
from oidc4vci.openid_credential_issuer.credential import Credential
from oidc4vci.wallet_provider.token import Token

#              TA
#          +------|---+
#          |          |
#         IM1        IM2
#          |          |
#    WalletProvider   +--+--+
#                     |     |
#                    RP  PIDIssuer

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
WP_ID = "https://wp.example.org"
IM1_ID = "https://im1.example.org"
IM2_ID = "https://im2.example.org"
OCI_ID = "https://oci.example.org"

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
    rp.keyjar.import_jwks(ANCHOR[TA_ID], TA_ID)

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
            'class': oidc4vci.wallet_provider.WalletProvider,
            'kwargs': {
                'config': {
                    "keys": {"key_defs": DEFAULT_KEY_DEFS, "uri_path": "static/jwks.json"},
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
    wp["federation_entity"].keyjar.import_jwks(ANCHOR[TA_ID], TA_ID)

    # OpenidCredentialIssuer
    BASEDIR = os.path.abspath(os.path.dirname(__file__))

    def full_path(local_file):
        return os.path.join(BASEDIR, local_file)

    USERINFO_db = json.loads(open(full_path("users.json")).read())

    OCI_FE = FederationEntityBuilder(
        OCI_ID,
        preference={
            "organization_name": "The OpenID Credential Issuer",
            "homepage_uri": "https://oci.example.com",
            "contacts": "operations@oci.example.com"
        },
        authority_hints=[IM2_ID],
        key_conf={"key_defs": DEFAULT_KEY_DEFS}
    )
    OCI_FE.add_services()
    OCI_FE.add_functions()
    OCI_FE.add_endpoints({}, **LEAF_ENDPOINT)
    OCI_FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
        'trust_anchors'] = ANCHOR

    OCIssuer = {
        'entity_id': OCI_ID,
        "federation_entity": {
            'class': FederationEntity,
            'kwargs': OCI_FE.conf
        },
        "openid_credential_issuer": {
            'class': OpenidCredentialIssuer,
            'kwargs': {
                'config': {
                    "client_authn_methods": {
                        "client_secret_basic": ClientSecretBasic,
                        "client_secret_post": ClientSecretPost,
                        "client_assertion": srv_ClientAssertion
                    },
                    "keys": {"key_defs": DEFAULT_KEY_DEFS, "uri_path": "static/jwks.json"},
                    "endpoint": {
                        "token": {
                            "path": "token",
                            "class": "oidc4vci.openid_credential_issuer.access_token.Token",
                            "kwargs": {
                                "client_authn_method": [
                                    "private_key_jwt"
                                ]
                            }
                        },
                        "authorization": {
                            "path": "authorization",
                            "class": Authorization,
                            "kwargs": {
                                "response_types_supported": ["code"],
                                "response_modes_supported": ["query", "form_post"],
                                "request_parameter_supported": True,
                                "request_uri_parameter_supported": True,
                                "client_authn_method": ["client_assertion"]
                            },
                        },
                        "credential": {
                            "path": "credential",
                            "class": Credential,
                            "kwargs": {
                            },
                        },
                        "pushed_authorization": {
                            "path": "pushed_authorization",
                            "class": PushedAuthorization,
                            "kwargs": {
                                "client_authn_method": [
                                    "client_assertion",
                                ]
                            },
                        },
                    },
                    "add_ons": {
                        "pkce": {
                            "function": "idpyoidc.server.oauth2.add_on.pkce.add_support",
                            "kwargs": {"code_challenge_length": 64,
                                       "code_challenge_method": "S256"},
                        },
                        "dpop": {
                            "function": "idpyoidc.server.oauth2.add_on.dpop.add_support",
                            "kwargs": {
                                'dpop_signing_alg_values_supported': ["ES256"]
                            }
                        }
                    },
                    'preference': {
                        "credentials_supported": [
                            {
                                "format": "vc+sd-jwt",
                                "id": "eudiw.pid.it",
                                "cryptographic_binding_methods_supported": ["jwk"],
                                "cryptographic_suites_supported": ["RS256", "RS512", "ES256",
                                                                   "ES512"],
                                "display": [{
                                    "name": "PID Provider Italiano di esempio",
                                    "locale": "it-IT",
                                    "logo": {
                                        "url": "https://pid-provider example.org/public/logo.svg",
                                        "alt_text": "logo di questo PID Provider"
                                    },
                                    "background_color": "#12107c",
                                    "text_color": "#FFFFFF"
                                },
                                    {
                                        "name": "Example Italian PID Provider",
                                        "locale": "en-US",
                                        "logo": {
                                            "url": "https://pid-provider.example.org/public/logo.svg",
                                            "alt_text": "The logo of this PID Provider"
                                        },
                                        "background_color": "#12107c",
                                        "text_color": "#FFFFFF"
                                    }
                                ],
                                "credential_definition": {
                                    "type": ["PersonIdentificationData"],
                                    "credentialSubject": {
                                        "given_name": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Current First Name",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Nome",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        },
                                        "family_name": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Current Family Name",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Cognome",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        },
                                        "birthdate": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Date of Birth",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Data di Nascita",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        },
                                        "place_of_birth": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Place of Birth",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Luogo di Nascita",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        },
                                        "unique_id": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Unique Identifier",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Identificativo univoco",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        },
                                        "tax_id_code": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Tax Id Number",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Codice Fiscale",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        ]
                    },
                    "authentication": {
                        "anon": {
                            "acr": "http://www.swamid.se/policy/assurance/al1",
                            "class": "idpyoidc.server.user_authn.user.NoAuthn",
                            "kwargs": {"user": "diana"},
                        }
                    },
                    "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_db}},
                    "authz": {
                        "class": AuthzHandling,
                        "kwargs": {
                            "grant_config": {
                                "usage_rules": {
                                    "authorization_code": {
                                        "supports_minting": [
                                            "access_token",
                                            "refresh_token",
                                            "id_token",
                                        ],
                                        "max_usage": 1,
                                    },
                                    "access_token": {},
                                    "refresh_token": {
                                        "supports_minting": [
                                            "access_token",
                                            "refresh_token",
                                            "id_token",
                                        ],
                                    },
                                },
                                "expires_in": 43200,
                            }
                        },
                    },
                    "session_params": SESSION_PARAMS,
                }
            }
        }
    }
    oci = FederationCombo(OCIssuer)
    oci["federation_entity"].keyjar.import_jwks(ANCHOR[TA_ID], TA_ID)

    # Setup subordinates

    ta.server.subordinate[IM1_ID] = {
        "jwks": im1.keyjar.export_jwks(),
        'authority_hints': [TA_ID],
        "registration_info": {
            "entity_types": ["federation_entity"],
            "intermediate": True
        }
    }

    ta.server.subordinate[IM2_ID] = {
        "jwks": im2.keyjar.export_jwks(),
        'authority_hints': [TA_ID],
        "registration_info": {
            "entity_types": ["federation_entity"],
            "intermediate": True
        }
    }

    im2.server.subordinate[WP_ID] = {
        "jwks": wp['federation_entity'].keyjar.export_jwks(),
        'authority_hints': [IM2_ID],
        "registration_info": {"entity_types": ["federation_entity", "wallet_provider"]},
    }

    im2.server.subordinate[OCI_ID] = {
        "jwks": oci['federation_entity'].keyjar.export_jwks(),
        'authority_hints': [IM2_ID],
        "registration_info": {"entity_types": ["federation_entity", "openid_credential_issuer"]},
    }

    im1.server.subordinate[RP_ID] = {
        "jwks": rp.keyjar.export_jwks(),
        'authority_hints': [IM1_ID],
        "registration_info": {"entity_types": ["federation_entity", "relying_party"]},
    }

    return {
        "ta": ta,
        "im1": im1,
        "im2": im2,
        "wp": wp,
        "rp": rp,
        "oci": oci
    }


WALLET_ID = "s6BhdRkqt3"


def wallet_setup(federation):
    FE = FederationEntityBuilder(
        RP_ID,
        preference={
            "organization_name": "The RP",
            "homepage_uri": "https://rp.example.com",
            "contacts": "operations@rp.example.com"
        },
        key_conf = {"key_defs": DEFAULT_KEY_DEFS},
        authority_hints=[IM1_ID],
    )
    FE.add_services()
    FE.add_functions()

    _anchor = {TA_ID: federation["ta"].keyjar.export_jwks()}
    FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
        'trust_anchors'] = _anchor

    WalletConfig = {
        'entity_id': WALLET_ID,
        "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
        "federation_entity": {
            'class': FederationEntity,
            'kwargs': FE.conf
        },
        "wallet": {
            'class': Client,
            'kwargs': {
                'config': {
                    # "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                    "services": {
                        "wallet_instance_attestation": {
                            "class": WalletInstanceAttestation,
                            "kwargs": {}
                        }
                    },
                    "wallet_provider_id": "https://wp.example.com"
                }
            }
        },
        "pid_eaa_consumer": {
            'class': PidEaaHandler,
            'kwargs': {
                'config': {
                    "base_url": "",
                    # "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                    "add_ons": {
                        "pkce": {
                            "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                            "kwargs": {"code_challenge_length": 64,
                                       "code_challenge_method": "S256"},
                        },
                        "dpop": {
                            "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
                            "kwargs": {
                                'dpop_signing_alg_values_supported': ["ES256"]
                            }
                        },
                        # "pushed_authorization": {
                        #     "function": "idpyoidc.client.oauth2.add_on.par.add_support",
                        #     "kwargs": {
                        #         "body_format": "jws",
                        #         "signing_algorithm": "RS256",
                        #         "http_client": None,
                        #         "merge_rule": "lax",
                        #     },
                        # }
                    },
                    "preference": {
                        "client_authn_methods": ["private_key_jwt"],
                        "response_types_supported": ["code"],
                        "response_modes_supported": ["query", "form_post"],
                        "request_parameter_supported": True,
                        "request_uri_parameter_supported": True,
                        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                        "token_endpoint_auth_signing_alg_values_supported": ["ES256"]
                    },
                    "services": {
                        "pid_eaa_authorization": {
                            "class": "oidc4vci.client.pid_eaa.Authorization",
                            "kwargs": {
                                "client_authn_methods": {"client_assertion": client_ClientAssertion}
                            },
                        },
                        "pid_eaa_token": {
                            "class": "oidc4vci.client.pid_eaa.AccessToken",
                            "kwargs": {}
                        }
                        # "credential": {
                        #     "path": "credential",
                        #     "class": Credential,
                        #     "kwargs": {
                        #     },
                        # }
                    }
                }
            }
        }
    }
    wallet = FederationCombo(WalletConfig)
    wallet["federation_entity"].keyjar.import_jwks(_anchor[TA_ID], TA_ID)
    # Need the wallet providers public keys. Could get this from the metadata
    wallet.keyjar.import_jwks(
        federation["wp"]["wallet_provider"].context.keyjar.export_jwks(),
        federation["wp"].entity_id)

    return wallet
