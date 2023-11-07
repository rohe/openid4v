import json
import os
from typing import List
from typing import Optional

from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.utils import make_federation_combo
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import ClientSecretBasic
from idpyoidc.server.client_authn import ClientSecretPost
from idpyoidc.server.oauth2.add_on.dpop import DPoPClientAuth
from idpyoidc.server.user_info import UserInfo

from openid4v.openid_credential_issuer import OpenidCredentialIssuer
from openid4v.openid_credential_issuer.client_authn import ClientAssertion

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
    }}

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("diploma.json")).read())


def main(entity_id: str,
         authority_hints: Optional[List[str]],
         trust_anchors: Optional[dict],
         preference: Optional[dict] = None):
    qeea = make_federation_combo(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        key_config={"key_defs": DEFAULT_KEY_DEFS},
        endpoints=LEAF_ENDPOINTS,
        trust_anchors=trust_anchors,
        entity_type={
            "openid_credential_issuer": {
                'class': OpenidCredentialIssuer,
                'kwargs': {
                    'config': {
                        "client_authn_methods": {
                            "client_secret_basic": ClientSecretBasic,
                            "client_secret_post": ClientSecretPost,
                            "client_assertion": ClientAssertion,
                            "dpop_client_auth": DPoPClientAuth
                        },
                        "keys": {"key_defs": DEFAULT_KEY_DEFS},
                        "endpoint": {
                            "token": {
                                "path": "token",
                                "class": "openid4v.openid_credential_issuer.access_token.Token",
                                "kwargs": {
                                    "client_authn_method": [
                                        "private_key_jwt"
                                    ]
                                }
                            },
                            "authorization": {
                                "path": "authorization",
                                "class":
                                    "openid4v.openid_credential_issuer.authorization.Authorization",
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
                                "class": "openid4v.openid_credential_issuer.credential.Credential",
                                "kwargs": {
                                    "client_authn_method": [
                                        "dpop_client_auth"
                                    ]
                                },
                            },
                            "pushed_authorization": {
                                "path": "pushed_authorization",
                                "class":
                                    "idpyoidc.server.oauth2.pushed_authorization.PushedAuthorization",
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
                                    "id": "eudiw.pid.se",
                                    "cryptographic_binding_methods_supported": ["jwk"],
                                    "cryptographic_suites_supported": ["RS256", "RS512", "ES256",
                                                                       "ES512"],
                                    "display": [
                                        {
                                            "name": "Example Swedish QEEA Provider",
                                            "locale": "en-US",
                                        }
                                    ],
                                    "credential_definition": {
                                        "type": ["OpenBadgeCredential"],
                                        "credentialSubject": {
                                            "type": {
                                                "mandatory": True,
                                                "display": [
                                                    {
                                                        "name": "Type of achievement",
                                                        "locale": "en-US"
                                                    }
                                                ]
                                            },
                                            "achievement": {
                                                "mandatory": True,
                                                "display": [
                                                    {
                                                        "name": "Achievement description",
                                                        "locale": "en-US"
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            ],
                            "attribute_disclosure": {
                                "": ["given_name",
                                     "family_name",
                                     "birthdate",
                                     "place_of_birth",
                                     "unique_id",
                                     "tax_id_code"]
                            },
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
    )

    return qeea
