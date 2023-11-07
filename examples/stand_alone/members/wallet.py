from typing import List
from typing import Optional

from fedservice.utils import make_federation_combo
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.oauth2 import Client

from openid4v.client.client_authn import ClientAssertion
from openid4v.client.pid_eaa_consumer import PidEaaHandler
from openid4v.client.wallet_instance_attestation import WalletInstanceAttestation


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None):
    wallet = make_federation_combo(
        entity_id,
        key_config={"key_defs": DEFAULT_KEY_DEFS},
        trust_anchors=trust_anchors,
        entity_type={
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
                                "class": "openid4v.client.pid_eaa.Authorization",
                                "kwargs": {
                                    "client_authn_methods": {"client_assertion": ClientAssertion}
                                },
                            },
                            "pid_eaa_token": {
                                "class": "openid4v.client.pid_eaa.AccessToken",
                                "kwargs": {}
                            },
                            "credential": {
                                "path": "credential",
                                "class": 'openid4v.client.pid_eaa.Credential',
                                "kwargs": {}
                            }
                        }
                    }
                }
            }
        }
    )

    return wallet
