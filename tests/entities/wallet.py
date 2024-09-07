from typing import List
from typing import Optional

from fedservice.utils import make_federation_combo
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

WALLET_CONFIG = {
    "services": {
        "integrity": {
            "class": "openid4v.client.device_integrity_service.IntegrityService"
        },
        "key_attestation": {
            "class": "openid4v.client.device_integrity_service.KeyAttestationService"
        },
        "wallet_instance_attestation": {
            "class": "openid4v.client.wallet_instance_attestation.WalletInstanceAttestation"
        },
        "challenge": {
            "class": "openid4v.client.challenge.ChallengeService"
        },
        "registration": {
            "class": "openid4v.client.registration.RegistrationService"
        }
    }
}

PID_EEA_CONSUMER_CONFIG = {
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
        "par": {
            "function": "idpyoidc.client.oauth2.add_on.par.add_support",
            "kwargs": {
                "authn_method": {
                    "client_assertion": {
                        "class": "openid4v.client.client_authn.ClientAssertion"
                    }
                }
            }
        }
        # "par": {
        #     "function": "idpyoidc.client.oauth2.add_on.par.add_support",
        #     "kwargs": {
        #         "authn_method": {
        #             "client_assertion": {
        #                 "class": "openid4v.client.client_authn.ClientAssertion"
        #             }
        #         }
        #     }
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
                "client_authn_methods": {
                    "client_attestation":
                        "openid4v.client.client_authn.ClientAuthenticationAttestation"
                },
                "default_authn_method": "client_attestation"
            },
        },
        "pid_eaa_token": {
            "class": "openid4v.client.pid_eaa.AccessToken",
            "kwargs": {
                "client_authn_methods": {
                    "client_attestation":
                        "openid4v.client.client_authn.ClientAuthenticationAttestation"},
                "default_authn_method": "client_attestation"
            }
        },
        "credential": {
            "path": "credential",
            "class": 'openid4v.client.pid_eaa.Credential',
            "kwargs": {
                "client_authn_methods": {"dpop_header": "openid4v.client.client_authn.DPoPHeader"},
                "default_authn_method": "dpop_header"
            }
        }
    }
}


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None,
         endpoints: Optional[list] = None,
         key_config: Optional[dict] = None,
         entity_type_config: Optional[dict] = None,
         services: Optional[list] = None
         ):
    if not key_config:
        key_config = {"key_defs": DEFAULT_KEY_DEFS}
    if not services:
        services = [
            "entity_configuration",
            "entity_statement",
            "list",
            "trust_mark_status"
        ]
    if not entity_type_config:
        entity_type_config = {
            "wallet": WALLET_CONFIG,
            "pid_eaa_consumer": PID_EEA_CONSUMER_CONFIG
        }
    else:
        if "wallet" not in entity_type_config:
            entity_type_config["wallet"] = WALLET_CONFIG
        if "pid_eaa_consumer" not in entity_type_config:
            entity_type_config["pid_eaa_consumer"] = PID_EEA_CONSUMER_CONFIG

    wallet = make_federation_combo(
        entity_id,
        preference=preference,
        key_config=key_config,
        trust_anchors=trust_anchors,
        endpoints=endpoints,
        services=services,
        entity_type={
            "wallet": {
                "class": "openid4v.client.Wallet",
                "kwargs": {
                    "config": WALLET_CONFIG,
                    "key_conf": {
                        "key_defs": [
                            {
                                "type": "EC",
                                "crv": "P-256",
                                "use": ["sig"]
                            }
                        ]
                    }
                }
            },
            "pid_eaa_consumer": {
                'class': "openid4v.client.pid_eaa_consumer.PidEaaHandler",
                'kwargs': {
                    'config': PID_EEA_CONSUMER_CONFIG
                }
            }
        }
    )

    return wallet
