#!/usr/bin/env python3
import json
from sys import argv
from typing import List
from typing import Optional

from fedservice.utils import get_jwks
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
        }
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


def wallet_setup(entity_id: str,
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
        httpc_params={"verify": False},
        trust_anchors=trust_anchors,
        endpoints=endpoints,
        services=services,
        entity_type={
            "wallet": {
                "class": "openid4v.client.Wallet",
                "kwargs": {
                    "config": entity_type_config["wallet"],
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
                    'config': entity_type_config["pid_eaa_consumer"]
                }
            }
        }
    )

    return wallet


def main(wallet_provider_id: str, trust_anchors: dict):
    _combo = wallet_setup(wallet_provider_id, trust_anchors=trust_anchors)
    _wallet = _combo["wallet"]

    # create an ephemeral key
    _ephemeral_key = _wallet.mint_new_key()

    # load it in the wallet KeyJar
    _jwks = {"keys": [_ephemeral_key.serialize(private=True)]}
    _wallet.context.keyjar.import_jwks(_jwks, _wallet.entity_id)
    _wallet.context.ephemeral_key = {_ephemeral_key.kid: _ephemeral_key}

    # Use the federation to figure out information about the wallet provider
    trust_chains = _wallet.get_trust_chains(wallet_provider_id)

    # load the wallet provider keys
    get_jwks(_wallet, _wallet.context.keyjar, trust_chains[0].metadata['wallet_provider'],
             wallet_provider_id)

    war_payload = {
        "challenge": "__not__applicable__",
        "hardware_signature": "__not__applicable__",
        "integrity_assertion": "__not__applicable__",
        "hardware_key_tag": "__not__applicable__",
        "cnf": {
            "jwk": _ephemeral_key.serialize()
        },
        "vp_formats_supported": {
            "jwt_vc_json": {
                "alg_values_supported": ["ES256K", "ES384"],
            },
            "jwt_vp_json": {
                "alg_values_supported": ["ES256K", "EdDSA"],
            },
        }
    }

    # The service I use to deal with sending the request and parsing the result
    _service = _wallet.get_service('wallet_instance_attestation')
    _service.wallet_provider_id = wallet_provider_id

    _info = _service.get_request_parameters(request_args=war_payload,
                                            endpoint=trust_chains[0].metadata['wallet_provider'][
                                                "token_endpoint"],
                                            ephemeral_key=_ephemeral_key)

    # print information that is used to send the request to the Wallet Provider
    print(_info)

    resp = _wallet.service_request(_service, response_body_type='application/jwt', **_info)

    return resp


if __name__ == "__main__":
    # Values from https://wiki.sunet.se/display/Projekt/EUDIW+pilot+setup
    # https://openidfed-test-1.sunet.se:5001/
    wallet_provider_id = argv[1]
    # trust_anchors_keys.json
    trust_anchors_file = argv[2]

    trust_anchors = json.load(open(trust_anchors_file, "r"))

    print(main(wallet_provider_id, trust_anchors))
