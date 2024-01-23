import os

import pytest
from fedservice.utils import make_federation_combo
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.server import ASConfiguration
from idpyoidc.server.client_authn import verify_client

from openid4v.wallet_provider import WalletProvider
from openid4v.wallet_provider.app_attestation import AppAttestation
from openid4v.wallet_provider.token import Token

BASEDIR = os.path.abspath(os.path.dirname(__file__))

TRUST_ANCHORS = {
    "https://127.0.0.1:7001": {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "VEhkNWFFSzVnS3B5cDlxMGR0RHhwM0EzQzF3MFUwV09xNGQwV1F4NkRaWQ",
                "n": "ii6GjcoPMtM92VS-Ig0P7ULEDyRNIVbOJFm1CTHtfuLMFct-kMe-cMC2RVqRZZnIbixU78WV6c7tWBxjvFw4fIEecSPxrrWpDTRMeQlsIleh1dySneZhATa5E6lWXKmspfznBVmypafnaWVGH5agWcOJpAYGreHxZPvD_GnVgNoUrcB0xHJc3Rt7U4Fbe1tYvS318hbgJk5sPTo1TnjgRUTOt88gvV8o0eOg0tG2Qm71Q6p14yEi_vZPq0nwLMg5MIwxjTHyFIkhlPraKpV-mO3FriKiWOVvxNlqZkclwO62plJkhH1uowE5nVnmAYwH4uXyLNyqPh8JSLycxNvQfw",
                "e": "AQAB"
            },
            {
                "kty": "EC",
                "use": "sig",
                "kid": "ekV1UUhhYVlESHAtUkxQR2lSWElSSXpaRzdqM2VFQ1Y0d0JTUmJjRjBBUQ",
                "crv": "P-256",
                "x": "IQ1Wea8xZuf5SGUuh9uKTQ7C_-_uTtOADd1TcsyJHF4",
                "y": "REIWFydYKHM1zjRhmoHP-n_mjrCOPn-1fG3trz0R7MU"
            }
        ]
    }
}


@pytest.fixture
def conf():
    return {
        "issuer": "https://example.com/",
        "httpc_params": {"verify": False, "timeout": 1},
        "keys": {"uri_path": "jwks.json", "key_defs": DEFAULT_KEY_DEFS},
        "endpoint": {
            "token": {
                "path": "token",
                "class": Token,
                "kwargs": {
                    "client_authn_method": [
                        "client_secret_basic",
                        "client_secret_post",
                        "client_secret_jwt",
                        "private_key_jwt",
                    ]
                },
            },
            "app_attestation": {
                "path": "app_attestation",
                "class": AppAttestation
            }
        },
        "client_authn": verify_client,
    }


@pytest.fixture
def entity_conf():
    return {
        "entity_id": "https://127.0.0.1:5005",
        "httpc_params": {
            "verify": False
        },
        "key_config": {
            "key_defs": [
                {
                    "type": "RSA",
                    "use": [
                        "sig"
                    ]
                },
                {
                    "type": "EC",
                    "crv": "P-256",
                    "use": [
                        "sig"
                    ]
                }
            ]
        },
        "trust_anchors": TRUST_ANCHORS,
        "services": [
            "entity_configuration",
            "entity_statement",
            "list",
            "trust_mark_status"
        ],
        "entity_type": {
            "wallet": {
                "class": "openid4v.client.Wallet",
                "kwargs": {
                    "config": {
                        "services": {
                            "wallet_instance_attestation": {
                                "class": "openid4v.client.wallet_instance_attestation.WalletInstanceAttestation"
                            }
                        }
                    },
                    "key_conf": {
                        "key_defs": [
                            {
                                "type": "EC",
                                "crv": "P-256",
                                "use": [
                                    "sig"
                                ]
                            }
                        ]
                    }
                }
            },
            "pid_eaa_consumer": {
                "class": "openid4v.client.pid_eaa_consumer.PidEaaHandler",
                "kwargs": {
                    "config": {
                        "add_ons": {
                            "pkce": {
                                "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                                "kwargs": {
                                    "code_challenge_length": 64,
                                    "code_challenge_method": "S256"
                                }
                            },
                            "dpop": {
                                "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
                                "kwargs": {
                                    "dpop_signing_alg_values_supported": [
                                        "ES256"
                                    ]
                                }
                            },
                            "pushed_authorization": {
                                "function": "idpyoidc.client.oauth2.add_on.par.add_support",
                                "kwargs": {
                                    "body_format": "urlencoded",
                                    "signing_algorithm": "RS256",
                                    "merge_rule": "lax",
                                    "authn_method": {
                                        "client_assertion": {
                                            "class": "openid4v.client.client_authn.ClientAssertion"
                                        }
                                    }
                                }
                            }
                        },
                        "preference": {
                            "response_types_supported": [
                                "code"
                            ],
                            "response_modes_supported": [
                                "query",
                                "form_post"
                            ],
                            "request_parameter_supported": True,
                            "request_uri_parameter_supported": True
                        },
                        "services": {
                            "pid_eaa_authorization": {
                                "class": "openid4v.client.pid_eaa.Authorization",
                                "kwargs": {
                                    "client_authn_methods": {
                                        "client_assertion": "openid4v.client.client_authn.ClientAssertion"
                                    }
                                }
                            },
                            "pid_eaa_token": {
                                "class": "openid4v.client.pid_eaa.AccessToken",
                                "kwargs": {
                                    "client_authn_methods": {
                                        "client_assertion": "openid4v.client.client_authn.ClientAuthenticationAttestation"
                                    }
                                }
                            },
                            "credential": {
                                "path": "credential",
                                "class": "openid4v.client.pid_eaa.Credential",
                                "kwargs": {
                                    "client_auth_methods": ["bearer_header"]
                                }
                            }
                        }
                    }
                }
            }
        }
    }


def test_nonce(conf, entity_conf):
    _client_id = "urn:foo:bar"
    _wallet_provider = WalletProvider(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
    _aa_endpoint = _wallet_provider.get_endpoint("app_attestation")
    args = _aa_endpoint.process_request({"client_id": _client_id})

    wallet = make_federation_combo(**entity_conf)

    _ws = wallet["wallet"].get_service('wallet_instance_attestation')
    req = _ws.construct(request_args={"client_id": _client_id,
                                      "aud": _wallet_provider.context.entity_id,
                                      "nonce": args["nonce"]})
    _token_endpoint = _wallet_provider.get_endpoint("wallet_provider_token")
    token_req = _token_endpoint.parse_request(req)
    assert token_req["__client_id"] == _client_id
