from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.oauth2 import Client

from openid4v.client.client_authn import ClientAuthenticationAttestation

CLIENT_CONFIG = {
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
    "trust_anchors": "file:trust_anchors.json",
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

_OAUTH2_SERVICES = {
    "metadata": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
    "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
    "credential": {"class": "openid4v.client.pid_eaa.Credential"},
}


def test_construction():
    client = Client(
        client_type="oauth2",
        config=CLIENT_CONFIG,
        keyjar=build_keyjar(DEFAULT_KEY_DEFS),
        services=_OAUTH2_SERVICES,
    )

    signing_key = new_ec_key(crv="P-256", key_ops=["sign"])
    request = {}
    _ = ClientAuthenticationAttestation().construct(
        request=request,
        service=client.get_service("authorization"),
        audience="https://server.example.com",
        wallet_instance_attestation="__WIA__",
        # thumbprint=signing_key.kid,
        signing_key=signing_key
    )

    assert "~" in request["client_assertion"]
    part = request["client_assertion"].split("~")
    assert len(part) == 2
    # The proof part
    _jws = factory(part[1])

    _key = signing_key
    _jws = factory(part[1])
    payload2 = _jws.verify_compact(part[1], keys=[_key])
    assert payload2
    assert set(payload2.keys()) == {'aud', 'exp', 'iss', 'jti', 'iat'}
