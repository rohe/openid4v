import json

import pytest
import responses
from cryptojwt.jws.jws import factory
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.util import rndstr

from examples import create_trust_chain_messages

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

_OAUTH2_SERVICES = {
    "metadata": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
    "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
    "credential": {"class": "openid4v.client.pid_eaa.Credential"},
}

WALLET_PROVIDER_ID = "https://wallet_provider.example.com"

WALLET_PROVIDER_CONFIG = {
    "entity_id": WALLET_PROVIDER_ID,
    "key_config": {
        "private_path": "private/wp_fed_keys.json",
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
        ],
        "public_path": "static/wp_fed_keys.json",
        "read_only": False
    },
    "preference": {
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
    },
    "authority_hints": [],
    "trust_anchors": {},
    "endpoints": [
        "entity_configuration"
    ],
    "entity_type": {
        "wallet_provider": {
            "class": "openid4v.wallet_provider.WalletProvider",
            "kwargs": {
                "config": {
                    "keys": {
                        "private_path": "private/wp_keys.json",
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
                        ],
                        "public_path": "static/wp_keys.json",
                        "read_only": False
                    },
                    "endpoint": {
                        "token": {
                            "path": "token",
                            "class": "openid4v.wallet_provider.token.Token",
                            "kwargs": {
                                "client_authn_method": [
                                    "client_secret_post",
                                    "client_secret_basic",
                                    "client_secret_jwt",
                                    "private_key_jwt"
                                ],
                                "lifetime": 3600,
                                "sign_alg": "ES256"
                            }
                        },
                        "challenge": {
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
                        }
                    },
                    "wallet_provider_id": "https://127.0.0.1:4000"
                }
            }
        },
    }
}

TA_ID = "https://ta.example.org"
TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]


class TestWIA():

    @pytest.fixture(autouse=True)
    def client_setup(self):
        self.ta = make_federation_entity(
            TA_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            endpoints=TA_ENDPOINTS
        )

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks()}

        CLIENT_CONFIG["trust_anchors"] = ANCHOR

        self.wallet = make_federation_combo(**CLIENT_CONFIG)

        WALLET_PROVIDER_CONFIG["trust_anchors"] = ANCHOR
        WALLET_PROVIDER_CONFIG["authority_hints"] = [TA_ID]
        self.wallet_provider = make_federation_combo(**WALLET_PROVIDER_CONFIG)

        self.ta.server.subordinate[WALLET_PROVIDER_ID] = {
            "jwks": self.wallet_provider["federation_entity"].keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

    def _wallet_instance_attestation_request(self, nonce):
        wallet_entity = self.wallet["wallet"]

        _service = wallet_entity.get_service("wallet_instance_attestation")
        _service.wallet_provider_id = WALLET_PROVIDER_ID

        request_args = {"challenge": nonce, "aud": WALLET_PROVIDER_ID}
        request_args["hardware_signature"] = rndstr()
        request_args["integrity_assertion"] = rndstr()
        request_args["hardware_key_tag"] = rndstr()

        req_info = _service.get_request_parameters(
            request_args,
            endpoint=f"{WALLET_PROVIDER_ID}/token")
        return req_info

    def test_wallet_instance_attestation_request(self):
        req_info = self._wallet_instance_attestation_request(nonce=rndstr(24))

        assert set(req_info.keys()) == {'method', 'body', 'headers', 'request', 'url'}
        _assertion = factory(req_info["request"]["assertion"])
        _payload = _assertion.jwt.payload()
        assert set(_payload.keys()) == {"challenge", "aud", "cnf", "iss", 'hardware_key_tag',
                                        'hardware_signature', 'iat', 'integrity_assertion', "jti", "exp"}

        def test_wallet_instance_attestation_response(self):
            _server = self.wallet_provider["wallet_provider"]
            _endpoint = _server.get_endpoint("nonce")
            _aa_response = _endpoint.process_request({"client_id": "urn:foo:bar"})
            _resp = json.loads(_aa_response["response_msg"])
            req_info = self._wallet_instance_attestation_request(_resp["nonce"])

            _endpoint = _server.get_endpoint("wallet_provider_token")
            _wia_request = _endpoint.parse_request(req_info["request"])
            assert set(_wia_request.keys()) == {'grant_type', '__verified_assertion', 'assertion'}
            # __verified_assertion is the unpacked assertion after the signature has been verified
            # __client_id is carried in the nonce
            _msgs = create_trust_chain_messages(self.wallet_provider, self.ta)

            with responses.RequestsMock() as rsps:
                for _url, _jwks in _msgs.items():
                    rsps.add("GET", _url, body=_jwks,
                             adding_headers={"Content-Type": "application/json"}, status=200)

                _response = _endpoint.process_request(_wia_request)

            assert _response
            assert _response["response_args"]["grant_type"] == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            _jws = factory(_response["response_args"]["assertion"])
            assert _jws.jwt.headers["typ"] == "wallet-attestation+jwt"
            _payload = _jws.jwt.payload()
            assert _payload
            assert _wia_request["__verified_assertion"]["cnf"] == _payload["cnf"]
            assert _payload["type"] == "WalletInstanceAttestation"
            assert "trust_chain" in _jws.jwt.headers
