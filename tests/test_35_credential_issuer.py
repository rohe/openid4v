import json
import os

import pytest
import responses
from fedservice.entity import get_verified_trust_chains
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.oauth2.add_on.par import push_authorization
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.util import rndstr

import openid4v.openid_credential_issuer.revocation
from examples import create_trust_chain_messages
from openid4v.message import AuthorizationServerMetadata
from openid4v.message import OpenidCredentialIssuer

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


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

WALLET_CONFIG = {
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
                                "authn_method": {
                                    "client_authentication_attestation": {
                                        "class": "openid4v.client.client_authn.ClientAuthenticationAttestation"
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
                                "client_authn_methods": {
                                    "dpop_client_auth": "openid4v.client.client_authn.DPoPHeader"
                                }
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
                    "wallet_provider_id": "https://127.0.0.1:4000",
                    "metadata_schema": 'openid4v.message.WalletProvider'
                }
            }
        },
    }
}

OAUTH_SERVER_CONF = {
    "client_authn_methods": {
        "client_secret_basic": "idpyoidc.server.client_authn.ClientSecretBasic",
        "client_secret_post": "idpyoidc.server.client_authn.ClientSecretPost",
        "client_assertion": "openid4v.openid_credential_issuer.client_authn.ClientAssertion",
        "dpop_client_auth": "idpyoidc.server.oauth2.add_on.dpop.DPoPClientAuth",
        "attest_jwt_client_auth": "openid4v.openid_credential_issuer.client_authn.ClientAuthenticationAttestation"
    },
    "keys": {
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
        "private_path": "private/as_keys.json",
        "public_path": "static/as_keys.json",
        "read_only": False
    },
    "endpoint": {
        "token": {
            "path": "token",
            "class": "openid4v.openid_credential_issuer.access_token.Token",
            "kwargs": {
                "client_authn_method": [
                    "client_authentication_attestation"
                ]
            }
        },
        "authorization": {
            "path": "authorization",
            "class": "openid4v.openid_credential_issuer.authorization.Authorization",
            "kwargs": {
                "response_types_supported": [
                    "code"
                ],
                "response_modes_supported": [
                    "query",
                    "form_post"
                ],
                "request_parameter_supported": True,
                "request_uri_parameter_supported": True,
                "automatic_registration": {
                    "class": "openid4v.openid_credential_issuer.AutomaticRegistration"
                }
            }
        },
        "pushed_authorization": {
            "path": "pushed_authorization",
            "class": "idpyoidc.server.oauth2.pushed_authorization.PushedAuthorization",
            "kwargs": {
                "client_authn_method": [
                    "client_authentication_attestation"
                ]
            }
        }
    },
    "add_ons": {
        "pkce": {
            "function": "idpyoidc.server.oauth2.add_on.pkce.add_support",
            "kwargs": {
                "code_challenge_length": 64,
                "code_challenge_method": "S256"
            }
        },
        "dpop": {
            "function": "idpyoidc.server.oauth2.add_on.dpop.add_support",
            "kwargs": {
                "dpop_signing_alg_values_supported": ["ES256"],
                "dpop_endpoints": ["credential"]
            }
        }
    },
    "authentication": {
        "anon": {
            "acr": "http://www.swamid.se/policy/assurance/al1",
            "class": "idpyoidc.server.user_authn.user.NoAuthn",
            "kwargs": {
                "user": "diana"
            }
        }
    },
    "userinfo": {
        "class": "idpyoidc.server.user_info.UserInfo",
        "kwargs": {
            "db_file": full_path("users.json")
        }
    },
    "authz": {
        "class": "idpyoidc.server.authz.AuthzHandling",
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": [
                            "access_token",
                            "refresh_token",
                            "id_token"
                        ],
                        "max_usage": 1
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": [
                            "access_token",
                            "refresh_token",
                            "id_token"
                        ]
                    }
                },
                "expires_in": 43200
            }
        }
    },
    "session_params": {
        "encrypter": {
            "kwargs": {
                "keys": {
                    "key_defs": [
                        {
                            "type": "OCT",
                            "use": [
                                "enc"
                            ],
                            "kid": "password"
                        },
                        {
                            "type": "OCT",
                            "use": [
                                "enc"
                            ],
                            "kid": "salt"
                        }
                    ]
                },
                "iterations": 1
            }
        }
    },
    "preference": {
        "acr_values_supported": [
            "https://www.spid.gov.it/SpidL1",
            "https://www.spid.gov.it/SpidL2",
            "https://www.spid.gov.it/SpidL3"
        ],
        "token_endpoint_auth_methods_supported": ['attest_jwt_client_auth'],
    },
    "metadata_schema": 'openid4v.message.AuthorizationServerMetadata'
}

OPENID_CREDENTIAL_ISSUER_CONFIG = {
    "client_authn_methods": {
        "dpop_client_auth": "idpyoidc.server.oauth2.add_on.dpop.DPoPClientAuth",
    },
    "keys": {
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
        "private_path": "private/ci_keys.json",
        "public_path": "static/ci_keys.json",
        "read_only": False
    },
    "endpoint": {
        "credential": {
            "path": "credential",
            "class": "openid4v.openid_credential_issuer.credential.Credential",
            "kwargs": {
                "client_authn_method": [
                    "dpop_client_auth"
                ]
            }
        },
        "revocation": {
            'path': 'revocation',
            'class': 'openid4v.openid_credential_issuer.revocation.Revocation',
            "kwargs": {}
        },
        "status_attestation": {
            'path': 'status_attestation',
            'class': 'openid4v.openid_credential_issuer.status_attestation.StatusAttestation',
            "kwargs": {}
        }
    },
    "preference": {
        "attribute_disclosure": {
            "": [
                "given_name",
                "family_name",
                "birthdate",
                "place_of_birth",
                "unique_id",
                "tax_id_code"
            ]
        },
        "display": [
            {
                "name": "EAA Provider",
                "locale": "en-US"
            }
        ],
        "credential_configurations_supported": [
            {
                "format": "vc+sd-jwt",
                "id": "eudiw.pid.se",
                "cryptographic_binding_methods_supported": [
                    "jwk"
                ],
                "credential_signing_alg_values_supported": [
                    "ES256",
                    "ES512"
                ],
                "display": [
                    {
                        "name": "Example Swedish QEEA Provider",
                        "locale": "en-US"
                    }
                ],
                "credential_definition": {
                    "type": [
                        "VerifiableCredential",
                        "PersonIdentificationData"
                    ],
                    "credentialSubject": {
                        "given_name": {
                            "display": [
                                {
                                    "name": "Given Name",
                                    "locale": "en-US"
                                }
                            ]
                        },
                        "family_name": {
                            "display": [
                                {
                                    "name": "Surname",
                                    "locale": "en-US"
                                }
                            ]
                        },
                        "unique_id": {
                            "display": [{
                                "name": "Unique Identifier",
                                "locale": "en-US"
                            }]
                        },
                        "tax_id_code": {
                            "display": [{
                                "name": "Tax Id Number",
                                "locale": "en-US"
                            }]
                        }
                    }
                }
            }
        ]
    },
    "userinfo": {
        "class": "idpyoidc.server.user_info.UserInfo",
        "kwargs": {
            "db_file": full_path("users.json")
        }
    },
    "metadata_schema": 'openid4v.message.OpenidCredentialIssuer'
}

TA_ID = "https://ta.example.org"
TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]
CREDENTIAL_ISSUER_ID = "https://127.0.0.1:5002"
CREDENTIAL_ISSUER_CONF = {
    "entity_id": CREDENTIAL_ISSUER_ID,
    "key_config": {
        "private_path": "private/qeaa_fed_keys.json",
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
        "public_path": "static/qeaa_fed_keys.json",
        "read_only": False
    },
    "authority_hints": [],
    "trust_anchors": {},
    "endpoints": [
        "entity_configuration"
    ],
    "entity_type": {
        "oauth_authorization_server": {
            "class": "openid4v.ServerEntity",
            "kwargs": {
                "config": OAUTH_SERVER_CONF
            }
        },
        "openid_credential_issuer": {
            "class": "openid4v.openid_credential_issuer.OpenidCredentialIssuer",
            "kwargs": {
                "config": OPENID_CREDENTIAL_ISSUER_CONFIG
            }
        }
    }
}


class TestCredentialIssuer():

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

        WALLET_CONFIG["trust_anchors"] = ANCHOR

        self.wallet = make_federation_combo(**WALLET_CONFIG)

        WALLET_PROVIDER_CONFIG["trust_anchors"] = ANCHOR
        WALLET_PROVIDER_CONFIG["authority_hints"] = [TA_ID]
        self.wallet_provider = make_federation_combo(**WALLET_PROVIDER_CONFIG)

        self.ta.server.subordinate[WALLET_PROVIDER_ID] = {
            "jwks": self.wallet_provider["federation_entity"].keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        CREDENTIAL_ISSUER_CONF["trust_anchors"] = ANCHOR
        CREDENTIAL_ISSUER_CONF["authority_hints"] = [TA_ID]
        self.credential_issuer = make_federation_combo(**CREDENTIAL_ISSUER_CONF)

        self.ta.server.subordinate[CREDENTIAL_ISSUER_ID] = {
            "jwks": self.credential_issuer["federation_entity"].keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

    def test_metadata(self):
        metadata = self.credential_issuer.get_metadata()
        assert set(metadata.keys()) == {'federation_entity', "oauth_authorization_server", "openid_credential_issuer"}

        as_metadata = AuthorizationServerMetadata(**metadata["oauth_authorization_server"])
        as_metadata.verify()

        ci_metadata = OpenidCredentialIssuer(**metadata["openid_credential_issuer"])
        ci_metadata.verify()

    def _create_wia(self):
        # First get the nonce
        _server = self.wallet_provider["wallet_provider"]
        _endpoint = _server.get_endpoint("challenge")
        _aa_response = _endpoint.process_request()
        _msg = json.loads(_aa_response["response_msg"])
        _nonce = _msg["nonce"]

        # Now for the Wallet Instance Attestation
        wallet_entity = self.wallet["wallet"]
        _service = wallet_entity.get_service("wallet_instance_attestation")
        _service.wallet_provider_id = WALLET_PROVIDER_ID
        request_args = {"challenge": _nonce, "aud": WALLET_PROVIDER_ID}
        req_info = _service.get_request_parameters(
            request_args,
            endpoint=f"{WALLET_PROVIDER_ID}/token")

        _endpoint = _server.get_endpoint("wallet_provider_token")
        _wia_request = _endpoint.parse_request(req_info["request"])
        assert set(_wia_request.keys()) == {'assertion', 'grant_type', '__verified_assertion', '__iccid'}
        # __verified_assertion is the unpacked assertion after the signature has been verified
        # __client_id is carried in the nonce
        _msgs = create_trust_chain_messages(self.wallet_provider, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _response = _endpoint.process_request(_wia_request)

        return _response["response_args"]["assertion"], _wia_request['__verified_assertion']["iss"]

    def test_qeaa_flow(self):
        _wia, _thumbprint = self._create_wia()
        assert _wia

        oic = self.credential_issuer["openid_credential_issuer"]

        _handler = self.wallet["pid_eaa_consumer"]
        _actor = _handler.get_consumer(oic.context.entity_id)
        if _actor is None:
            _actor = _handler.new_consumer(oic.context.entity_id)
            _msgs = create_trust_chain_messages(self.credential_issuer, self.ta)

            with responses.RequestsMock() as rsps:
                for _url, _jwks in _msgs.items():
                    rsps.add("GET", _url, body=_jwks,
                             adding_headers={"Content-Type": "application/json"}, status=200)

                _trust_chains = get_verified_trust_chains(_actor, oic.context.entity_id)
            _metadata = _trust_chains[0].metadata
            _context = _actor.get_service_context()
            _context.provider_info = _metadata["openid_credential_issuer"]

        assert _actor
        _service = _actor.get_service("authorization")
        _nonce = rndstr(24)
        _context = _actor.get_service_context()
        # Need a new state for a new authorization request
        _state = _context.cstate.create_state(iss=_context.get("issuer"))
        _context.cstate.bind_key(_nonce, _state)
        _service.certificate_issuer_id = _context.get("issuer")

        req_args = {
            "authorization_details": [
                {
                    "type": "openid_credential",
                    "format": "vc+sd-jwt",
                    "credential_definition": {
                        "type": "PersonIdentificationData"
                    }
                }
            ],
            "response_type": ["code"],
            "nonce": _nonce,
            "state": _state,
            "client_id": _thumbprint,
            "redirect_uri": "eudiw://wallet.example.org",
        }

        _par_endpoint = oic.get_endpoint("pushed_authorization")
        _request_uri = "urn:uuid:bwc4JK-ESC0w8acc191e-Y1LTC2"
        # The response from the PAR endpoint
        _resp = {"request_uri": _request_uri, "expires_in": 3600}
        # the authorization stored on the server
        oic.context.par_db[_request_uri] = req_args

        with responses.RequestsMock() as rsps:
            rsps.add("POST", _par_endpoint.full_path, body=json.dumps(_resp),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            # PAR request
            _req = push_authorization(request_args=AuthorizationRequest(**req_args),
                                      service=_service,
                                      wallet_instance_attestation=_wia)

        _authz_endpoint = oic.get_endpoint("authorization")
        _p_req = _authz_endpoint.parse_request(_req)
        _resp = _authz_endpoint.process_request(_p_req)
        assert "code" in _resp["response_args"]
        _code = _resp["response_args"]["code"]

        # Time for the Token endpoint

        _service = _actor.get_service("accesstoken")
        assert _service
        token_req_info = _service.get_request_parameters(
            request_args={
                "code": _code,
                "redirect_uri": req_args["redirect_uri"],
                "grant_type": "authorization_code",
                "state": req_args["state"]
            },
            attestation=_wia
        )

        _endp = oic.get_endpoint("token")
        _req = _endp.parse_request(token_req_info["request"])
        _token_resp = _endp.process_request(_req)
        assert _token_resp
        assert set(_token_resp["response_args"].keys()) == {'access_token',
                                                            'c_nonce',
                                                            'c_nonce_expires_in',
                                                            'expires_in',
                                                            'scope',
                                                            'token_type'}

        # and now for the credential endpoint

        _service = _actor.get_service("credential")

        cred_req_info = _service.get_request_parameters(
            request_args={
                "format": "vc+sd-jwt",
                "credential_definition": {
                    "type": ["PersonIdentificationData"]
                },
                "access_token": _token_resp["response_args"]["access_token"]
            },
            state=req_args["state"],
            endpoint=_metadata['openid_credential_issuer']['credential_endpoint']
        )

        assert cred_req_info["method"] == "POST"
        assert 'Authorization' in cred_req_info["headers"]
        assert 'dpop' in cred_req_info["headers"]
        assert cred_req_info["headers"]["Content-Type"] == "application/json"

        _endp = oic.get_endpoint("credential")
        _req = _endp.parse_request(cred_req_info["request"], http_info={"headers": cred_req_info["headers"]})
        _resp = _endp.process_request(_req)
        assert _resp
        assert set(_resp["response_args"].keys()) == {'c_nonce_expires_in', 'c_nonce', 'format', 'credential'}
