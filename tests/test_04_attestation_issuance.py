import base64
import hashlib
import json
import os

import pytest
from cryptojwt import as_unicode
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.dsa import ECDSASigner
from cryptojwt.utils import as_bytes
from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.key_import import import_jwks
from idpyoidc.key_import import store_under_other_id

from openid4v.device_integrity_service import DeviceIntegrityService
from openid4v.device_integrity_service.integrity import IntegrityAssertion
from openid4v.device_integrity_service.key_attest import KeyAttestation
from openid4v.wallet_provider.challenge import Challenge
from openid4v.wallet_provider.registration import Registration
from openid4v.wallet_provider.token import Token

BASEDIR = os.path.abspath(os.path.dirname(__file__))

TRUST_ANCHORS = {
    "https://127.0.0.1:7001": {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "VEhkNWFFSzVnS3B5cDlxMGR0RHhwM0EzQzF3MFUwV09xNGQwV1F4NkRaWQ",
                "n": "ii6GjcoPMtM92VS-Ig0P7ULEDyRNIVbOJFm1CTHtfuLMFct-kMe"
                     "-cMC2RVqRZZnIbixU78WV6c7tWBxjvFw4fIEecSPxrrWpDTRMeQlsIleh1dySneZhATa5E6lWXKmspfznBVmypafnaWVGH5agWcOJpAYGreHxZPvD_GnVgNoUrcB0xHJc3Rt7U4Fbe1tYvS318hbgJk5sPTo1TnjgRUTOt88gvV8o0eOg0tG2Qm71Q6p14yEi_vZPq0nwLMg5MIwxjTHyFIkhlPraKpV-mO3FriKiWOVvxNlqZkclwO62plJkhH1uowE5nVnmAYwH4uXyLNyqPh8JSLycxNvQfw",
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
def wallet_provider_endpoints():
    return {
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
        "challenge": {
            "path": "challenge",
            "class": Challenge
        },
        "registration": {
            "path": "registration",
            "class": Registration
        }
    }


@pytest.fixture
def wallet_provider_conf(wallet_provider_endpoints):
    return {
        "issuer": "https://example.com/",
        "httpc_params": {"verify": False, "timeout": 1},
        "keys": {"uri_path": "jwks.json", "key_defs": DEFAULT_KEY_DEFS},
        "endpoint": wallet_provider_endpoints
    }


@pytest.fixture
def wallet_conf():
    return {
        "entity_id": "https://127.0.0.1:5005",
        "httpc_params": {
            "verify": False
        },
        "key_config": {
            "key_defs": [
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
        "services": ["entity_configuration"],
        "entity_type": {
            "wallet": {
                "class": "openid4v.client.Wallet",
                "kwargs": {
                    "config": {
                        "services": {
                            "integrity": {
                                "class": "openid4v.client.device_integrity_service.IntegrityService"
                            },
                            "key_attestation": {
                                "class":
                                    "openid4v.client.device_integrity_service.KeyAttestationService"
                            },
                            "wallet_instance_attestation": {
                                "class":
                                    "openid4v.client.wallet_instance_attestation.WalletInstanceAttestation"
                            },
                            "challenge": {
                                "class": "openid4v.client.challenge.ChallengeService"
                            },
                            "registration": {
                                "class": "openid4v.client.registration.RegistrationService"
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
            }
        }
    }


WALLET_PROVIDER_ID = "https://127.0.0.1:4000"
TA_ID = "https://ta.example.org"
DEVICE_INTEGRITY_SERVICE_ID = "https://127.0.0.1:4001"


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self, wallet_provider_endpoints, wallet_conf):
        self.ta = make_federation_entity(
            TA_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS}
        )

        TRUST_ANCHORS = {TA_ID: self.ta.keyjar.export_jwks()}

        self.wp = make_federation_combo(
            WALLET_PROVIDER_ID,
            preference={
                "policy_uri": "https://wallet-provider.example.org/privacy_policy",
                "tos_uri": "https://wallet-provider.example.org/info_policy",
                "logo_uri": "https://wallet-provider.example.org/logo.svg",
            },
            authority_hints=[TA_ID],
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            endpoints=LEAF_ENDPOINTS,
            trust_anchors=TRUST_ANCHORS,
            entity_type={
                "wallet_provider": {
                    'class': 'openid4v.wallet_provider.WalletProvider',
                    'kwargs': {
                        'config': {
                            "keys": {"key_defs": DEFAULT_KEY_DEFS},
                            "endpoint": wallet_provider_endpoints,
                            'preference': {
                                "policy_uri": "https://wallet-provider.example.org/privacy_policy",
                                "tos_uri": "https://wallet-provider.example.org/info_policy",
                                "logo_uri": "https://wallet-provider.example.org/logo.svg",
                                "aal_values_supported": [
                                    "https://wallet-provider.example.org/LoA/basic",
                                    "https://wallet-provider.example.org/LoA/medium",
                                    "https://wallet-provider.example.org/LoA/high"
                                ],
                                "grant_types_supported": [
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-client"
                                    "-attestation"
                                ],
                                "token_endpoint_auth_methods_supported": [
                                    "private_key_jwt"
                                ],
                                "token_endpoint_auth_signing_alg_values_supported": [
                                    "ES256",
                                    "ES384",
                                    "ES512"
                                ]
                            }
                        }
                    }
                },
                "device_integrity_service": {
                    "class": DeviceIntegrityService,
                    "kwargs": {
                        'config': {
                            "keys": {"key_defs": DEFAULT_KEY_DEFS},
                            "endpoint": {
                                "integrity": {
                                    "path": "integrity",
                                    "class": IntegrityAssertion,
                                },
                                "key_attest": {
                                    "path": "key_attest",
                                    "class": KeyAttestation
                                }
                            }
                        }
                    }
                }
            }
        )

        self.wallet = make_federation_combo(**wallet_conf)

        # OEM key distribution
        _wallet = self.wallet["wallet"]
        _wallet.oem_key_jar = KeyJar()
        _wallet.oem_key_jar = import_jwks(
            _wallet.oem_key_jar,
            self.wp["device_integrity_service"].oem_keyjar.export_jwks(),
            WALLET_PROVIDER_ID)

        oem_kj = self.wp["device_integrity_service"].oem_keyjar
        oem_kj = store_under_other_id(oem_kj, "", WALLET_PROVIDER_ID, True)

    def wallet_instance_initialization_and_registration(self):
        _dis = self.wp["device_integrity_service"]
        _wallet = self.wallet["wallet"]

        # Step 2 Device Integrity Check

        _dis_service = self.wallet["wallet"].get_service('integrity')
        req = _dis_service.construct()

        _integrity_endpoint = _dis.get_endpoint("integrity")
        parsed_args = _integrity_endpoint.parse_request(req)
        response_args = _integrity_endpoint.process_request(parsed_args)
        _wallet.context.crypto_hardware_key = new_ec_key('P-256')

        # Step 3-5

        _get_challenge = _wallet.get_service("challenge")
        req = _get_challenge.construct()

        _wallet_provider = self.wp["wallet_provider"]

        _challenge_endpoint = _wallet_provider.get_endpoint("challenge")
        parsed_args = _challenge_endpoint.parse_request(req)
        _response = _challenge_endpoint.process_request(parsed_args)
        response_args = _response["response_args"]

        challenge = response_args["nonce"]

        # Step 6

        _wallet.context.crypto_hardware_key = new_ec_key('P-256')

        # Step 7-8

        _key_attestation_service = _wallet.get_service("key_attestation")
        request_args = {
            "challenge": "challenge",
            "crypto_hardware_key": json.dumps(_wallet.context.crypto_hardware_key.serialize())
        }

        req = _key_attestation_service.construct(request_args)

        _key_attestation_endpoint = _dis.get_endpoint("key_attestation")
        parsed_args = _key_attestation_endpoint.parse_request(req)
        _response = _key_attestation_endpoint.process_request(parsed_args)
        response_args = _response["response_args"]

        key_attestation = response_args["key_attestation"]

        # Step 9-13
        # Collect challenge, key_attestation, hardware_key_tag

        _registration_service = _wallet.get_service("registration")
        _req = _registration_service.construct({
            "challenge": challenge,
            "key_attestation": as_unicode(key_attestation),
            "hardware_key_tag": _wallet.context.crypto_hardware_key.kid
        })

        _registration_endpoint = _wallet_provider.get_endpoint("registration")
        parsed_args = _registration_endpoint.parse_request(_req)
        _ = _registration_endpoint.process_request(parsed_args)

    def test_wallet_attestation_issuance(self):
        self.wallet_instance_initialization_and_registration()

        _dis = self.wp["device_integrity_service"]
        _wallet_provider = self.wp["wallet_provider"]
        _wallet = self.wallet["wallet"]

        # Step 2 Check for cryptographic hardware key

        assert _wallet.context.crypto_hardware_key
        _wallet_provider.context.crypto_hardware_key[
            _wallet.context.crypto_hardware_key.kid] = _wallet.context.crypto_hardware_key

        # Step 3 generate an ephemeral key pair

        _ephemeral_key = new_ec_key('P-256')
        _ephemeral_key.use = "sig"
        _jwks = {"keys": [_ephemeral_key.serialize(private=True)]}
        _ephemeral_key_tag = _ephemeral_key.kid
        # _wallet_entity_id = f"https://wallet.example.com/instance/{_ephemeral_key_tag}"
        _wallet.context.keyjar = import_jwks(_wallet.context.keyjar, _jwks, _wallet.entity_id)

        # Step 4-6 Get challenge

        _get_challenge = _wallet.get_service("challenge")
        req = _get_challenge.construct()

        _challenge_endpoint = _wallet_provider.get_endpoint("challenge")
        parsed_args = _challenge_endpoint.parse_request(req)
        _response = _challenge_endpoint.process_request(parsed_args)
        response_args = _response["response_args"]

        challenge = response_args["nonce"]

        # Step 7 generate client_data_hash

        client_data = {
            "challenge": challenge,
            "jwk_thumbprint": _ephemeral_key_tag
        }

        client_data_hash = hashlib.sha256(as_bytes(json.dumps(client_data))).digest()

        # Step 8-10
        # signing the client_data_hash with the Wallet Hardware's private key
        _signer = ECDSASigner()
        hardware_signature = _signer.sign(msg=client_data_hash,
                                          key=_wallet.context.crypto_hardware_key.private_key())

        # It requests the Device Integrity Service to create an integrity_assertion linked to the
        # client_data_hash.

        _dis_service = self.wallet["wallet"].get_service('integrity')
        req = _dis_service.construct(request_args={
            "hardware_signature": as_unicode(base64.b64encode(hardware_signature))
        })

        _integrity_endpoint = _dis.get_endpoint("integrity")
        parsed_args = _integrity_endpoint.parse_request(req)
        _response = _integrity_endpoint.process_request(parsed_args)
        response_args = _response["response_args"]

        # Step 11-12

        war_payload = {
            "challenge": challenge,
            "hardware_signature": as_unicode(base64.b64encode(hardware_signature)),
            "integrity_assertion": as_unicode(response_args["integrity_assertion"]),
            "hardware_key_tag": _wallet.context.crypto_hardware_key.kid,
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

        _assertion = JWT(_wallet.context.keyjar, sign_alg="ES256")
        _assertion.iss = _wallet.entity_id
        _jws = _assertion.pack(payload=war_payload, kid=_ephemeral_key_tag)
        assert _jws

        token_request = {
            "assertion": _jws,
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer"
        }

        _token_endpoint = _wallet_provider.get_endpoint('wallet_provider_token')
        parsed_args = _token_endpoint.parse_request(token_request)
        _response = _token_endpoint.process_request(parsed_args)

        assert "response_args" in _response
        response_args = _response["response_args"]

        # should be able to verify the assertion's signature with the wallet provider's keys.

        _jwt = JWT(_wallet_provider.context.keyjar)
        _assertion = _jwt.unpack(response_args['assertion'])
        assert _assertion
        assert _assertion["iss"] == WALLET_PROVIDER_ID
