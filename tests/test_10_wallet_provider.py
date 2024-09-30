import base64
import hashlib
import json

from cryptojwt import JWT
from cryptojwt import as_unicode
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.dsa import ECDSASigner
from cryptojwt.utils import as_bytes
import pytest

from tests.build_federation import build_federation

TA_ID = "https://ta.example.org"
WP_ID = "https://wp.example.org"
WALLET_ID = "I_am_the_wallet"

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [WP_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    WP_ID: {
        "entity_type": "wallet_provider",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
            "preference": {
                "organization_name": "The Wallet Provider",
                "homepage_uri": "https://wp.example.com",
                "contacts": "operations@wp.example.com"
            }
        }
    },
    WALLET_ID: {
        "entity_type": "wallet",
        "trust_anchors": [TA_ID],
        "kwargs": {}
    }
}


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def federation_setup(self):
        self.federation = build_federation(FEDERATION_CONFIG)
        self.ta = self.federation[TA_ID]
        self.wp = self.federation[WP_ID]
        self.wallet = self.federation[WALLET_ID]

    def test_metadata(self):
        _metadata = self.wp.get_metadata()
        assert set(_metadata.keys()) == {'device_integrity_service', 'wallet_provider',
                                         'federation_entity'}

    def test_sparse_wia(self):
        # Construct the wallet instance request
        _wallet = self.wallet["wallet"]
        _wallet_provider = self.wp["wallet_provider"]

        # Step 3 generate an ephemeral key pair

        _ephemeral_key = _wallet.mint_ephemeral_key()

        #
        _wia_service = _wallet.get_service('wallet_instance_attestation')
        _wia_service.wallet_provider_id = _wallet_provider.entity_id
        request_args = {
            "challenge": "__not__applicable__",
            "hardware_signature": "__not__applicable__",
            "integrity_assertion": "__not__applicable__",
            "hardware_key_tag": "__not__applicable__",
            "authorization_endpoint": "__not__applicable__",
            "response_types_supported": "__not__applicable__",
            "response_modes_supported": "__not__applicable__",
            "request_object_signing_alg_values_supported": "__not__applicable__"
        }
        request_args.update({
            "vp_formats_supported": {
                "jwt_vc_json": {
                    "alg_values_supported": [
                        "ES256K",
                        "ES384"
                    ]
                },
                "jwt_vp_json": {
                    "alg_values_supported": [
                        "ES256K",
                        "EdDSA"
                    ]
                }
            },
            "cnf": _wallet.context.ephemeral_key[_ephemeral_key.kid].serialize(private=False)
        })
        req = _wia_service.construct(
            request_args=request_args,
            ephemeral_key=_wallet.context.ephemeral_key[_ephemeral_key.kid])

        assert req

        _wia_endpoint = _wallet_provider.get_endpoint("wallet_provider_token")

        parsed_args = _wia_endpoint.parse_request(req)
        _response = _wia_endpoint.process_request(parsed_args)
        assert _response

    def wallet_instance_initialization_and_registration(self):
        _dis = self.wp["device_integrity_service"]
        _wallet = self.wallet["wallet"]

        # Step 2 Device Integrity Check

        _dis_service = self.wallet["wallet"].get_service('integrity')
        req = _dis_service.construct()

        _integrity_endpoint = _dis.get_endpoint("integrity")
        parsed_args = _integrity_endpoint.parse_request(req)
        _ = _integrity_endpoint.process_request(parsed_args)
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

        # _wallet.context.crypto_hardware_key = new_ec_key('P-256')

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
            "hardware_key_tag": as_unicode(
                _wallet.context.crypto_hardware_key.thumbprint("SHA-256"))
        })

        _registration_endpoint = _wallet_provider.get_endpoint("registration")
        parsed_args = _registration_endpoint.parse_request(_req)
        _ = _registration_endpoint.process_request(parsed_args)

        _wallet_provider.context.crypto_hardware_key[
            _req["hardware_key_tag"]] = _wallet.context.crypto_hardware_key

    def test_wallet_attestation_issuance(self):
        self.wallet_instance_initialization_and_registration()

        _dis = self.wp["device_integrity_service"]
        _wallet_provider = self.wp["wallet_provider"]
        _wallet = self.wallet["wallet"]

        # Step 2 Check for cryptographic hardware key

        assert _wallet.context.crypto_hardware_key

        # Step 3 generate an ephemeral key pair

        _ephemeral_key = new_ec_key('P-256')
        _ephemeral_key.use = "sig"
        _jwks = {"keys": [_ephemeral_key.serialize(private=True)]}
        _ephemeral_key_tag = _ephemeral_key.kid
        # _wallet_entity_id = f"https://wallet.example.com/instance/{_ephemeral_key_tag}"
        _wallet.context.keyjar.import_jwks(_jwks, _wallet.entity_id)
        _wallet.context.ephemeral_key = {_ephemeral_key_tag: _ephemeral_key}

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
        response = _integrity_endpoint.process_request(parsed_args)
        response_args = response["response_args"]

        # Step 11-12

        hardware_key_tag = as_unicode(_wallet.context.crypto_hardware_key.kid)

        war_payload = {
            "challenge": challenge,
            "hardware_signature": as_unicode(base64.b64encode(hardware_signature)),
            "integrity_assertion": as_unicode(response_args["integrity_assertion"]),
            "hardware_key_tag": hardware_key_tag,
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
        response = _token_endpoint.process_request(parsed_args)

        return response["response_args"]["assertion"], _ephemeral_key_tag
