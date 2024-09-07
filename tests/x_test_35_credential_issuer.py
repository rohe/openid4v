import json
import os

import pytest
import responses
from fedservice.entity import get_verified_trust_chains
from idpyoidc.client.oauth2.add_on.par import push_authorization
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.util import rndstr

from examples import create_trust_chain_messages
from openid4v.message import AuthorizationServerMetadata
from openid4v.message import OpenidCredentialIssuer
from tests.build_federation import build_federation

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


TA_ID = "https://ta.example.org"
WALLET_PROVIDER_ID = "https://wp.example.org"
CREDENTIAL_ISSUER_ID = "https://ci.example.org"
WALLET_ID = "https://wallet.example.org"

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [WALLET_PROVIDER_ID, CREDENTIAL_ISSUER_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ["entity_configuration", "list", "fetch", "resolve"],
        }
    },
    WALLET_PROVIDER_ID: {
        "entity_type": "wallet_provider",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID]
        }
    },
    CREDENTIAL_ISSUER_ID: {
        "entity_type": "openid_credential_issuer",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID]
        }
    },
    WALLET_ID: {
        "entity_type": "wallet",
        "trust_anchors": [TA_ID],
        "kwargs": {}
    }
}


class TestCredentialIssuer():

    @pytest.fixture(autouse=True)
    def create_federation(self):
        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.wallet_provider = federation[WALLET_PROVIDER_ID]
        self.credential_issuer = federation[CREDENTIAL_ISSUER_ID]
        self.wallet = federation[WALLET_ID]

    def test_metadata(self):
        metadata = self.credential_issuer.get_metadata()
        assert set(metadata.keys()) == {'federation_entity', "oauth_authorization_server",
                                        "openid_credential_issuer"}

        as_metadata = AuthorizationServerMetadata(**metadata["oauth_authorization_server"])
        as_metadata.verify()

        ci_metadata = OpenidCredentialIssuer(**metadata["openid_credential_issuer"])
        ci_metadata.verify()

    def _create_wia(self):
        # First get the nonce
        _server = self.wallet_provider["wallet_provider"]
        _endpoint = _server.get_endpoint("challenge")
        _aa_response = _endpoint.process_request()
        _aa_response_args = _aa_response["response_args"]
        _msg = _aa_response_args
        _nonce = _msg["nonce"]

        # Now for the Wallet Instance Attestation
        wallet_entity = self.wallet["wallet"]
        _service = wallet_entity.get_service("wallet_instance_attestation")
        _service.wallet_provider_id = WALLET_PROVIDER_ID
        ephemeral_key = wallet_entity.mint_new_key()

        request_args = {
            "aud": WALLET_PROVIDER_ID,
            #  "challenge": SINGLE_REQUIRED_STRING,
            "challenge": _nonce,
            # "hardware_signature": SINGLE_REQUIRED_STRING,
            "hardware_signature": "__hardware_signature__",
            # "integrity_assertion": SINGLE_REQUIRED_STRING,
            "integrity_assertion": "__integrity_assertion__",
            # "hardware_key_tag": SINGLE_REQUIRED_STRING,
            "hardware_key_tag": "__hardware_key_tag__",
            # "cnf": SINGLE_REQUIRED_JSON,
            "cnf": {"jwk": ephemeral_key.serialize()},
            "vp_formats_supported": {
                "jwt_vp_json": {
                    "alg_values_supported": ["ES256"]
                },
                "jwt_vc_json": {
                    "alg_values_supported": ["ES256"]
                }
            }
        }
        req_info = _service.get_request_parameters(
            request_args,
            endpoint=f"{WALLET_PROVIDER_ID}/token",
            ephemeral_key=ephemeral_key
        )

        _endpoint = _server.get_endpoint("wallet_provider_token")
        _wia_request = _endpoint.parse_request(req_info["request"])
        assert set(_wia_request.keys()) == {'assertion', 'grant_type', '__verified_assertion'}
        # __verified_assertion is the unpacked assertion after the signature has been verified
        # __client_id is carried in the nonce

        # _msgs = create_trust_chain_messages(self.wallet_provider, self.ta)
        #
        # with responses.RequestsMock() as rsps:
        #     for _url, _jwks in _msgs.items():
        #         rsps.add("GET", _url, body=_jwks,
        #                  adding_headers={"Content-Type": "application/json"}, status=200)

        _response = _endpoint.process_request(_wia_request)

        return _response["response_args"]["assertion"], _wia_request['__verified_assertion']["iss"]

    def test_qeaa_flow(self):
        _wia, _thumbprint = self._create_wia()
        assert _wia

        oic = self.credential_issuer["openid_credential_issuer"]
        oas = self.credential_issuer["oauth_authorization_server"]

        _handler = self.wallet["pid_eaa_consumer"]
        _actor = _handler.get_consumer(oas.context.entity_id)
        if _actor is None:
            _actor = _handler.new_consumer(oas.context.entity_id)
            _msgs = create_trust_chain_messages(self.credential_issuer, self.ta)

            with responses.RequestsMock() as rsps:
                for _url, _jwks in _msgs.items():
                    rsps.add("GET", _url, body=_jwks,
                             adding_headers={"Content-Type": "application/json"}, status=200)

                _trust_chains = get_verified_trust_chains(_actor, oas.context.entity_id)
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

        _par_endpoint = oas.get_endpoint("pushed_authorization")
        _request_uri = "urn:uuid:bwc4JK-ESC0w8acc191e-Y1LTC2"
        # The response from the PAR endpoint
        _resp = {"request_uri": _request_uri, "expires_in": 3600}
        # the authorization stored on the server
        oas.context.par_db[_request_uri] = req_args

        with responses.RequestsMock() as rsps:
            rsps.add("POST", _par_endpoint.full_path, body=json.dumps(_resp),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            # PAR request
            _req = push_authorization(request_args=AuthorizationRequest(**req_args),
                                      service=_service,
                                      client_assertion=_wia)

        _authz_endpoint = oas.get_endpoint("authorization")
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

        _endp = oas.get_endpoint("token")
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
        _req = _endp.parse_request(cred_req_info["request"],
                                   http_info={"headers": cred_req_info["headers"]})
        _resp = _endp.process_request(_req)
        assert _resp
        assert set(_resp["response_args"].keys()) == {'c_nonce_expires_in', 'c_nonce', 'format',
                                                      'credential'}
