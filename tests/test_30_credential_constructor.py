import os

import pytest
import responses
from cryptojwt import JWT
from cryptojwt.jwk.ec import new_ec_key
from idpyoidc.key_import import import_jwks
from idpyoidc.util import rndstr

from examples.entities.flask_wallet.views import hash_func
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


TA_ID = "https://ta.example.org"
WP_ID = "https://wp.example.org"
PID_ID = "https://pid.example.org"
WALLET_ID = "I_am_the_wallet"

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [WP_ID, PID_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    PID_ID: {
        "entity_type": "openid_credential_issuer",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "httpc_params": {"verify": False},
            "preference": {
                "organization_name": "The OpenID PID Credential Issuer",
                "homepage_uri": "https://pid.example.com",
                "contacts": "operations@pid.example.com"
            },
            "authority_hints": [TA_ID],
            "entity_type_config": {
                "openid_credential_issuer": {
                    "session_management": False,
                    "endpoint": {
                        "credential": {
                            "path": "credential",
                            "class": "openid4v.openid_credential_issuer.credential.Credential",
                            "kwargs": {
                                "client_authn_method": [
                                    "dpop_client_auth"
                                ],
                                "credential_constructor": {
                                    "PDA1Credential": {
                                        "class":
                                            "openid4v.openid_credential_issuer.credential_constructor.authentic_source.CredentialConstructor",
                                        "kwargs": {
                                            "url": "http://vc-interop-1.sunet.se/api/v1/credential",
                                            "jwks_url": "http://vc-interop-1.sunet.se/api/v1/credential/.well-known/jwks",
                                            "body": {
                                                "authentic_source": "SUNET",
                                                "document_type": "PDA1",
                                                "credential_type": "sdjwt"
                                            }
                                        }
                                    },
                                    "EHICCredential": {
                                        "class":
                                            "openid4v.openid_credential_issuer.credential_constructor.authentic_source.CredentialConstructor",
                                        "kwargs": {
                                            "url": "http://vc-interop-1.sunet.se/api/v1/credential",
                                            "jwks_url": "http://vc-interop-1.sunet.se/api/v1/credential/.well-known/jwks",
                                            "body": {
                                                "authentic_source": "SUNET",
                                                "document_type": "EHIC",
                                                "credential_type": "sdjwt"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "revocation": {
                            "path": "revocation",
                            "class": "openid4v.openid_credential_issuer.revocation.Revocation"
                        },
                        "status_attestation": {
                            "path": "status_attestation",
                            "class": "openid4v.openid_credential_issuer.status_attestation.StatusAttestation"
                        }
                    }
                }
            }
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


class TestPID():

    @pytest.fixture(autouse=True)
    def federation_setup(self):
        #          TA --------+
        #          |          |
        #       +--+--+       |
        #       |     |       |
        #      PID    WP   WALLET

        self.federation = build_federation(FEDERATION_CONFIG)
        self.ta = self.federation[TA_ID]
        self.pid = self.federation[PID_ID]
        self.wp = self.federation[WP_ID]
        self.wallet = self.federation[WALLET_ID]

    def test_pid_issuer_metadata(self):
        where_and_what = create_trust_chain_messages(self.pid, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            # collect metadata for PID issuer
            pid_issuer_metadata = self.wallet["federation_entity"].get_verified_metadata(
                self.pid.entity_id)

        assert set(pid_issuer_metadata.keys()) == {'openid_credential_issuer',
                                                   'oauth_authorization_server',
                                                   'federation_entity'}

    def wallet_attestation_issuance(self):
        _wallet = self.wallet["wallet"]
        _wallet_provider = self.wp["wallet_provider"]

        _ephemeral_key = new_ec_key('P-256')
        _ephemeral_key.use = "sig"
        _jwks = {"keys": [_ephemeral_key.serialize(private=True)]}
        _ephemeral_key_tag = _ephemeral_key.kid
        # _wallet_entity_id = f"https://wallet.example.com/instance/{_ephemeral_key_tag}"
        _wallet.context.keyjar = import_jwks(_wallet.context.keyjar, _jwks, _wallet.entity_id)
        _wallet.context.ephemeral_key = {_ephemeral_key_tag: _ephemeral_key}

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

    def _create_pushed_authz_response(self, authn_request):
        pushed_authorization_endpoint = self.pid["oauth_authorization_server"].get_endpoint(
            "pushed_authorization")

        _cred = self.wallet
        http_info = {
            "headers": {"authorization": "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3"}
        }

        _req = pushed_authorization_endpoint.parse_request(authn_request, http_info=http_info)

        _resp = pushed_authorization_endpoint.process_request(_req)
        return _resp

    @pytest.disable()
    def test_authorization_EHIC(self):
        where_and_what = create_trust_chain_messages(self.pid,
                                                     self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            # collect metadata for PID issuer
            pid_issuer_metadata = self.wallet["federation_entity"].get_verified_metadata(
                self.pid.entity_id)

        wallet_instance_attestation, _ephemeral_key_tag = self.wallet_attestation_issuance()

        # authorization_endpoint = pid_issuer_metadata["oauth_authorization_server"][
        # "authorization_endpoint"]

        handler = self.wallet["pid_eaa_consumer"]
        actor = handler.new_consumer(self.pid.entity_id)
        authorization_service = actor.get_service("authorization")
        authorization_service.certificate_issuer_id = self.pid.entity_id

        b64hash = hash_func(self.pid.entity_id)
        _redirect_uri = f"https://127.0.0.1:5005/authz_cb/{b64hash}"

        request_args = {
            "authorization_details": [
                {
                    "type": "openid_credential",
                    "format": "vc+sd-jwt",
                    "vct": "EHICCredential"
                }
            ],
            "response_type": "code",
            "client_id": _ephemeral_key_tag,
            "redirect_uri": _redirect_uri,
            "issuer_state": "authentic_source=authentic_source_se&document_type=EHIC&collect_id=collect_id_10"
        }

        kwargs = {
            "state": rndstr(24),
            "wallet_instance_attestation": wallet_instance_attestation,
            "signing_key": self.wallet["wallet"].context.ephemeral_key[_ephemeral_key_tag]
        }

        authz_req = authorization_service.get_request_parameters(request_args=request_args,
                                                                 **kwargs)

        # The PID Issuer parses the authz request

        _authorization_endpoint = self.pid["oauth_authorization_server"].get_endpoint(
            'authorization')
        _authorization_endpoint.request_format = "url"

        where_and_what = create_trust_chain_messages(self.wp, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            parsed_args = _authorization_endpoint.parse_request(authz_req["url"],
                                                                http_info={"headers": authz_req["headers"]})

        authz_response = _authorization_endpoint.process_request(parsed_args)

        assert authz_response

        # Now for the token request

        _args = {
            "audience": self.pid.entity_id,
            "thumbprint": _ephemeral_key_tag,
            "wallet_instance_attestation": wallet_instance_attestation,
            "signing_key": self.wallet["wallet"].context.ephemeral_key[_ephemeral_key_tag]
        }

        _lifetime = self.wallet["pid_eaa_consumer"].config.get("jwt_lifetime", None)
        if _lifetime:
            _args["lifetime"] = _lifetime

        _request_args = {
            "code": authz_response['response_args']["code"],
            "grant_type": "authorization_code",
            "redirect_uri": parsed_args["redirect_uri"],
            "state": authz_response['response_args']["state"]
        }

        _token_service = actor.get_service("accesstoken")
        _metadata = self.wallet["federation_entity"].get_verified_metadata(self.pid.entity_id)
        _args["endpoint"] = _metadata['oauth_authorization_server']['token_endpoint']
        token_req_info = _token_service.get_request_parameters(_request_args, **_args)
        assert token_req_info

        assert "dpop" in token_req_info["headers"]

        # Token endpoint

        _token_endpoint = self.pid["oauth_authorization_server"].get_endpoint("token")
        _http_info = {
            "headers": token_req_info["headers"],
            "url": token_req_info["url"],
            "method": token_req_info["method"]}

        parsed_args = _token_endpoint.parse_request(token_req_info["body"], http_info=_http_info)

        token_response = _token_endpoint.process_request(parsed_args)

        assert token_response

        _context = _token_service.upstream_get("context")
        _context.cstate.update(authz_response['response_args']["state"],
                               token_response["response_args"])

        # credential issuer service

        _credential_service = actor.get_service("credential")

        _request_args = {
            "format": 'vc+sd-jwt'
        }

        _args = {
            "state": authz_response['response_args']["state"]
        }

        req_info = _credential_service.get_request_parameters(request_args=_request_args, **_args)

        assert req_info

        assert req_info["headers"]["Authorization"].startswith("DPoP")

        _credential_endpoint = self.pid["openid_credential_issuer"].get_endpoint("credential")

        _http_info = {
            "headers": req_info["headers"],
            "url": req_info["url"],
            "method": req_info["method"]}
        parsed_args = _credential_endpoint.parse_request(req_info["body"], http_info=_http_info)

        credential_response = _credential_endpoint.process_request(parsed_args)

        assert "error" not in credential_response

    @pytest.disable()
    def test_authorization_PDA1(self):
        where_and_what = create_trust_chain_messages(self.pid,
                                                     self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            # collect metadata for PID issuer
            pid_issuer_metadata = self.wallet["federation_entity"].get_verified_metadata(
                self.pid.entity_id)

        wallet_instance_attestation, _ephemeral_key_tag = self.wallet_attestation_issuance()

        # authorization_endpoint = pid_issuer_metadata["oauth_authorization_server"][
        # "authorization_endpoint"]

        handler = self.wallet["pid_eaa_consumer"]
        actor = handler.new_consumer(self.pid.entity_id)
        authorization_service = actor.get_service("authorization")
        authorization_service.certificate_issuer_id = self.pid.entity_id

        b64hash = hash_func(self.pid.entity_id)
        _redirect_uri = f"https://127.0.0.1:5005/authz_cb/{b64hash}"

        # request_args = {
        #     "authorization_details": [
        #         {
        #             "type": "openid_credential",
        #             "format": "vc+sd-jwt",
        #             "vct": "PDA1Credential"
        #         }
        #     ],
        #     "response_type": "code",
        #     "client_id": _ephemeral_key_tag,
        #     "redirect_uri": _redirect_uri,
        #     "authentic_source": 'authentic_source_dk',
        #     "document_type": 'PDA1',
        #     "collect_id": "collect_id_20"
        # }

        request_args = {
            "authorization_details": [
                {
                    "type": "openid_credential",
                    "format": "vc+sd-jwt",
                    "vct": "PDA1Credential"
                }
            ],
            "response_type": "code",
            "client_id": _ephemeral_key_tag,
            "redirect_uri": _redirect_uri,
            "issuer_state": "authentic_source=authentic_source_dk&document_type=PDA1&collect_id=collect_id_20"
        }

        kwargs = {
            "state": rndstr(24),
            "wallet_instance_attestation": wallet_instance_attestation,
            "signing_key": self.wallet["wallet"].context.ephemeral_key[_ephemeral_key_tag]
        }

        authz_req = authorization_service.get_request_parameters(request_args=request_args,
                                                                 **kwargs)

        # The PID Issuer parses the authz request

        _authorization_endpoint = self.pid["oauth_authorization_server"].get_endpoint(
            'authorization')
        _authorization_endpoint.request_format = "url"

        where_and_what = create_trust_chain_messages(self.wp, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            parsed_args = _authorization_endpoint.parse_request(authz_req["url"],
                                                                http_info={"headers": authz_req["headers"]})

        authz_response = _authorization_endpoint.process_request(parsed_args)

        assert authz_response

        # Now for the token request

        _args = {
            "audience": self.pid.entity_id,
            "thumbprint": _ephemeral_key_tag,
            "wallet_instance_attestation": wallet_instance_attestation,
            "signing_key": self.wallet["wallet"].context.ephemeral_key[_ephemeral_key_tag]
        }

        _lifetime = self.wallet["pid_eaa_consumer"].config.get("jwt_lifetime", None)
        if _lifetime:
            _args["lifetime"] = _lifetime

        _request_args = {
            "code": authz_response['response_args']["code"],
            "grant_type": "authorization_code",
            "redirect_uri": parsed_args["redirect_uri"],
            "state": authz_response['response_args']["state"]
        }

        _token_service = actor.get_service("accesstoken")
        _metadata = self.wallet["federation_entity"].get_verified_metadata(self.pid.entity_id)
        _args["endpoint"] = _metadata['oauth_authorization_server']['token_endpoint']
        token_req_info = _token_service.get_request_parameters(_request_args, **_args)
        assert token_req_info

        assert "dpop" in token_req_info["headers"]

        # Token endpoint

        _token_endpoint = self.pid["oauth_authorization_server"].get_endpoint("token")
        _http_info = {
            "headers": token_req_info["headers"],
            "url": token_req_info["url"],
            "method": token_req_info["method"]}

        parsed_args = _token_endpoint.parse_request(token_req_info["body"], http_info=_http_info)

        token_response = _token_endpoint.process_request(parsed_args)

        assert token_response

        _context = _token_service.upstream_get("context")
        _context.cstate.update(authz_response['response_args']["state"],
                               token_response["response_args"])

        # credential issuer service

        _credential_service = actor.get_service("credential")

        _request_args = {
            "format": 'vc+sd-jwt'
        }

        _args = {
            "state": authz_response['response_args']["state"]
        }

        req_info = _credential_service.get_request_parameters(request_args=_request_args, **_args)

        assert req_info

        assert req_info["headers"]["Authorization"].startswith("DPoP")

        _credential_endpoint = self.pid["openid_credential_issuer"].get_endpoint("credential")

        _http_info = {
            "headers": req_info["headers"],
            "url": req_info["url"],
            "method": req_info["method"]}
        parsed_args = _credential_endpoint.parse_request(req_info["body"], http_info=_http_info)

        credential_response = _credential_endpoint.process_request(parsed_args)

        assert "error" not in credential_response
