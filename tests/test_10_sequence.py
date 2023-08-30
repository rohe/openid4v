import json
import os

import pytest
import responses
from cryptojwt.key_jar import init_key_jar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.oauth2 import Client

_dirname = os.path.dirname(os.path.abspath(__file__))

CLI_KEY = init_key_jar(
    public_path="{}/pub_client.jwks".format(_dirname),
    private_path="{}/priv_client.jwks".format(_dirname),
    key_defs=DEFAULT_KEY_DEFS,
    issuer_id="client_id",
)


class TestAuthorizationRequest():

    @pytest.fixture(autouse=True)
    def create_client(self):
        config = {
            "client_id": "client_id",
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "preference": {"response_types": ["code"]},
            "add_ons": {
                "pushed_authorization": {
                    "function": "idpyoidc.client.oauth2.add_on.par.add_support",
                    "kwargs": {
                        "body_format": "jws",
                        "signing_algorithm": "ES256",
                        "http_client": None,
                        "merge_rule": "lax",
                    },
                },
                "pkce": {
                    "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                    "kwargs": {"code_challenge_length": 64, "code_challenge_method": "S256"},
                },
                "dpop": {
                    "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
                    "kwargs": {"dpop_signing_alg_values_supported": ["ES256", "ES512"]},
                }
            },
            "services": {
                "authorization": {"class": "oidc4vc.client.authorization.Authorization"},
                "access_token": {"class": "oidc4vc.client.access_token.AccessToken"},
                "credential": {"class": "oidc4vc.client.credential.Credential"}
            },
            "provider_info": {
                "authorization_endpoint": "https://issuer.example.com/auth",
                "token_endpoint": "https://issuer.example.com/token",
                "credential_endpoint": "https://issuer.example.com/credential",
                "dpop_signing_alg_values_supported": ["RS256", "ES256"],
                "pushed_authorization_request_endpoint": "https://issuer.example.com/push"
            }
        }
        self.entity = Client(keyjar=CLI_KEY, config=config)

    def test_authorization_request(self):
        auth_service = self.entity.get_service("authorization")
        req_args = {
            "response_type": "code",
            "authorization_details": [
                {
                    "type": "openid_credential",
                    "format": "jwt_vc_json",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential",
                            "UniversityDegreeCredential"
                        ]
                    }
                }
            ]
        }
        with responses.RequestsMock() as rsps:
            _resp = {"request_uri": "urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2", "expires_in": 3600}
            rsps.add(
                "GET",
                auth_service.upstream_get("context").provider_info[
                    "pushed_authorization_request_endpoint"
                ],
                body=json.dumps(_resp),
                status=200,
            )

            _req = auth_service.construct(request_args=req_args, state="state")

        assert set(_req.keys()) == {"request_uri", "response_type", "client_id"}
        _item = self.entity.context.cstate.get('state')
        assert _item['response_type'] == "code"
        assert _item['redirect_uri'] == 'https://example.com/cli/authz_cb'