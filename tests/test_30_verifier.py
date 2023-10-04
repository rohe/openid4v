import json
import os

import pytest
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.user_info import UserInfo

from oidc4vci.verifier import Verifier

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())

CRYPT_CONFIG = {
    "kwargs": {
        "keys": {
            "key_defs": [
                {"type": "OCT", "use": ["enc"], "kid": "password"},
                {"type": "OCT", "use": ["enc"], "kid": "salt"},
            ]
        },
        "iterations": 1,
    }
}

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}


class TestEndpoint(object):

    @pytest.fixture(autouse=True)
    def create_server(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt zebra",
            "verify_ssl": False,
            "keys": {"key_defs": DEFAULT_KEY_DEFS},
            "token_handler_args": {
                "jwks_def": {
                    "key_defs": DEFAULT_KEY_DEFS,
                },
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                    },
                },
                "refresh": {"lifetime": 86400},
            },
            "endpoint": {
                "resource": {
                    "path": "{}/resource",
                    "class": "oidc4vci.verifier.resource.Resource",
                    "kwargs": {},
                }
            },
            "authentication": {
                "anon": {
                    "acr": "http://www.swamid.se/policy/assurance/al1",
                    "class": "idpyoidc.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_db}},
            "template_dir": "template",
            "authz": {
                "class": AuthzHandling,
                "kwargs": {
                    "grant_config": {
                        "usage_rules": {
                            "authorization_code": {
                                "supports_minting": [
                                    "access_token",
                                    "refresh_token",
                                    "id_token",
                                ],
                                "max_usage": 1,
                            },
                            "access_token": {},
                            "refresh_token": {
                                "supports_minting": [
                                    "access_token",
                                    "refresh_token",
                                    "id_token",
                                ],
                            },
                        },
                        "expires_in": 43200,
                    }
                },
            },
            "session_params": SESSION_PARAMS,
        }
        server = Verifier(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)

        context = server.context
        context.cdb = {}
        server.keyjar.import_jwks(server.keyjar.export_jwks(True, ""), conf["issuer"])
        self.context = context
        self.endpoint = server.get_endpoint("resource")
        self.session_manager = context.session_manager
        self.user_id = "diana"

        # self.rp_keyjar = KeyJar()
        # self.rp_keyjar.add_symmetric("client_1", "hemligtkodord1234567890")
        # self.endpoint.upstream_get("attribute", "keyjar").add_symmetric(
        #     "client_1", "hemligtkodord1234567890"
        # )

    def _create_session(self, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            areq = auth_req.copy()
            areq["sector_identifier_uri"] = sector_identifier
        else:
            areq = auth_req

        client_id = areq["client_id"]
        ae = create_authn_event(self.user_id)
        return self.session_manager.create_session(
            ae, areq, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def test_process_request(self):
        _pr_resp = self.endpoint.parse_request({})
        _resp = self.endpoint.process_request(_pr_resp)
        assert set(_resp.keys()) == {
            "response_args",
            "fragment_enc",
            "return_uri",
            "cookie",
            "session_id",
        }
