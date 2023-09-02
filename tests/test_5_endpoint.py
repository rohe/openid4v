import os

import pytest
from cryptojwt.key_jar import build_keyjar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.server import ASConfiguration
from idpyoidc.server.client_authn import verify_client

from oidc4vci.wallet_provider import ServerEntity
from oidc4vci.wallet_provider.token import Token

BASEDIR = os.path.abspath(os.path.dirname(__file__))
CLIENT_KEYJAR = build_keyjar(DEFAULT_KEY_DEFS)

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
        },
        "client_authn": verify_client,

    }


class TestEndpoint(object):

    @pytest.fixture(autouse=True)
    def create_endpoint(self, conf):
        server = ServerEntity(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        server.keyjar.import_jwks(CLIENT_KEYJAR.export_jwks(), "client_1")
        self.token_endpoint = server.get_endpoint("token")


def test():
    pass
