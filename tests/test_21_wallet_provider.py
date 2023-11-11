import pytest
from fedservice.defaults import LEAF_ENDPOINTS

from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

WALLET_PROVIDER_ID = "https://127.0.0.1:4000"
TA_ID = "https://ta.example.org"


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
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
            preference= {
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
            authority_hints=["https://auth.example.com"],
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            endpoints=LEAF_ENDPOINTS,
            trust_anchors=TRUST_ANCHORS,
            entity_type={
                "wallet_provider": {
                    'class': 'openid4v.wallet_provider.WalletProvider',
                    'kwargs': {
                        'config': {
                            "keys": {"key_defs": DEFAULT_KEY_DEFS},
                            "endpoint": {
                                "token": {
                                    "path": "token",
                                    "class": "openid4v.wallet_provider.token.Token",
                                    "kwargs": {
                                        "client_authn_method": [
                                            "client_secret_post",
                                            "client_secret_basic",
                                            "client_secret_jwt",
                                            "private_key_jwt",
                                        ],
                                    },
                                }
                            },
                            'preference': {
                                "policy_uri": "https://wallet-provider.example.org/privacy_policy",
                                "tos_uri": "https://wallet-provider.example.org/info_policy",
                                "logo_uri": "https://wallet-provider.example.org/logo.svg",
                                "attested_security_context":
                                    "https://wallet-provider.example.org/LoA/basic",
                                "type": "WalletInstanceAttestation",
                                "authorization_endpoint": "eudiw:",
                                "response_types_supported": [
                                    "vp_token"
                                ],
                                "vp_formats_supported": {
                                    "jwt_vp_json": {
                                        "alg_values_supported": ["ES256"]
                                    },
                                    "jwt_vc_json": {
                                        "alg_values_supported": ["ES256"]
                                    }
                                },
                                "request_object_signing_alg_values_supported": [
                                    "ES256"
                                ],
                                "presentation_definition_uri_supported": False,
                            }
                        }
                    }
                }
            }
        )

    def test_metadata(self):
        _metadata = self.wp.get_metadata()
        assert set(_metadata.keys()) == {"federation_entity", "wallet_provider"}

