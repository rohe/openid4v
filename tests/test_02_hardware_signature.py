import json

import pytest
from cryptojwt.jwk.ec import new_ec_key

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


class TestHardwareSignature(object):

    @pytest.fixture(autouse=True)
    def federation_setup(self):
        self.federation = build_federation(FEDERATION_CONFIG)
        self.ta = self.federation[TA_ID]
        self.wp = self.federation[WP_ID]
        self.wallet = self.federation[WALLET_ID]

    def test(self):
        ephemeral_key = new_ec_key('P-256')
        _wallet = self.wallet["wallet"]
        _wallet.context.crypto_hardware_key = new_ec_key('P-256')
        _wallet.context.wia_flow[ephemeral_key.kid] = {}

        hardware_sig = _wallet.create_hardware_signature(challenge="CHALLENGE",
                                                         ephemeral_key_tag=ephemeral_key.kid)

        self.wp["device_integrity_service"].context.crypto_hardware_key = {
            _wallet.context.crypto_hardware_key.kid: _wallet.context.crypto_hardware_key}

        _token = self.wp["wallet_provider"].get_endpoint("wallet_provider_token")
        assert _token.validate_hardware_signature(
            cnf={"jwk": ephemeral_key.serialize()},
            challenge="CHALLENGE",
            hardware_signature=hardware_sig,
            hardware_key_tag = _wallet.context.crypto_hardware_key.kid
        )
