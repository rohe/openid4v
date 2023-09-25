from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from idpyoidc.server.util import execute

#              TA
#          +------|---+
#          |          |
#         IM1        IM2
#          |          |
#    WalletProvider   +--+--+
#                     |     |
#                    RP  PIDIssuer

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
WP_ID = "https://wp.example.org"
IM1_ID = "https://im1.example.org"
IM2_ID = "https://im2.example.org"
OCI_ID = "https://pid.example.org"
WALLET_ID = "s6BhdRkqt3"


SESSION_PARAMS = {
    "encrypter": {
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
}


def federation_setup():
    # TRUST ANCHOR

    kwargs = {
        "entity_id": TA_ID,
        "preference": {
            "organization_name": "The example federation operator",
            "homepage_uri": "https://ta.example.com",
            "contacts": "operations@ta.example.com"
        }
    }
    trust_anchor = execute('members.ta', **kwargs)

    trust_anchors = {TA_ID: trust_anchor.keyjar.export_jwks()}

    ##################
    # intermediate 1
    ##################

    kwargs = {
        "entity_id": IM1_ID,
        "preference": {
            "organization_name": "Intermediate 1",
            "homepage_uri": "https://im1.example.com",
            "contacts": "operations@example.com"
        },
        "authority_hints": [TA_ID],
        "trust_anchors": trust_anchors
    }
    im1 = execute("members.intermediate", **kwargs)

    ##################
    # intermediate 2
    ##################

    kwargs = {
        "entity_id": IM2_ID,
        "preference": {
            "organization_name": "Intermediate 2",
            "homepage_uri": "https://im2.example.com",
            "contacts": "operations@example.com"
        },
        "authority_hints": [TA_ID],
        "trust_anchors": trust_anchors
    }
    im2 = execute("members.intermediate", **kwargs)

    ########################################
    # Leaf
    ########################################

    kwargs = {
        "entity_id": RP_ID,
        "preference": {
            "organization_name": "The RP",
            "homepage_uri": "https://rp.example.com",
            "contacts": "operations@rp.example.com"
        },
        "authority_hints": [IM1_ID],
        "trust_anchors": trust_anchors
    }
    rp = execute("members.rp", **kwargs)

    ########################################
    # Wallet provider
    ########################################

    kwargs = {
        "entity_id": WP_ID,
        "preference": {
            "organization_name": "The Wallet Provider",
            "homepage_uri": "https://wp.example.com",
            "contacts": "operations@wp.example.com"
        },
        "authority_hints": [IM2_ID],
        "trust_anchors": trust_anchors
    }
    wp = execute("members.wallet_provider", **kwargs)

    #########################################
    # OpenidCredentialIssuer
    #########################################

    kwargs = {
        "entity_id": WP_ID,
        "preference": {
            "organization_name": "The OpenID Credential Issuer",
            "homepage_uri": "https://pid.example.com",
            "contacts": "operations@pid.example.com"
        },
        "authority_hints": [IM2_ID],
        "trust_anchors": trust_anchors
    }

    pid = execute("members.pid", **kwargs)

    # Setup subordinates

    trust_anchor.server.subordinate[IM1_ID] = {
        "jwks": im1.keyjar.export_jwks(),
        'authority_hints': [TA_ID],
        "registration_info": {
            "entity_types": ["federation_entity"],
            "intermediate": True
        }
    }

    trust_anchor.server.subordinate[IM2_ID] = {
        "jwks": im2.keyjar.export_jwks(),
        'authority_hints': [TA_ID],
        "registration_info": {
            "entity_types": ["federation_entity"],
            "intermediate": True
        }
    }

    im2.server.subordinate[WP_ID] = {
        "jwks": wp['federation_entity'].keyjar.export_jwks(),
        'authority_hints': [IM2_ID],
        "registration_info": {"entity_types": ["federation_entity", "wallet_provider"]},
    }

    im2.server.subordinate[OCI_ID] = {
        "jwks": pid['federation_entity'].keyjar.export_jwks(),
        'authority_hints': [IM2_ID],
        "registration_info": {"entity_types": ["federation_entity", "openid_credential_issuer"]},
    }

    im1.server.subordinate[RP_ID] = {
        "jwks": rp.keyjar.export_jwks(),
        'authority_hints': [IM1_ID],
        "registration_info": {"entity_types": ["federation_entity", "relying_party"]},
    }

    #########################################
    # Wallet
    #########################################

    kwargs = {
        "entity_id": WALLET_ID,
        "trust_anchors": trust_anchors
    }
    wallet = execute("members.wallet", **kwargs)

    return {
        "ta": trust_anchor,
        "im1": im1,
        "im2": im2,
        "wp": wp,
        "rp": rp,
        "pid": pid
    }


