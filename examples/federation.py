import logging

from cryptojwt.utils import importer

logger = logging.getLogger()

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


def run(cls, **kwargs):
    _func = importer(f"{cls}.main")
    return _func(**kwargs)


def federation_setup():
    # TRUST ANCHOR
    logger.info("---- Trust Anchor ----")
    kwargs = {
        "entity_id": TA_ID,
        "preference": {
            "organization_name": "The example federation operator",
            "homepage_uri": "https://ta.example.com",
            "contacts": "operations@ta.example.com"
        }
    }
    trust_anchor = run('members.ta', **kwargs)

    trust_anchors = {TA_ID: trust_anchor.keyjar.export_jwks()}

    ##################
    # intermediate 1
    ##################
    logger.info("---- Intermediate 1 ----")
    logger.info("--- Subordinate to the Trust Anchor ---")

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
    im1 = run("members.intermediate", **kwargs)

    trust_anchor.server.subordinate[IM1_ID] = {
        "jwks": im1.keyjar.export_jwks(),
        'authority_hints': [TA_ID],
        "registration_info": {
            "entity_types": ["federation_entity"],
            "intermediate": True
        }
    }

    ##################
    # intermediate 2
    ##################

    logger.info("---- Intermediate 2 ----")
    logger.info("--- Subordinate to the Trust Anchor ---")

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
    im2 = run("members.intermediate", **kwargs)

    trust_anchor.server.subordinate[IM2_ID] = {
        "jwks": im2.keyjar.export_jwks(),
        'authority_hints': [TA_ID],
        "registration_info": {
            "entity_types": ["federation_entity"],
            "intermediate": True
        }
    }

    ########################################
    # Leaf
    ########################################

    logger.info("---- RP (not used) ----")
    logger.info("--- Subordinate to intermediate 1 ---")

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
    rp = run("members.rp", **kwargs)
    im1.server.subordinate[RP_ID] = {
        "jwks": rp.keyjar.export_jwks(),
        'authority_hints': [IM1_ID],
        "registration_info": {"entity_types": ["federation_entity", "relying_party"]},
    }

    ########################################
    # Wallet provider
    ########################################

    logger.info("---- Wallet ----")
    logger.info("--- Subordinate to intermediate 2 ---")

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
    wp = run("members.wallet_provider", **kwargs)

    im2.server.subordinate[WP_ID] = {
        "jwks": wp['federation_entity'].keyjar.export_jwks(),
        'authority_hints': [IM2_ID],
        "registration_info": {"entity_types": ["federation_entity", "wallet_provider"]},
    }

    #########################################
    # OpenidCredentialIssuer
    #########################################

    logger.info("---- Openid Credential Issuer ----")
    logger.info("--- Subordinate to intermediate 2 ---")

    kwargs = {
        "entity_id": OCI_ID,
        "preference": {
            "organization_name": "The OpenID Credential Issuer",
            "homepage_uri": "https://pid.example.com",
            "contacts": "operations@pid.example.com"
        },
        "authority_hints": [IM2_ID],
        "trust_anchors": trust_anchors
    }

    pid = run("members.pid", **kwargs)

    im2.server.subordinate[OCI_ID] = {
        "jwks": pid['federation_entity'].keyjar.export_jwks(),
        'authority_hints': [IM2_ID],
        "registration_info": {"entity_types": ["federation_entity", "openid_credential_issuer"]},
    }


    #########################################
    # Wallet
    #########################################

    logger.info("---- Openid Credential Issuer ----")
    logger.info("--- Outside the federation ---")

    kwargs = {
        "entity_id": WALLET_ID,
        "trust_anchors": trust_anchors,
        "wallet_provider": wp
    }
    wallet = run("members.wallet", **kwargs)

    ################## The whole set ###################

    return {
        "ta": trust_anchor,
        "im1": im1,
        "im2": im2,
        "wp": wp,
        "rp": rp,
        "pid": pid,
        "wallet": wallet
    }
