import logging

from examples import execute_function

#              TA
#          +------|---+
#          |          |
#         IM1        IM2
#          |          |
#    WalletProvider   +-----+----------+
#                     |     |          |
#                    RP  PIDIssuer QEEAIssuer

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
WP_ID = "https://wp.example.org"
IM1_ID = "https://im1.example.org"
IM2_ID = "https://im2.example.org"
PID_ID = "https://pid.example.org"
QEEA_ID = "https://qeea.example.org"

logger = logging.getLogger(__name__)


def federation_setup():
    ##################
    # TRUST ANCHOR
    ##################

    logger.info("---- Trust Anchor ----")
    kwargs = {
        "entity_id": TA_ID,
        "preference": {
            "organization_name": "The example federation operator",
            "homepage_uri": "https://ta.example.com",
            "contacts": "operations@ta.example.com"
        }
    }
    trust_anchor = execute_function('members.ta.main', **kwargs)
    logger.debug(f"Creating Trust Anchor: entity_id={TA_ID}")
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
    im1 = execute_function("members.intermediate.main", **kwargs)

    logger.debug(f"Registering '{IM1_ID}' as subordinate to '{TA_ID}'")

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
    im2 = execute_function("members.intermediate.main", **kwargs)

    logger.debug(f"Registering '{IM2_ID}' as subordinate to '{TA_ID}'")

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
    rp = execute_function("members.rp.main", **kwargs)

    logger.debug(f"Registering '{RP_ID}' as subordinate to '{IM1_ID}'")

    im1.server.subordinate[RP_ID] = {
        "jwks": rp.keyjar.export_jwks(),
        'authority_hints': [IM1_ID],
        "registration_info": {"entity_types": ["federation_entity", "relying_party"]},
    }

    ########################################
    # Wallet provider
    ########################################

    logger.info("---- Wallet Provider ----")
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
    wallet_provider = execute_function("members.wallet_provider.main", **kwargs)

    logger.debug(f"Registering '{WP_ID}' as subordinate to '{IM2_ID}'")

    im2.server.subordinate[WP_ID] = {
        "jwks": wallet_provider['federation_entity'].keyjar.export_jwks(),
        'authority_hints': [IM2_ID],
        "registration_info": {"entity_types": ["federation_entity", "wallet_provider"]},
    }

    #########################################
    # OpenidCredentialIssuer - PID version
    #########################################

    logger.info("---- Openid Credential Issuer PID variant ----")
    logger.info("--- Subordinate to intermediate 2 ---")

    kwargs = {
        "entity_id": PID_ID,
        "preference": {
            "organization_name": "The OpenID PID Credential Issuer",
            "homepage_uri": "https://pid.example.com",
            "contacts": "operations@pid.example.com"
        },
        "authority_hints": [IM2_ID],
        "trust_anchors": trust_anchors
    }

    pid = execute_function("members.pid.main", **kwargs)

    logger.debug(f"Registering '{PID_ID}' as subordinate to '{IM2_ID}'")

    im2.server.subordinate[PID_ID] = {
        "jwks": pid['federation_entity'].keyjar.export_jwks(),
        'authority_hints': [IM2_ID],
        "registration_info": {"entity_types": ["federation_entity", "openid_credential_issuer"]},
    }


    #########################################
    # OpenidCredentialIssuer - (Q)EEA version
    #########################################

    logger.info("---- Openid Credential Issuer QEEA variant ----")
    logger.info("--- Outside the federation ---")

    kwargs = {
        "entity_id": QEEA_ID,
        "preference": {
            "organization_name": "The OpenID QEEA Credential Issuer",
            "homepage_uri": "https://qeea.example.com",
            "contacts": "operations@qeea.example.com"
        },
        "authority_hints": [IM2_ID],
        "trust_anchors": trust_anchors
    }

    qeea = execute_function("members.qeea.main", **kwargs)

    logger.debug(f"Registering '{QEEA_ID}' as subordinate to '{IM2_ID}'")

    im2.server.subordinate[QEEA_ID] = {
        "jwks": qeea['federation_entity'].keyjar.export_jwks(),
        'authority_hints': [IM2_ID],
        "registration_info": {"entity_types": ["federation_entity", "openid_credential_issuer"]},
    }


    # ------------- return federation entities --------------

    return {
        "ta": trust_anchor,
        "im1": im1,
        "im2": im2,
        "wp": wallet_provider,
        "rp": rp,
        "pid": pid,
        "qeea": qeea
    }


if __name__ == "__main__":
    print(federation_setup())
