from idpyoidc.key_import import import_jwks

from examples import execute_function

WALLET_ID = "s6BhdRkqt3"


def wallet_setup(federation):
    #########################################
    # Wallet
    #########################################

    _anchor = federation["ta"]
    trust_anchors = {_anchor.entity_id: _anchor.keyjar.export_jwks()}

    kwargs = {
        "entity_id": WALLET_ID,
        "trust_anchors": trust_anchors
    }
    wallet = execute_function("members.wallet.main", **kwargs)

    # Need the wallet providers public keys. Could get this from the metadata
    _keyjar = wallet["federation_entity"]
    _keyjar = import_jwks(_keyjar,
                          federation["wp"]["wallet_provider"].context.keyjar.export_jwks(),
                          federation["wp"].entity_id)

    return wallet
