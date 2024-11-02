from cryptojwt import JWT
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.key_jar import build_keyjar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.key_import import store_under_other_id
from idpyoidc.util import rndstr


class Wallet(object):
    def __init__(self, id):
        self.id = id
        self.keyjar = build_keyjar(DEFAULT_KEY_DEFS)
        self.keyjar = store_under_other_id(self.keyjar, "", self.id, True)

    def create_wallet_instance_attestation_request(self, wallet_provider_id):
        ec_key = new_ec_key(crv="P-256", key_ops=["sign"])
        self.keyjar.add_keys(issuer_id=self.id, keys=[ec_key])

        _jwt = JWT(key_jar=self.keyjar, sign_alg='ES256', iss=self.id)
        _jwt.with_jti = True

        payload = {
            "type": "WalletInstanceAttestationRequest",
            "nonce": rndstr(),  # create nonce
            "cnf": {
                "jwk": ec_key.serialize()
            }
        }

        return _jwt.pack(payload,
                         aud=wallet_provider_id,
                         kid=ec_key.kid,
                         issuer_id=self.id,
                         jws_headers={"typ": "var+jwt"})

    def create_credential_request(self):
        pass
