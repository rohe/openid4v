from typing import Optional

from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwk.asym import AsymmetricKey
from cryptojwt.jwk.ec import new_ec_key
from idpyoidc.client.client_auth import ClientAuthnMethod

from openid4v import ASSERTION_TYPE


class ClientAssertion(ClientAuthnMethod):

    def construct(self, request, service=None, http_args=None, **kwargs):
        if "client_assertion" not in request:
            request["client_assertion"] = kwargs["client_attestation"]

        request["client_assertion_type"] = ASSERTION_TYPE
        return {}


class ClientAuthenticationAttestation(object):

    def __call__(self,
                 entity_id: str,
                 signing_key: AsymmetricKey,
                 audience: str,
                 jwt_lifetime: Optional[int] = 360,
                 jwt_pop_lifetime: Optional[int] = 300,
                 nonce: Optional[str] = ""):
        client_instance_key = new_ec_key(crv="P-256", key_ops=["sign"])
        part1 = self.construct_client_attestation_jwt(entity_id, signing_key, client_instance_key,
                                                      lifetime=jwt_lifetime)
        part2 = self.construct_client_attestation_pop_jwt(entity_id, client_instance_key,
                                                          audience=audience,
                                                          lifetime=jwt_pop_lifetime, nonce=nonce)
        return f"{part1}~{part2}"

    def construct_client_attestation_jwt(self,
                                         entity_id: str,
                                         signing_key: AsymmetricKey,
                                         client_instance_key: AsymmetricKey,
                                         lifetime: Optional[int] = 0):
        keyjar = KeyJar()
        keyjar.add_keys(entity_id, keys=[signing_key])

        if lifetime:
            _signer = JWT(key_jar=keyjar, sign_alg='ES256', iss=entity_id, lifetime=lifetime)
        else:
            _signer = JWT(key_jar=keyjar, sign_alg='ES256', iss=entity_id)

        payload = {
            "cnf": {
                "jwk": client_instance_key.serialize()
            },
            "sub": entity_id
        }

        return _signer.pack(payload, kid=signing_key.kid)

    def construct_client_attestation_pop_jwt(self,
                                             entity_id: str,
                                             signing_key: AsymmetricKey,
                                             audience: str,
                                             lifetime: Optional[int] = 300,
                                             nonce: Optional[str] = ""):

        keyjar = KeyJar()
        keyjar.add_keys(entity_id, keys=[signing_key])

        if lifetime:
            _signer = JWT(key_jar=keyjar, sign_alg='ES256', iss=entity_id, lifetime=lifetime)
        else:
            _signer = JWT(key_jar=keyjar, sign_alg='ES256', iss=entity_id)
        _signer.with_jti = True

        payload = {"aud": audience}
        if nonce:
            payload["nonce"] = nonce

        return _signer.pack(payload, kid=signing_key.kid)
