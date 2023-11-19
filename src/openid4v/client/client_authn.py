from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwk.asym import AsymmetricKey
from idpyoidc.client.client_auth import ClientAuthnMethod
from idpyoidc.message import Message

from openid4v import ASSERTION_TYPE


class ClientAssertion(ClientAuthnMethod):

    def construct(self, request, service=None, http_args=None, **kwargs) -> dict:
        if "client_assertion" not in request:
            request["client_assertion"] = kwargs["client_attestation"]

        request["client_assertion_type"] = ASSERTION_TYPE
        return {}


class ClientAuthenticationAttestation(ClientAuthnMethod):

    def construct(self,
                  request: Union[dict, Message],
                  service=None,
                  http_args: Optional[dict] = None,
                  **kwargs) -> dict:
        entity_id = kwargs.get("thumbprint")
        wia = kwargs["wallet_instance_attestation"]
        part2 = self.construct_client_attestation_pop_jwt(entity_id, **kwargs)
        request["client_assertion"] = f"{wia}~{part2}"
        request["client_assertion_type"] = ASSERTION_TYPE
        return {}

    def construct_client_attestation_pop_jwt(self,
                                             entity_id: str,
                                             signing_key: AsymmetricKey,
                                             audience: str,
                                             lifetime: Optional[int] = 300,
                                             nonce: Optional[str] = "",
                                             **kwargs):

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
