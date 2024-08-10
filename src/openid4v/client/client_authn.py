import logging
from typing import Optional
from typing import Union

from cryptojwt import JWK
from cryptojwt import JWT
from cryptojwt import KeyJar
from idpyoidc.client.client_auth import ClientAuthnMethod
from idpyoidc.client.client_auth import find_token_info
from idpyoidc.message import Message
from idpyoidc.node import topmost_unit

from openid4v import ASSERTION_TYPE

logger = logging.getLogger(__name__)

class ClientAssertion(ClientAuthnMethod):

    def construct(self, request, service=None, http_args=None, **kwargs) -> dict:
        if "client_assertion" not in request:
            request["client_assertion"] = kwargs["client_assertion"]

        request["client_assertion_type"] = ASSERTION_TYPE
        return {}


class ClientAuthenticationAttestation(ClientAuthnMethod):

    def construct(self,
                  request: Union[dict, Message],
                  service=None,
                  http_args: Optional[dict] = None,
                  **kwargs) -> dict:
        logging.debug(f"kwargs: {kwargs}")
        entity_id = request.get("client_id", kwargs.get("thumbprint"))

        if kwargs.get("audience", None) is None:
            _aud = getattr(service, "certificate_issuer_id", None)
            if not _aud:
                _aud = service.upstream_get("context").issuer
            if _aud:
                kwargs["audience"] = _aud

        if kwargs.get("signing_key"):
            pass
        else:
            _combo = topmost_unit(service)
            _wallet = _combo["wallet"]
            signing_keys = _wallet.keyjar.get_signing_key(kid=entity_id)
            if signing_keys:
                kwargs["signing_key"] = signing_keys[0]
            else:
                kwargs["signing_key"] = _wallet.context.ephemeral_key[kwargs["ephemeral_key_tag"]]

        part2 = self.construct_client_attestation_pop_jwt(entity_id=entity_id, **kwargs)
        _att = kwargs.get("attestation", kwargs.get("wallet_instance_attestation"))
        request["client_assertion"] = f"{_att}~{part2}"
        request["client_assertion_type"] = ASSERTION_TYPE
        return {}

    def construct_client_attestation_pop_jwt(self,
                                             audience: str,
                                             signing_key: JWK,
                                             entity_id: Optional[str] = "",
                                             lifetime: Optional[int] = 300,
                                             nonce: Optional[str] = "",
                                             **kwargs):

        keyjar = KeyJar()
        # if entity_id:
        #     keyjar.add_keys(entity_id, keys=[signing_key])
        # else:
        #     entity_id = signing_key.kid

        keyjar.add_keys(signing_key.kid, [signing_key])

        if lifetime:
            _signer = JWT(key_jar=keyjar, sign_alg='ES256', iss=signing_key.kid, lifetime=lifetime)
        else:
            _signer = JWT(key_jar=keyjar, sign_alg='ES256', iss=signing_key.kid)
        _signer.with_jti = True

        payload = {"aud": audience}
        if nonce:
            payload["nonce"] = nonce

        return _signer.pack(payload, kid=signing_key.kid)


class DPoPHeader(ClientAuthnMethod):
    """The bearer header authentication method."""

    def construct(self, request=None, service=None, http_args=None, **kwargs):
        """
        Constructing the Authorization header. The value of
        the Authorization header is "DPoP <access_token>".

        :param request: Request class instance
        :param service: The service this authentication method applies to.
        :param http_args: HTTP header arguments
        :param kwargs: extra keyword arguments
        :return:
        """

        _token_type = "access_token"

        _token_info = find_token_info(request, _token_type, service, **kwargs)

        if not _token_info:
            raise KeyError("No bearer token available")
        if _token_info["token_type"] not in ["Bearer", "DPoP"]:
            raise ValueError("Wrong token type")

        # The authorization value starts with DPoP
        _bearer = f"DPoP {_token_info[_token_type]}"

        # Add 'Authorization' to the headers
        if http_args is None:
            http_args = {"headers": {}}
            http_args["headers"]["Authorization"] = _bearer
        else:
            try:
                http_args["headers"]["Authorization"] = _bearer
            except KeyError:
                http_args["headers"] = {"Authorization": _bearer}

        return http_args
