"""Implements the service that talks to the Access Token endpoint."""
import logging
from typing import Optional
from typing import Union
from urllib.parse import parse_qs

from cryptojwt import JWT
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory
from fedservice.entity import get_verified_trust_chains
from idpyoidc import verified_claim_name
from idpyoidc.client.client_auth import get_client_authn_methods
from idpyoidc.defaults import JWT_BEARER
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.metadata import get_signing_algs
from idpyoidc.server import Endpoint

from openid4v.message import WalletInstanceAttestationResponse
from openid4v.message import WalletInstanceRequest
from openid4v.message import WalletInstanceRequestJWT

LOGGER = logging.getLogger(__name__)


class InvalidNonce(ValueError):
    pass


class Token(Endpoint):
    """The token endpoint."""

    request_cls = WalletInstanceRequest
    response_cls = WalletInstanceAttestationResponse
    error_msg = ResponseMessage
    endpoint_name = "token_endpoint"  # Used when handling metadata
    synchronous = True
    service_name = "wallet_provider_token"
    default_authn_method = "client_secret_basic"
    http_method = "POST"
    request_format = "urlencoded"
    request_placement = "body"
    response_body_type = "jose"
    name = "wallet_provider_token"  # The name of this endpoint in the server context

    _include = {
        "grant_types_supported": [
            "urn:ietf:params:oauth:client-assertion-type:jwt-key-attestation"]}

    _supports = {
        "token_endpoint_auth_methods_supported": get_client_authn_methods,
        "token_endpoint_auth_signing_alg": get_signing_algs,
    }

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)

    def verify_self_signed_signature(self, self_signed_jwt):
        _jws = factory(self_signed_jwt)
        _payload = _jws.jwt.payload()
        self.upstream_get("attribute", "keyjar")
        keyjar = self.upstream_get('unit').context.keyjar
        _key = key_from_jwk_dict(_payload['cnf']['jwk'])
        keyjar.add_keys(_payload['iss'], [_key])

        # basically verifies that the sender has control of the key included in the message.
        _verifier = JWT(key_jar=keyjar)
        _verifier.typ2msg_cls = {
            "wiar+jwt": WalletInstanceRequestJWT
        }
        _val = _verifier.unpack(self_signed_jwt)
        return _val

    def parse_request(
            self,
            request: Union[Message, dict, str],
            http_info: Optional[dict] = None,
            verify_args: Optional[dict] = None,
            **kwargs
    ):
        if isinstance(request, str):  # json
            request = {k: v[0] for k, v in parse_qs(request).items()}

        _ver_request = self.verify_self_signed_signature(request["assertion"])
        request[verified_claim_name("assertion")] = _ver_request

        if 'nonce' in _ver_request:
            # Find the AppAttestation endpoint in the same server
            app_attestation = self.upstream_get("unit").get_endpoint("app_attestation")
            if app_attestation:
                _nonce = _ver_request.get("nonce", None)
                if _nonce:
                    iccid = app_attestation.attestation_service.verify_nonce(_ver_request["nonce"])

                    if not iccid:
                        raise InvalidNonce("Nonce invalid")
                    request["__iccid"] = iccid
                else:
                    raise ValueError("Missing 'nonce'")
        return request

    def process_request(self, request: Optional[Union[Message, dict]] = None, **kwargs):
        """

        :param request:
        :param kwargs:
        :return: Dictionary with response information
        """
        if isinstance(request, self.error_cls):
            return request
        elif request is None:
            return self.error_cls(error="invalid_request")

        req_args = request[verified_claim_name("assertion")]
        # carry over
        payload = {
            "sub": req_args['iss'],
            "cnf": req_args["cnf"],
            "attested_security_context": "https://wallet-provider.example.org/LoA/basic",
            "type": "WalletInstanceAttestation",
        }
        payload.update(self.upstream_get("unit").wallet_instance_discovery(req_args['iss']))

        keyjar = self.upstream_get("attribute", "keyjar")
        entity_id = self.upstream_get("attribute", "entity_id")
        sign_alg = kwargs.get("sign_alg", "ES256")
        lifetime = kwargs.get("lifetime", 86400)
        _signer = JWT(key_jar=keyjar, sign_alg=sign_alg, iss=entity_id, lifetime=lifetime)
        _signer.with_jti = True

        _jws_header = {"typ": "wallet-attestation+jwt"}
        _trust_chain = kwargs.get("trust_chain")
        if _trust_chain:
            _jws_header["trust_chain"] = _trust_chain
        else: # Collect Trust Chain
            _trust_chains = get_verified_trust_chains(self, entity_id=entity_id)
            if len(_trust_chains) >= 1:
                _jws_header["trust_chain"] = _trust_chains[0].chain

        _wallet_instance_attestation = _signer.pack(payload,
                                                    aud=req_args['iss'],
                                                    issuer_id=entity_id,
                                                    jws_headers=_jws_header)

        response_args = {
            "assertion": _wallet_instance_attestation,
            "grant_type": JWT_BEARER
        }

        if isinstance(response_args, ResponseMessage):
            return response_args

        _headers = [("Content-type", "application/json")]
        # resp = {"response": json.dumps(response_args), "http_headers": _headers}
        LOGGER.debug(f"Process request returned: {response_args}")
        return {"response_args": response_args}

    def supports(self):
        return {"grant_types_supported": self._include["grant_types_supported"]}
