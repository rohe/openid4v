"""Implements the service that talks to the Access Token endpoint."""
import logging
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory
from idpyoidc import verified_claim_name
from idpyoidc.client.client_auth import get_client_authn_methods
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.metadata import get_signing_algs
from idpyoidc.server import Endpoint

from oidc4vci.message import WalletInstanceAttestationResponse
from oidc4vci.message import WalletInstanceRequest
from oidc4vci.message import WalletInstanceRequestJWT

LOGGER = logging.getLogger(__name__)


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
    name = "token"  # The name of this endpoint in the server context

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
            "var+jwt": WalletInstanceRequestJWT
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
        request[verified_claim_name("assertion")] = self.verify_self_signed_signature(
            request["assertion"])

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
        keyjar = self.upstream_get("attribute", "keyjar")
        entity_id = self.upstream_get("attribute", "entity_id")
        _signer = JWT(key_jar=keyjar, sign_alg='ES256', iss=entity_id, lifetime=300)
        _signer.with_jti = True

        _jws_header = {"typ": "wallet-attestation+jwt"}
        _trust_chain = kwargs.get("trust_chain")
        if _trust_chain:
            _jws_header["trust_chain"] = _trust_chain

        _wallet_instance_attestation = _signer.pack(payload,
                                                    aud=req_args['iss'],
                                                    issuer_id=entity_id,
                                                    jws_headers=_jws_header)

        response_args = {
            "attestation": _wallet_instance_attestation
        }

        if isinstance(response_args, ResponseMessage):
            return response_args

        _headers = [("Content-type", "application/json")]
        resp = {"response_args": response_args, "http_headers": _headers}
        return resp

    def supports(self):
        return {"grant_types_supported": self._include["grant_types_supported"]}
