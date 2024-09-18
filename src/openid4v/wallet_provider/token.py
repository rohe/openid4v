"""Implements the service that talks to the Access Token endpoint."""
import base64
import hashlib
import json
import logging
from typing import Optional
from typing import Union
from urllib.parse import parse_qs

from cryptojwt import JWT
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.dsa import ECDSASigner
from cryptojwt.jws.jws import factory
from cryptojwt.utils import as_bytes
from fedservice.entity import get_verified_trust_chains
from idpyoidc import verified_claim_name
from idpyoidc.client.client_auth import get_client_authn_methods
from idpyoidc.defaults import JWT_BEARER
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.alg_info import get_signing_algs
from idpyoidc.server import Endpoint
from idpyoidc.server.util import execute

from openid4v.message import WalletAttestationRequestJWT
from openid4v.message import WalletInstanceAttestationResponse
from openid4v.message import WalletInstanceRequest

logger = logging.getLogger(__name__)


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

    def __init__(self, upstream_get, config: Optional[dict] = None, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)
        self.add_trust_chain = kwargs.get("add_trust_chain", False)
        if config:
            for val in ["challenge", "integrity_assertion", "hardware_signature"]:
                _validator = config.get(f"{val}_validator", None)
                if _validator:
                    setattr(self, f"{val}_validator", execute(_validator))
                else:
                    setattr(self, f"{val}_validator", getattr(self, f"validate_{val}"))
        else:
            for val in ["challenge", "integrity_assertion", "hardware_signature"]:
                setattr(self, f"{val}_validator", getattr(self, f"validate_{val}"))

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
            "wiar+jwt": WalletAttestationRequestJWT
        }
        _val = _verifier.unpack(self_signed_jwt)
        return _val

    def validate_challenge(self, **kwargs):
        challenge = kwargs["challenge"]
        # Find the nonce endpoint in the same server
        nonce_endpoint = self.upstream_get("unit").get_endpoint("challenge")
        if nonce_endpoint:
            if not nonce_endpoint.challenge_service.verify_nonce(challenge):
                return False
        return True

    def validate_integrity_assertion(self, **kwargs):
        # value is a base64 encoded
        _val = base64.b64decode(kwargs["integrity_assertion"])
        return True

    def validate_hardware_signature(self, **kwargs):
        key = ECKey(**kwargs["cnf"]["jwk"])
        key.deserialize()
        client_data = {
            "challenge": kwargs["challenge"],
            "jwk_thumbprint": key.kid
        }

        client_data_hash = hashlib.sha256(as_bytes(json.dumps(client_data))).digest()

        # value is a base64 encoded
        _sig = base64.b64decode(kwargs["hardware_signature"])
        _signer = ECDSASigner()
        # _wallet_provider.context.crypto_hardware_key = {hardware_key_tag: _wallet.context.crypto_hardware_key}
        _context = self.upstream_get("context")
        _sign_key = _context.crypto_hardware_key[kwargs["hardware_key_tag"]]
        return _signer.verify(client_data_hash, _sig, _sign_key.public_key())

    def parse_request(
            self,
            request: Union[Message, dict, str],
            http_info: Optional[dict] = None,
            verify_args: Optional[dict] = None,
            **kwargs
    ):
        if isinstance(request, str):  # json
            request = {k: v[0] for k, v in parse_qs(request).items()}

        # This is the validation of the JWK PoP
        _ver_request = self.verify_self_signed_signature(request["assertion"])
        request[verified_claim_name("assertion")] = _ver_request

        for item in ["challenge", "integrity_assertion", "hardware_signature"]:
            _val = _ver_request.get(item, None)
            if _val != '__not__applicable__':
                _app = getattr(self, f"{item}_validator", None)
                if not _app(**_ver_request):
                    logger.error(f"Validation of {item} failed")

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
            "vp_formats_supported": req_args["vp_formats_supported"],
            # "aal": "https://wallet-provider.example.org/LoA/basic",
            # "type": "WalletInstanceAttestation",
            "authorization_endpoint": "eudiw:",
            "response_types_supported": ["vp_token"],
            "response_modes_supported": ["form_post.jwt"],
            "request_object_signing_alg_values_supported": ["ES256"],
            "presentation_definition_uri_supported": False
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
        elif self.add_trust_chain:  # Collect Trust Chain
            _trust_chains = get_verified_trust_chains(self, entity_id=entity_id)
            if len(_trust_chains) >= 1:
                _jws_header["trust_chain"] = _trust_chains[0].chain

        _wallet_instance_attestation = _signer.pack(payload,
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
        logger.debug(f"Process request returned: {response_args}")
        return {"http_headers": _headers, "response_args": response_args}

    def supports(self):
        return {"grant_types_supported": self._include["grant_types_supported"]}
