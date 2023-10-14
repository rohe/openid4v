from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urlencode

from cryptojwt import JWT
from cryptojwt.jwk.ec import new_ec_key
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from idpyoidc import verified_claim_name
from idpyoidc.client.configure import Configuration
from idpyoidc.client.service import Service
from idpyoidc.defaults import JWT_BEARER
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.util import rndstr

from openid4v.message import WalletInstanceAttestationResponse
from openid4v.message import WalletInstanceRequest


class WalletInstanceAttestation(Service):
    """The service that talks to the Wallet provider."""

    msg_type = WalletInstanceRequest
    response_cls = WalletInstanceAttestationResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = "wallet_instance_attestation"
    http_method = "POST"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        Service.__init__(self, upstream_get, conf=conf)
        self.wallet_provider_id = conf.get("wallet_provider_id", "")
        self.wallet_instance_attestations = {}

    def get_endpoint(self):
        # get endpoint from the Entity Configuration
        chains, leaf_ec = collect_trust_chains(self, self.wallet_provider_id)
        if len(chains) == 0:
            return None

        trust_chains = verify_trust_chains(self, chains, leaf_ec)
        trust_chains = apply_policies(self, trust_chains)
        if len(chains) == 0:
            return None

        # pick one
        return trust_chains[0].metadata['wallet_provider']["token_endpoint"]

    def get_request_parameters(
            self,
            request_args: Optional[dict] = None,
            authn_method: Optional[str] = "",
            endpoint: Optional[str] = "",
            **kwargs
    ) -> dict:
        """
        Builds the request message and constructs the HTTP headers.

        :param request_args: Message arguments
        :param authn_method: Client authentication method
        :param endpoint:
        :param kwargs: extra keyword arguments
        :return: List of entity IDs
        """
        keyjar = self.upstream_get("attribute", "keyjar")
        ec_key = new_ec_key(crv="P-256", use="sig")

        entity_id = self.upstream_get("attribute", "entity_id")

        keyjar.add_keys(issuer_id=entity_id, keys=[ec_key])
        keyjar.add_keys(issuer_id="", keys=[ec_key])

        _jwt = JWT(key_jar=keyjar, sign_alg='ES256', iss=entity_id)
        _jwt.with_jti = True

        if not endpoint:
            endpoint = self.get_endpoint()

        payload = request_args.copy()
        # Should have gotten nonce out-of-bounds
        if "nonce" not in payload:
            payload["nonce"] = rndstr()

        payload.update(
            {
                # "type": "WalletInstanceAttestationRequest",
                "cnf": {
                    "jwk": ec_key.serialize()
                }
            }
        )
        _jws = _jwt.pack(payload,
                         aud=self.wallet_provider_id,
                         kid=ec_key.kid,
                         issuer_id=entity_id,
                         jws_headers={"typ": "wiar+jwt"}
                         )

        _data = urlencode({
            "assertion": _jws,
            "grant_type": JWT_BEARER})

        return {"url": endpoint, 'method': self.http_method, "data": _data}

    def post_parse_response(self, response, **kwargs):
        kid = response[verified_claim_name("assertion")]['cnf']['jwk']["kid"]
        self.wallet_instance_attestations[kid] = response
        return response
