from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.jwk import key_from_jwk_dict
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.service import FederationService
from fedservice.entity.utils import get_federation_entity
from idpyoidc import verified_claim_name
from idpyoidc.client.configure import Configuration
from idpyoidc.defaults import JWT_BEARER
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.node import topmost_unit

from openid4v.message import WalletInstanceAttestationResponse
from openid4v.message import WalletInstanceRequest

WalletInstanceAttestationLifetime = 2592000  # 30 days


class WalletInstanceAttestation(FederationService):
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
        if conf is None:
            conf = {}
        FederationService.__init__(self, upstream_get, conf=conf)
        self.wallet_provider_id = conf.get("wallet_provider_id", "")
        self.wallet_instance_attestation = {}
        _lifetime = conf.get('lifetime', 0)
        self.lifetime = _lifetime or WalletInstanceAttestationLifetime

    def get_trust_chains(self):
        chains, leaf_ec = collect_trust_chains(self, self.wallet_provider_id)
        if len(chains) == 0:
            return None

        trust_chains = verify_trust_chains(self, chains, leaf_ec)
        trust_chains = apply_policies(self, trust_chains)
        if len(trust_chains) == 0:
            return None

        _fe = get_federation_entity(self)
        _fe.trust_chain[self.wallet_provider_id] = trust_chains
        _wallet_unit = _fe.upstream_get("unit")["wallet"]
        _wallet_unit.context.keyjar.import_jwks(
            trust_chains[0]["metadata"]["wallet_provider"]["jwks"], self.wallet_provider_id)
        return trust_chains

    def get_endpoint(self):
        trust_chains = self.get_trust_chains()
        # get endpoint from the Entity Configuration
        # pick one
        if trust_chains:
            return trust_chains[0].metadata['wallet_provider']["token_endpoint"]
        else:
            return ""

    def construct(self, request_args=None, **kwargs) -> Message:
        """
        Instantiate the request as a message class instance with
        attribute values gathered in a pre_construct method or in the
        gather_request_args method.

        :param request_args:
        :param kwargs: extra keyword arguments
        :return: message class instance
        """
        wallet_unit = self.upstream_get("unit")
        keyjar = wallet_unit.context.keyjar

        ec_key = kwargs.get("ephemeral_key")
        keyjar.add_keys(issuer_id=ec_key.kid, keys=[ec_key])
        # keyjar.add_keys(issuer_id="", keys=[ec_key])

        _jwt = JWT(key_jar=keyjar, sign_alg='ES256', iss=ec_key.kid)
        _jwt.with_jti = True
        _jwt.lifetime = kwargs.get("lifetime", self.lifetime)

        if request_args:
            payload = request_args.copy()
        else:
            payload = {}

        # Should have gotten nonce out-of-bounds
        # if "nonce" not in payload:
        #     payload["nonce"] = rndstr()

        payload["cnf"] = {"jwk": ec_key.serialize()}

        _jws = _jwt.pack(payload,
                         aud=self.wallet_provider_id,
                         kid=ec_key.kid,
                         issuer_id=ec_key.kid,
                         jws_headers={"typ": "wiar+jwt"}
                         )

        _data = WalletInstanceRequest(assertion=_jws, grant_type=JWT_BEARER)

        return _data

    def gather_verify_arguments(
            self, response: Optional[Union[dict, Message]] = None,
            behaviour_args: Optional[dict] = None
    ):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """

        issuer = self.wallet_provider_id

        _fe = get_federation_entity(self)
        if issuer not in _fe.trust_chain:  # have to fetch trust chain
            self.get_trust_chains()

        wallet_unit = topmost_unit(self)["wallet"]
        _keyjar = wallet_unit.context.keyjar
        if issuer not in _keyjar:
            for _chain in _fe.trust_chain[issuer]:
                _keyjar.import_jwks(_chain.metadata["wallet_provider"]["jwks"], issuer)

        kwargs = {
            "iss": issuer,
            "keyjar": _keyjar,
            "verify": True,
            "client_id": _fe.entity_id,
        }

        return kwargs

    def post_parse_response(self, response, **kwargs):
        _client = self.upstream_get("unit")
        kid = response[verified_claim_name("assertion")]['cnf']['jwk']["kid"]
        _wia = getattr(_client.context, "wallet_instance_attestation", None)
        if not _wia:
            _client.context.wallet_instance_attestation = {}

        _client.context.wallet_instance_attestation[kid] = {
            "attestation": response["assertion"],
            "expires": response[verified_claim_name("assertion")]["exp"]
        }
        return response
