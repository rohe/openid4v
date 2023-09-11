from typing import Callable
from typing import Optional
from typing import Union

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from idpyoidc import verified_claim_name
from idpyoidc.client.client_auth import get_client_authn_methods
from idpyoidc.client.configure import Configuration
from idpyoidc.client.exception import ParameterError
from idpyoidc.client.oauth2 import access_token
from idpyoidc.client.oidc import IDT2REG
from idpyoidc.client.service import Service
from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import AuthorizationResponse
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.metadata import get_signing_algs
from idpyoidc.server.oauth2 import pushed_authorization
from idpyoidc.time_util import time_sans_frac

from oidc4vci.message import AuthorizationRequest


class Authorization(Service):
    """The service that talks to the Certificate issuer."""

    msg_type = AuthorizationRequest
    response_cls = AuthorizationResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = "authorization"
    http_method = "POST"
    default_authn_method = "client_assertion"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        Service.__init__(self, upstream_get, conf=conf)
        self.certificate_issuer_id = conf.get("certificate_issuer_id")
        self.pre_construct = [self.set_state]

    def set_state(self, request_args, **kwargs):
        _context = self.upstream_get("context")
        try:
            _state = kwargs["state"]
        except KeyError:
            try:
                _state = request_args["state"]
            except KeyError:
                _state = _context.cstate.create_key()

        request_args["state"] = _state
        _context.cstate.set(_state, {"iss": _context.issuer})
        return request_args, {}

    def get_endpoint(self):
        # get endpoint from the Entity Configuration
        chains, leaf_ec = collect_trust_chains(self, self.certificate_issuer_id)
        if len(chains) == 0:
            return None

        trust_chains = verify_trust_chains(self, chains, leaf_ec)
        trust_chains = apply_policies(self, trust_chains)
        if len(chains) == 0:
            return None

        # pick one
        return trust_chains[0].metadata['wallet_provider']["token_endpoint"]


class AccessToken(access_token.AccessToken):
    msg_type = oauth2.AccessTokenRequest
    response_cls = oauth2.AccessTokenResponse
    error_msg = oauth2.ResponseMessage
    default_authn_method = "private_key_jwt"
    service_name = "accesstoken"

    _include = {"grant_types_supported": ["authorization_code"]}

    _supports = {
        "token_endpoint_auth_methods_supported": get_client_authn_methods,
        "token_endpoint_auth_signing_alg_values_supported": get_signing_algs,
    }

    def __init__(self, upstream_get, conf: Optional[dict] = None, **kwargs):
        access_token.AccessToken.__init__(self, upstream_get, conf=conf, **kwargs)

    def gather_verify_arguments(
            self, response: Optional[Union[dict, Message]] = None,
            behaviour_args: Optional[dict] = None
    ):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """
        _context = self.upstream_get("context")
        _entity = self.upstream_get("entity")

        kwargs = {
            "client_id": _entity.get_client_id(),
            "iss": _context.issuer,
            "keyjar": self.upstream_get("attribute", "keyjar"),
            "verify": True,
            "skew": _context.clock_skew,
        }

        _reg_resp = _context.registration_response
        if _reg_resp:
            for attr, param in IDT2REG.items():
                try:
                    kwargs[attr] = _reg_resp[param]
                except KeyError:
                    pass

        try:
            kwargs["allow_missing_kid"] = _context.allow["missing_kid"]
        except KeyError:
            pass

        _verify_args = _context.claims.get_usage("verify_args")
        if _verify_args:
            if _verify_args:
                kwargs.update(_verify_args)

        return kwargs

    def update_service_context(self, resp, key: Optional[str] = "", **kwargs):
        _cstate = self.upstream_get("context").cstate
        try:
            _idt = resp[verified_claim_name("id_token")]
        except KeyError:
            pass
        else:
            try:
                if _cstate.get_base_key(_idt["nonce"]) != key:
                    raise ParameterError('Someone has messed with "nonce"')
            except KeyError:
                raise ValueError("Invalid nonce value")

            _cstate.bind_key(_idt["sub"], key)

        if "expires_in" in resp:
            resp["__expires_at"] = time_sans_frac() + int(resp["expires_in"])

        _cstate.update(key, resp)

class PushedAuthorization(pushed_authorization.PushedAuthorization):
    def __init__(self, upstream_get, **kwargs):
        pushed_authorization.PushedAuthorization.__init__(self, upstream_get, **kwargs)
