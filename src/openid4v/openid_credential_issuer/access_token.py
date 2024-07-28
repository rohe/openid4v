"""Implements the service that talks to the Access Token endpoint."""
import logging
from typing import Optional
from typing import Union

from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc import metadata
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oauth2 import TokenErrorResponse
from idpyoidc.server import Endpoint
from idpyoidc.server.oauth2.token_helper import validate_resource_indicators_policy
from idpyoidc.server.session.grant import Grant
from idpyoidc.server.session.token import MintingNotAllowed
from idpyoidc.server.session.token import SessionToken
from idpyoidc.util import rndstr

from openid4v import message

LOGGER = logging.getLogger(__name__)


class Token(Endpoint):
    """The access token service."""

    request_cls = message.AccessTokenRequest
    response_cls = message.AccessTokenResponse
    error_msg = ResponseMessage
    error_cls = TokenErrorResponse
    request_format = "urlencoded"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "token_endpoint"
    name = "token"
    default_capabilities = {"token_endpoint_auth_signing_alg_values_supported": None}
    endpoint_type = "oauth2"
    default_authn_method = "private_key_jwt"

    _supports = {
        "token_endpoint_auth_methods_supported": [],
        "token_endpoint_auth_signing_alg_values_supported": metadata.get_signing_algs()
    }

    def __init__(self, upstream_get, conf=None, **kwargs):
        Endpoint.__init__(self, upstream_get, conf=conf, **kwargs)

    def _process_request(self, request: Optional[Union[Message, dict]] = None, **kwargs):
        """

        :param request:
        :param kwargs:
        :return: Dictionary with response information
        """
        _context = self.upstream_get("context")
        _mngr = _context.session_manager
        LOGGER.debug(20 * "=" + "Access Token" + 20 * "=")

        if request["grant_type"] != "authorization_code":
            return self.error_cls(error="invalid_request", error_description="Unknown grant_type")

        try:
            _access_code = request["code"].replace(" ", "+")
        except KeyError:  # Missing code parameter - absolutely fatal
            return self.error_cls(error="invalid_request", error_description="Missing code")

        _session_info = _mngr.get_session_info_by_token(
            _access_code, grant=True, handler_key="authorization_code"
        )
        client_id = _session_info["client_id"]
        if client_id != request["client_id"]:
            LOGGER.debug("{} owner of token".format(client_id))
            LOGGER.warning("Client using token it was not given")
            return self.error_cls(error="invalid_grant", error_description="Wrong client")

        _cinfo = self.upstream_get("context").cdb.get(client_id)

        if "resource_indicators" in _cinfo and "access_token" in _cinfo["resource_indicators"]:
            resource_indicators_config = _cinfo["resource_indicators"]["access_token"]
        else:
            resource_indicators_config = self.kwargs.get("resource_indicators", None)

        if resource_indicators_config is not None:
            if "policy" not in resource_indicators_config:
                policy = {"policy": {"function": validate_resource_indicators_policy}}
                resource_indicators_config.update(policy)

            # req = self._enforce_resource_indicators_policy(req, resource_indicators_config)

            if isinstance(request, TokenErrorResponse):
                return request

        grant = _session_info["grant"]
        token_type = "Bearer"

        # Is DPOP supported
        try:
            _dpop_enabled = _context.add_on.get("dpop")
        except AttributeError:
            _dpop_enabled = False

        if _dpop_enabled:
            _dpop_jkt = request.get("dpop_jkt")
            if _dpop_jkt:
                grant.extra["dpop_jkt"] = _dpop_jkt
                token_type = "DPoP"

        _based_on = grant.get_token(_access_code)
        _supports_minting = _based_on.usage_rules.get("supports_minting", [])

        _authn_req = grant.authorization_request

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _authn_req:
            if request["redirect_uri"] != _authn_req["redirect_uri"]:
                return self.error_cls(
                    error="invalid_request", error_description="redirect_uri mismatch"
                )

        LOGGER.debug("All checks OK")

        if resource_indicators_config is not None:
            scope = request["scope"]
        else:
            scope = grant.scope

        if "offline_access" in scope and "refresh_token" in _supports_minting:
            issue_refresh = True
        else:
            issue_refresh = kwargs.get("issue_refresh", False)

        _response = {
            "token_type": token_type,
            "scope": scope,
        }

        if "access_token" in _supports_minting:

            resources = request.get("resource", None)
            if resources:
                token_args = {"resources": resources}
            else:
                token_args = None

            try:
                token = self._mint_token(
                    token_class="access_token",
                    grant=grant,
                    session_id=_session_info["branch_id"],
                    client_id=_session_info["client_id"],
                    based_on=_based_on,
                    token_args=token_args,
                )
            except MintingNotAllowed as err:
                LOGGER.warning(err)
            else:
                _response["access_token"] = token.value
                _nonce = rndstr(16)
                _expires_in = _context.conf.get("c_nonce_expires_in", 86400)
                _response["c_nonce"] = _nonce
                _response["c_nonce_expires_in"] = _expires_in
                token.nonce = _nonce
                token.nonce_expires = utc_time_sans_frac() + _expires_in
                if token.expires_at:
                    _response["expires_in"] = token.expires_at - utc_time_sans_frac()

        if issue_refresh and "refresh_token" in _supports_minting:
            try:
                refresh_token = self._mint_token(
                    token_class="refresh_token",
                    grant=grant,
                    session_id=_session_info["branch_id"],
                    client_id=_session_info["client_id"],
                    based_on=_based_on,
                )
            except MintingNotAllowed as err:
                LOGGER.warning(err)
            else:
                _response["refresh_token"] = refresh_token.value

        # since the grant content has changed. Make sure it's stored
        _mngr[_session_info["branch_id"]] = grant

        _based_on.register_usage()

        return _response

    def _mint_token(
            self,
            token_class: str,
            grant: Grant,
            session_id: str,
            client_id: str,
            based_on: Optional[SessionToken] = None,
            scope: Optional[list] = None,
            token_args: Optional[dict] = None,
            token_type: Optional[str] = "",
    ) -> SessionToken:
        _context = self.upstream_get("context")
        _mngr = _context.session_manager
        usage_rules = grant.usage_rules.get(token_class)
        if usage_rules:
            _exp_in = usage_rules.get("expires_in")
        else:
            _token_handler = _mngr.token_handler[token_class]
            _exp_in = _token_handler.lifetime

        token_args = token_args or {}
        for meth in _context.token_args_methods:
            token_args = meth(_context, client_id, token_args)

        if token_args:
            _args = token_args
        else:
            _args = {}

        token = grant.mint_token(
            session_id,
            context=_context,
            token_class=token_class,
            token_handler=_mngr.token_handler[token_class],
            based_on=based_on,
            usage_rules=usage_rules,
            scope=scope,
            token_type=token_type,
            **_args,
        )

        if _exp_in:
            if isinstance(_exp_in, str):
                _exp_in = int(_exp_in)

            if _exp_in:
                token.expires_at = utc_time_sans_frac() + _exp_in

        _context.session_manager.set(_context.session_manager.unpack_session_key(session_id), grant)

        return token

    def process_request(self, request: Optional[Union[Message, dict]] = None, **kwargs):
        if isinstance(request, self.error_cls):
            return request

        if request is None:
            return self.error_cls(error="invalid_request")

        response_args = self._process_request(request, **kwargs)

        if isinstance(response_args, ResponseMessage):
            return response_args

        _access_token = response_args["access_token"]
        _context = self.upstream_get("context")

        _handler_key = "access_token"

        _session_info = _context.session_manager.get_session_info_by_token(
            _access_token, grant=True, handler_key=_handler_key
        )

        _cookie = _context.new_cookie(
            name=_context.cookie_handler.name["session"],
            sub=_session_info["grant"].sub,
            sid=_context.session_manager.session_key(
                _session_info["user_id"],
                _session_info["client_id"],
                _session_info["grant"].id,
            ),
        )

        _headers = [("Content-type", "application/json")]
        resp = {"response_args": response_args, "http_headers": _headers}
        if _cookie:
            resp["cookie"] = [_cookie]
        return resp
