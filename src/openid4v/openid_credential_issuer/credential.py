import json
import logging

from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from fedservice.entity.utils import get_federation_entity
from idpyoidc.key_import import import_jwks_as_json
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.node import topmost_unit
from idpyoidc.server import Endpoint
from idpyoidc.server.util import execute
from idpyoidc.util import rndstr

from openid4v.message import CredentialRequest
from openid4v.message import CredentialResponse
from openid4v.openid_credential_issuer.credential_constructor import CredentialConstructor

logger = logging.getLogger(__name__)


def get_keyjar(unit):
    _fed = get_federation_entity(unit)
    if _fed:
        return _fed.keyjar
    else:
        return unit.upstream_get("attribute", "keyjar")


class Credential(Endpoint):
    response_cls = CredentialResponse
    request_cls = CredentialRequest
    error_msg = oidc.ResponseMessage
    request_format = "json"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "credential_endpoint"
    name = "credential"
    endpoint_type = "oauth2"
    automatic_registration = True

    _supports = {
        "credential_configurations_supported": None,
        "attribute_disclosure": None,
        "array_disclosure": None
    }

    def __init__(self, upstream_get, conf=None, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)
        # dpop support
        self.post_parse_request.append(self.add_access_token_to_request)

        self.credential_constructor = {}
        logger.debug(f"Credential endpoint kwargs: {kwargs}")
        logger.debug(f"Credential endpoint config: {conf}")
        if "credential_constructor" in kwargs:
            for typ, spec in kwargs["credential_constructor"].items():
                self.credential_constructor[typ] = execute(spec, upstream_get=upstream_get)
        else:
            self.credential_constructor["PersonIdentificationData"] = CredentialConstructor(
                upstream_get=upstream_get)

    def _get_session_info(self, endpoint_context, token):
        _jws = factory(token)
        if _jws:
            _sid = _jws.jwt.payload().get("sid")
            _info = endpoint_context.session_manager.get_session_info(session_id=_sid)
        else:
            _info = endpoint_context.session_manager.get_session_info_by_token(
                token, handler_key="access_token"
            )

        return _info

    def part_of_combo(self):
        # The credential issuer may be part of a Combo which also includes the OAuth
        # authorization server
        return topmost_unit(self).get("oauth_authorization_server", None)

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        _jws = factory(token)
        if _jws:
            _payload = _jws.jwt.payload()

            if endpoint_context.entity_id == _payload["iss"]:
                oas = self.part_of_combo()
                if oas:
                    # Try to verify the signature of token
                    _jwt = JWT(oas.context.keyjar)
                    _info = _jwt.unpack(token)
                    return _info["client_id"]

            fed_entity = topmost_unit(self).get("federation_entity", None)
            _metadata = fed_entity.get_verified_metadata(_payload["iss"])
            # get keys
            if 'jwks_uri' in _metadata["oauth_authorization_server"]:
                endpoint_context.keyjar.add_url(_metadata["oauth_authorization_server"]["jwks_uri"])
            elif 'jwks' in _metadata["oauth_authorization_server"]:
                endpoint_context.keyjar = import_jwks_as_json(endpoint_context.keyjar,
                                                              _metadata[
                                                                  "oauth_authorization_server"][
                                                                  "jwks"])
            elif 'signed_jwks_uri' in _metadata["oauth_authorization_server"]:
                pass

            _jwt = JWT(endpoint_context.keyjar)
            _info = _jwt.unpack(token)
            return _info["client_id"]
        else:
            _info = endpoint_context.session_manager.get_session_info_by_token(
                token, handler_key="access_token"
            )

        return _info["client_id"]

    def add_access_token_to_request(self, request, client_id, context, **kwargs):
        request["access_token"] = kwargs["auth_info"]["token"]
        return request

    def _pick_constructor(self, authz_detail):
        logger.debug(f"Available Constructors: {self.credential_constructor.keys()}")
        cd = authz_detail.get("credential_definition", "")
        choice = None
        if cd:
            cd_type = cd.get("type", [])
            for typ in cd_type:
                if typ in self.credential_constructor:
                    logger.debug(
                        f"Picked Credential Constructor based on credential_constructor = {typ}")
                    choice = self.credential_constructor[typ]
        elif "vct" in authz_detail:
            vct = authz_detail.get("vct", "")
            if vct in self.credential_constructor:
                logger.debug(
                    f"Picked Credential Constructor based on vct = {vct}")
                choice = self.credential_constructor[vct]
        elif "credential_configuration_id" in authz_detail:
            cc_id = authz_detail.get('credential_configuration_id')
            if cc_id in self.credential_constructor:
                logger.debug(
                    f"Picked Credential Constructor based on credential_configuration_id = {cc_id}")
                choice = self.credential_constructor[cc_id]

        if choice:
            logger.debug(f"Choose {choice}")
            return choice
        else:
            return None

    def process_request(self, request=None, **kwargs):
        logger.debug(f"Credential.process_request: {request}")
        _msg = {}
        client_id = ""

        _context = self.upstream_get("context")
        _persistence = None
        if _context.session_manager is None:
            # session information at oauth_server
            logger.debug("--- Using AS context ---")
            oas = self.part_of_combo()
            if oas:
                _context = oas.context
                _persistence = getattr(oas, "persistence", None)
        else:
            _persistence = self.upstream_get("attribute", "persistence")

        try:
            # logger.debug(f"Session manager keys: {list(_context.session_manager.db.keys())}")
            _session_info = self._get_session_info(_context, request["access_token"])
        except (KeyError, ValueError):
            logger.exception("Invalid request access_token")
            return self.error_cls(error="invalid_token", error_description="Invalid Token")

        if _session_info:
            client_id = _session_info["client_id"]
            authz_details = _session_info["grant"].authorization_request.get(
                "authorization_details", [])
            # Does only one
            authz_detail = authz_details[0]

            if isinstance(authz_detail, Message):
                logger.debug(f"pick_constructor: authz_details={authz_detail.to_dict()}")
            else:
                logger.debug(f"pick_constructor: authz_details={authz_detail}")

            _credential_constructor = self._pick_constructor(authz_detail)
            if _credential_constructor is None:
                raise AttributeError("Asked for credential type I can't produce")

            try:
                _msg = _credential_constructor(user_id=_session_info["user_id"],
                                               request=request,
                                               authz_detail=authz_detail,
                                               grant=_session_info["grant"],
                                               client_id=client_id,
                                               persistence=_persistence)
            except Exception as err:
                logger.exception("Credential constructor")
                return self.error_cls(error="invalid_token", error_description=f"{err}")

        _resp = json.loads(_msg)
        _resp.update({
            "format": "vc+sd-jwt",
            "c_nonce": rndstr(),
            "c_nonce_expires_in": 86400
        })
        return {"response_args": _resp, "client_id": client_id}
