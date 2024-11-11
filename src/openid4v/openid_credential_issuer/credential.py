import json
import logging
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from fedservice.entity.utils import get_federation_entity
from idpyoidc.exception import RequestError
from idpyoidc.key_import import import_jwks_as_json
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.node import topmost_unit
from idpyoidc.server import Endpoint
from idpyoidc.server.util import execute
from idpyoidc.util import rndstr
from idpysdjwt.issuer import Issuer
from satosa_idpyop.persistence import Persistence

from openid4v.message import CredentialDefinition
from openid4v.message import CredentialRequest
from openid4v.message import CredentialResponse

logger = logging.getLogger(__name__)


def get_keyjar(unit):
    _fed = get_federation_entity(unit)
    if _fed:
        return _fed.keyjar
    else:
        return unit.upstream_get("attribute", "keyjar")


def match_vc_sd_jwt_format(request, supported):
    # Assumes format is "vc+sd-jwt"
    if request.get("vct", "") == supported.get("vct", ""):
        return True
    else:
        return False


def matching_authz_detail_against_supported(authz_detail, supported):
    if authz_detail.get("type", "") != "openid_credential":
        return []

    matching = []
    for _attr in ["format", "credential_configuration_id"]:
        _item = authz_detail.get(_attr, "")
        if _item:
            for name, cs in supported.items():
                if _attr == "credential_configuration_id":
                    if name == _item:
                        matching.append(cs)
                elif _attr == "format":
                    if cs.get(_attr, "") == _item:
                        if _attr == "format" and _item == "vc+sd-jwt":
                            if match_vc_sd_jwt_format(authz_detail, cs):
                                matching.append(cs)
    return matching


class CredentialConstructor(object):

    def __init__(self, upstream_get, **kwargs):
        self.upstream_get = upstream_get

    def calculate_attribute_disclosure(self, info):
        attribute_disclosure = self.upstream_get('context').claims.get_preference(
            "attribute_disclosure")
        if attribute_disclosure:
            return {"": {k: v for k, v in info.items() if k in attribute_disclosure[""]}}
        else:
            return {}

    def calculate_array_disclosure(self, info):
        array_disclosure = self.upstream_get('context').claims.get_preference("array_disclosure")
        _discl = {}
        if array_disclosure:
            for k in array_disclosure:
                if k in info and len(info[k]) > 1:
                    _discl[k] = info[k]

        return _discl

    def matching_credentials_supported(self, authz_detail):
        _supported = self.upstream_get('context').claims.get_preference(
            "credential_configurations_supported")
        logger.debug(f"Credential_supported: {_supported}")
        matching = []
        if _supported:
            m = matching_authz_detail_against_supported(authz_detail, _supported)
            if m:
                matching.extend(m)

        return matching

    @staticmethod
    def _must_display(disclose, must_display):
        for part, spec in disclose.items():
            if part == "":
                for key, val in spec.items():
                    _val = must_display.get(key)
                    if _val == val:
                        del must_display[key]
                    elif isinstance(_val, list) and val in _val:
                        _val.remove(val)
            else:
                _dict = must_display.get(part)
                if _dict:
                    for key, val in spec.items():
                        _val = _dict.get(key)
                        if _val == val:
                            del _dict[part][key]
                        elif isinstance(_val, list) and val in _val:
                            _val.remove(val)
                if dict == {}:
                    del must_display[part]
        return must_display

    def __call__(self,
                 user_id: str,
                 client_id: str,
                 request: Optional[Union[dict, Message]] = None,
                 grant: Optional[dict] = None,
                 id_token: Optional[str] = None,
                 authz_detail: Optional[dict] = None,
                 persistence: Optional[Persistence] = None
                 ) -> str:
        logger.debug(":" * 20 + f"Credential constructor" + ":" * 20)

        # If an OP was used to handle the authentication then an id_token is provided
        # In the SAML case it's SATOSA internal_data.auth_info

        logger.debug(f"authz_detail: {authz_detail}")
        # compare what this entity supports with what is requested
        _matching = self.matching_credentials_supported(authz_detail)

        if _matching == []:
            raise RequestError("unsupported_credential_type")

        _cntxt = self.upstream_get("context")
        _mngr = _cntxt.session_manager

        # This is what the requester hopes to get
        if "credential_definition" in authz_detail:
            _req_cd = CredentialDefinition().from_dict(authz_detail["credential_definition"])
            csub = _req_cd.get("credentialSubject", {})
            if csub:
                _claims_restriction = {c: None for c in csub.keys()}
            else:
                _claims_restriction = {c: None for c in _matching[0].keys()}
        else:
            _claims_restriction = {}
            for m in _matching:
                if "credential_definition" in m:
                    _req_cd = CredentialDefinition().from_dict(m["credential_definition"])
                    csub = _req_cd.get("credentialSubject", {})
                    _restriction = {c: None for c in csub.keys()}
                    _claims_restriction.update(_restriction)

        logger.debug(f"claims_restriction: {_claims_restriction}")
        # Collect user info
        info = _cntxt.claims_interface.get_user_claims(user_id,
                                                       claims_restriction=_claims_restriction,
                                                       client_id=client_id)

        logger.debug(f"user claims [{user_id}]: {info}")

        # Initiate the Issuer
        ci = Issuer(
            key_jar=self.upstream_get("attribute", "keyjar"),
            iss=self.upstream_get("attribute", "entity_id"),
            sign_alg="ES256",
            lifetime=900,
            holder_key={}
        )
        must_display = info.copy()

        # First object disclosure
        _attribute_disclose = self.calculate_attribute_disclosure(info)

        if _attribute_disclose:
            # Figure out what must be displayed
            ci.objective_disclosure = _attribute_disclose
            must_display = self._must_display(_attribute_disclose, must_display)

        # Then array disclosure
        _array_disclosure = self.calculate_array_disclosure(info)
        if _array_disclosure:
            ci.array_disclosure = _array_disclosure

        # create SD-JWT
        return ci.create_holder_message(payload=must_display, jws_headers={"typ": "example+sd-jwt"})


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
                                               persistence=_persistence )
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
