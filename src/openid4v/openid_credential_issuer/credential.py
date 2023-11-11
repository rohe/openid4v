from datetime import datetime
import logging
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
from fedservice.entity.utils import get_federation_entity
from idpyoidc.exception import RequestError
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.server.oidc.userinfo import UserInfo
from idpyoidc.server.util import execute
from idpyoidc.util import rndstr
from idpysdjwt.issuer import Issuer

from openid4v.message import CredentialDefinition
from openid4v.message import CredentialRequest
from openid4v.message import CredentialResponse
from openid4v.message import CredentialsSupported
from openid4v.message import Proof

logger = logging.getLogger(__name__)


def get_keyjar(unit):
    _fed = get_federation_entity(unit)
    if _fed:
        return _fed.keyjar
    else:
        return unit.upstream_get("attribute", "keyjar")


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

    def matching_credentials_supported(self, request):
        _supported = self.upstream_get('context').claims.get_preference(
            "credentials_supported")
        matching = []
        for cs in _supported:
            if cs["format"] != request["format"]:
                continue
            _cred_def_sup = cs["credential_definition"]
            _req_cred_def = request["credential_definition"]
            # The set of type values must match
            if set(_cred_def_sup["type"]) != set(_req_cred_def["type"]):
                continue
            matching.append(_cred_def_sup.get("credentialSubject", {}))
        return matching

    def __call__(self, user_id: str, request: Union[dict, Message]) -> str:
        # compare what this entity supports with what is requested
        _matching = self.matching_credentials_supported(request)

        if _matching == []:
            raise RequestError("unsupported_credential_type")

        _cntxt = self.upstream_get("context")
        _mngr = _cntxt.session_manager
        _session_info = _mngr.get_session_info_by_token(
            request["access_token"], grant=True, handler_key="access_token"
        )

        # This is what the requester hopes to get
        if "credential_definition" in request:
            _req_cd = CredentialDefinition().from_dict(request["credential_definition"])
            csub = _req_cd.get("credentialSubject", {})
            if csub:
                _claims_restriction = {c: None for c in csub.keys()}
            else:
                _claims_restriction = {c: None for c in _matching[0].keys()}
        else:
            _claims_restriction = {c: None for c in _matching[0].keys()}

        info = _cntxt.claims_interface.get_user_claims(
            _session_info["user_id"], claims_restriction=_claims_restriction
        )
        # create SD-JWT
        _cntxt = self.upstream_get("context")
        info = _cntxt.claims_interface.get_user_claims(
            _session_info["user_id"], claims_restriction=_claims_restriction
        )

        ci = Issuer(
            key_jar=get_keyjar(self),
            iss=self.upstream_get("attribute", "entity_id"),
            sign_alg="ES256",
            lifetime=600,
            holder_key={}
        )
        _discl = self.calculate_attribute_disclosure(info)
        if _discl:
            ci.objective_disclosure = _discl

        _discl = self.calculate_array_disclosure(info)
        if _discl:
            ci.array_disclosure = _discl

        return ci.create_holder_message(payload=info, jws_headers={"typ": "example+sd-jwt"})


class Credential(UserInfo):
    msg_type = CredentialRequest
    response_cls = CredentialResponse
    error_msg = oidc.ResponseMessage
    request_format = "json"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "credential_endpoint"
    name = "credential"
    endpoint_type = "oauth2"

    _supports = {
        "credentials_supported": None,
        "attribute_disclosure": None,
        "array_disclosure": None
    }

    def __init__(self, upstream_get, conf=None, **kwargs):
        UserInfo.__init__(self, upstream_get, conf=conf, **kwargs)
        # dpop support
        self.post_parse_request.append(self.credential_request)
        if conf and "credential_constructor" in conf:
            self.credential_constructor = execute(conf["credential_constructor"])
        else:
            self.credential_constructor = CredentialConstructor(upstream_get=upstream_get)

    def _verify_proof(self, proof):
        if proof["proof_type"] == "jwt":
            entity_id = self.upstream_get("attribute", "entity_id")
            key_jar = get_keyjar(self)
            # first get the key from JWT:jwk
            _jws = factory(proof["jwt"])
            key_jar.add_key(entity_id, _jws.jwt.payload()["jwk"])

            # verify key_proof
            _verifier = JWT(key_jar=key_jar)
            _payload = _verifier.unpack(proof["jwt"])
            return _payload

    def credential_request(
            self,
            request: Optional[Union[Message, dict]] = None,
            client_id: Optional[str] = "",
            http_info: Optional[dict] = None,
            auth_info: Optional[dict] = None,
            **kwargs,
    ):
        """The Credential endpoint

        :param http_info: Information on the HTTP request
        :param request: The authorization request as a Message instance
        :return: dictionary
        """

        if "error" in request:
            return request

        _cred_request = CredentialsSupported().from_dict(request)

        _proof = Proof().from_dict(request["proof"])
        entity_id = self.upstream_get("attribute", "entity_id")
        keyjar = get_federation_entity(self).keyjar
        _proof.verify(keyjar=keyjar, aud=entity_id)
        request["proof"] = _proof
        return request

    def verify_token_and_authentication(self, request):
        _mngr = self.upstream_get("context").session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(
                request["access_token"], grant=True, handler_key="access_token"
            )
        except (KeyError, ValueError):
            return self.error_cls(error="invalid_token", error_description="Invalid Token")

        _grant = _session_info["grant"]
        token = _grant.get_token(request["access_token"])
        # should be an access token
        if token and token.token_class != "access_token":
            return self.error_cls(error="invalid_token", error_description="Wrong type of token")

        # And it should be valid
        if token.is_active() is False:
            return self.error_cls(error="invalid_token", error_description="Invalid Token")

        _auth_event = _grant.authentication_event
        # if the authentication is still active or offline_access is granted.
        if not _auth_event["valid_until"] >= utc_time_sans_frac():
            logger.debug(
                "authentication not valid: {} > {}".format(
                    datetime.fromtimestamp(_auth_event["valid_until"]),
                    datetime.fromtimestamp(utc_time_sans_frac()),
                )
            )
            return False, None

            # This has to be made more finegrained.
            # if "offline_access" in session["authn_req"]["scope"]:
            #     pass
        return True, _session_info["client_id"]

    def process_request(self, request=None, **kwargs):
        allowed, client_id = self.verify_token_and_authentication(request)
        if not isinstance(allowed, bool):
            return allowed

        if not allowed:
            return self.error_cls(error="invalid_token", error_description="Access not granted")

        try:
            _mngr = self.upstream_get("context").session_manager
            _session_info = _mngr.get_session_info_by_token(
                request["access_token"], grant=True, handler_key="access_token"
            )
        except (KeyError, ValueError):
            return self.error_cls(error="invalid_token", error_description="Invalid Token")

        _msg = self.credential_constructor(user_id=_session_info["user_id"], request=request)

        _resp = {
            "format": "vc+sd-jwt",
            "credential": _msg,
            "c_nonce": rndstr(),
            "c_nonce_expires_in": 86400
        }

        return {"response_args": _resp, "client_id": client_id}
