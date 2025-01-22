import json
import logging
from typing import Optional
from typing import Union

from idpyoidc.exception import RequestError
from idpyoidc.message import Message
from idpyoidc.node import topmost_unit
from idpysdjwt.issuer import Issuer
from satosa_idpyop.persistence import Persistence

from openid4v.message import CredentialDefinition

logger = logging.getLogger(__name__)


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

    def _get_userinfo(self, cntx, user_id, claims_restriction, client_id):
        if cntx.userinfo:
            info = cntx.claims_interface.get_user_claims(user_id,
                                                         claims_restriction=claims_restriction,
                                                         client_id=client_id)
        else:
            entity = topmost_unit(self)
            _oas = entity["oauth_authorization_server"]
            info = _oas.context.claims_interface.get_user_claims(user_id,
                                                                 claims_restriction=claims_restriction,
                                                                 client_id=client_id)
        return info

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
        info = self._get_userinfo(_cntxt, user_id, _claims_restriction, client_id)

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
        _sdjwt = ci.create_holder_message(payload=must_display,
                                          jws_headers={"typ": "example+sd-jwt"})
        return json.dumps({"credentials": {"credential": _sdjwt}})
