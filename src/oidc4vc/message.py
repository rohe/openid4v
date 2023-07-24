import json

from idpyoidc.exception import MissingAttribute
from idpyoidc.message import Message
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import OPTIONAL_MESSAGE
from idpyoidc.message import REQUIRED_LIST_OF_STRINGS
from idpyoidc.message import REQUIRED_MESSAGE
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import msg_list_ser
from idpyoidc.message import msg_ser
from idpyoidc.message import oidc
from idpyoidc.message.oauth2 import deserialize_from_one_of
from idpyoidc.message.oidc import JsonWebToken
from idpyoidc.message.oidc import SINGLE_OPTIONAL_BOOLEAN
from idpyoidc.message.oidc import jwt_deser


class Proof(Message):
    c_param = {
        "proof_type": SINGLE_REQUIRED_STRING
    }


class ProofToken(JsonWebToken):
    c_param = {
        "iss": SINGLE_OPTIONAL_STRING,
        "aud": SINGLE_REQUIRED_STRING,  # Array of strings or string
        "iat": SINGLE_REQUIRED_INT,
        "nonce": SINGLE_REQUIRED_STRING
    }


SINGLE_REQUIRED_PROOF_TOKEN = (Message, True, msg_ser, jwt_deser, False)


class ProofJWT(Proof):
    c_param = Proof.c_param.copy()
    c_param.update({
        "jwt": SINGLE_REQUIRED_STRING
    })

    def verify(self, **kwargs):
        super(ProofJWT, self).verify(**kwargs)
        _proof_token = ProofToken().from_jwt(self['jwt'], **kwargs)

        # typ MUST be specified in the JWS header and MUST be 'openid4vci-proof+jwt'
        _header = _proof_token.jws_header
        if "typ" in _header and _header['typ'] == 'openid4vci-proof+jwt':
            pass
        else:
            raise ValueError("Wrong value type")

        self['__proof_token__'] = _proof_token

class LOGO(Message):
    c_param = {
        "url": SINGLE_OPTIONAL_STRING,
        "alt_text": SINGLE_OPTIONAL_STRING
    }

def logo_deser(val, sformat="dict"):
    return deserialize_from_one_of(val, LOGO, sformat)

SINGLE_OPTIONAL_LOGO = (LOGO, False, msg_ser, logo_deser, False)

class DisplayProperty(Message):
    c_param = {
        "name": SINGLE_OPTIONAL_STRING,
        "locale": SINGLE_OPTIONAL_STRING,
        "logo": SINGLE_OPTIONAL_LOGO,
        "description": SINGLE_OPTIONAL_STRING,
        "background_color": SINGLE_OPTIONAL_STRING,
        "text_color": SINGLE_OPTIONAL_STRING
    }


def prop_deser(val, sformat="dict"):
    return deserialize_from_one_of(val, DisplayProperty, sformat)


def disp_props_deser(inst, sformat="dict"):
    if isinstance(inst, list):
        return [prop_deser(v, sformat) for v in inst]
    else:
        return prop_deser(inst, sformat)


OPTIONAL_DISPLAY_PROPERIES = (
    [DisplayProperty], False, msg_ser, disp_props_deser, False
)


class ClaimsSupport(Message):
    c_param = {
        "mandatory": SINGLE_OPTIONAL_BOOLEAN,
        "value_type": SINGLE_OPTIONAL_STRING,
        "display": OPTIONAL_DISPLAY_PROPERIES
    }


class Claims(Message):
    c_param = {}

    def verify(self, **kwargs):
        super(Claims, self).verify(**kwargs)
        _dict = {}
        for namespace, obj in self.items():
            csv = {}
            for attr, support in obj.items():
                if isinstance(support, dict):
                    _cs = ClaimsSupport(**support)
                    _cs.verify(**kwargs)
                    csv[attr] = _cs

            _dict[namespace] = csv

        for k, v in _dict.items():
            self[k] = v


def claims_deser(val, sformat="dict"):
    return deserialize_from_one_of(val, Claims, sformat)


SINGLE_OPTIONAL_CLAIMS = (
    Claims, True, msg_ser, claims_deser, False
)


class CredentialSubject(Message):
    c_param = {}

    def verify(self, **kwargs):
        super(CredentialSubject, self).verify(**kwargs)
        csv = {}
        for key, val in self.items():
            if isinstance(val, dict):
                _sup = ClaimsSupport(**val)
                _sup.verify(**kwargs)
                csv[key] = _sup

        for k, v in csv.items():
            self[k] = v


def cred_subj_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return CredentialSubject().deserialize(val, sformat)


def cred_subj_list_deser(val, sformat="urlencoded"):
    if isinstance(val, dict):
        return [CredentialSubject(**val)]

    _res = []
    for v in val:
        _res.append(cred_subj_deser(v, sformat))
    return _res


OPTIONAL_LIST_OF_CREDENTIALSUBJECTS = (
    [CredentialSubject], False, msg_list_ser, cred_subj_list_deser, False)


class CredentialDefinition(Message):
    c_param = {
        "type": REQUIRED_LIST_OF_STRINGS,
        "credentialSubject": OPTIONAL_LIST_OF_CREDENTIALSUBJECTS
    }

    def verify(self, **kwargs):
        super(CredentialDefinition, self).verify(**kwargs)
        if "credentialSubject" in self:
            for _cs in self["credentialSubject"]:
                _cs.verify(**kwargs)


def cred_def_deser(val, sformat="dict"):
    return deserialize_from_one_of(val, CredentialDefinition, sformat)


SINGLE_REQUIRED_CREDENTIAL_DEFINITION = (
    CredentialDefinition, True, msg_ser, cred_def_deser, False
)
SINGLE_OPTIONAL_CREDENTIAL_DEFINITION = (
    CredentialDefinition, True, msg_ser, cred_def_deser, False
)


class CredentialRequest(Message):
    c_param = {
        "format": SINGLE_REQUIRED_STRING,
        "proof": REQUIRED_MESSAGE,
        "doc_type": SINGLE_OPTIONAL_STRING,
        "claims": SINGLE_OPTIONAL_CLAIMS
    }


class CredentialRequestJwtVcJson(CredentialRequest):
    c_param = {
        "format": SINGLE_REQUIRED_STRING,
        "proof": REQUIRED_MESSAGE,
        "credential_definition": SINGLE_REQUIRED_CREDENTIAL_DEFINITION
    }

    def verify(self, **kwargs):
        super(CredentialRequest, self).verify(**kwargs)

        self['proof'] = ProofJWT(**self['proof'])
        self['proof'].verify(**kwargs)


class AuthorizationDetail(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "format": SINGLE_REQUIRED_STRING,
        "credential_definition": SINGLE_OPTIONAL_CREDENTIAL_DEFINITION,
        "doctype": SINGLE_OPTIONAL_STRING,
        "claims": OPTIONAL_MESSAGE
    }

    def _verify_jwt_vc_json(self, **kwargs):
        if "credential_definition" not in self:
            raise MissingAttribute("Expected 'credential_definition' in authorization_detail")
        self["credential_definition"] = CredentialDefinition(**self["credential_definition"])

    def _verify_ldp_vc(self, **kwargs):
        if "credential_definition" not in self:
            raise MissingAttribute("Expected 'credential_definition' in authorization_detail")
        self["credential_definition"] = CredentialDefinition(**self["credential_definition"])

    def _verify_mso_mdoc(self, **kwargs):
        if "doctype" not in self:
            raise MissingAttribute("Expected 'doctype' in authorization_detail")

    def verify(self, **kwargs):
        super(AuthorizationDetail, self).verify(**kwargs)

        if self["type"] == "openid_credential":
            # Expect format
            if "format" not in self:
                raise MissingAttribute("Expected 'format' in authorization_detail")

            if self["format"] == "jwt_vc_json":
                self._verify_jwt_vc_json(**kwargs)
            elif self["format"] == "ldp_vc":
                self._verify_ldp_vc(**kwargs)
            elif self['format'] == "mso_mdoc":
                self._verify_mso_mdoc(**kwargs)
            else:
                raise SystemError(f"Unsupported format {self['format']}")


class AuthorizationRequest(oidc.AuthorizationRequest):
    c_param = oidc.AuthorizationRequest.c_param.copy()
    c_param.update({
        "wallet_issuer": SINGLE_OPTIONAL_STRING,
        "user_hint": SINGLE_OPTIONAL_STRING,
        "issuer_state": SINGLE_OPTIONAL_STRING
    })


class AccessTokenRequest(oidc.AccessTokenRequest):
    c_param = oidc.AccessTokenRequest.c_param.copy()
    c_param.update({
        "pre-authorized_code": SINGLE_OPTIONAL_STRING,
        "user_pin": SINGLE_OPTIONAL_STRING,
    })

class CredentialMetadata(Message):
    c_param = {
        "format": SINGLE_REQUIRED_STRING,
        "id": SINGLE_REQUIRED_STRING,
        "cryptographic_binding_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "cryptographic_suites_supported": OPTIONAL_LIST_OF_STRINGS,
        "proof_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "display": OPTIONAL_DISPLAY_PROPERIES
    }

    def verify(self, **kwargs):
        super(CredentialMetadata, self).verify(**kwargs)