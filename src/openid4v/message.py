import json
from urllib.parse import urlsplit

from cryptojwt import JWT
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory
from fedservice import message as fed_msg
from fedservice.message import SINGLE_REQUIRED_DICT
from idpyoidc import verified_claim_name
from idpyoidc.exception import MissingAttribute
from idpyoidc.message import json_deserializer
from idpyoidc.message import json_serializer
from idpyoidc.message import Message
from idpyoidc.message import msg_list_ser
from idpyoidc.message import msg_ser
from idpyoidc.message import oauth2
from idpyoidc.message import oidc
from idpyoidc.message import OPTIONAL_LIST_OF_DICTS
from idpyoidc.message import OPTIONAL_LIST_OF_MESSAGES
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import OPTIONAL_MESSAGE
from idpyoidc.message import REQUIRED_LIST_OF_DICTS
from idpyoidc.message import REQUIRED_LIST_OF_STRINGS
from idpyoidc.message import REQUIRED_MESSAGE
from idpyoidc.message import SINGLE_OPTIONAL_INT
from idpyoidc.message import SINGLE_OPTIONAL_JSON
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_JSON
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message.oauth2 import deserialize_from_one_of
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import JsonWebToken
from idpyoidc.message.oidc import jwt_deser
from idpyoidc.message.oidc import SINGLE_OPTIONAL_BOOLEAN
from idpyoidc.message.oidc import SINGLE_OPTIONAL_DICT
from idpyoidc.message.oidc.identity_assurance import REQUIRED_VERIFIED_CLAIMS
from idpysdjwt.holder import Holder

from openid4v.utils import extract_key_from_jws
from openid4v.utils import jws_issuer


class ProofToken(JsonWebToken):
    c_param = {
        "iss": SINGLE_OPTIONAL_STRING,
        "aud": SINGLE_REQUIRED_STRING,  # Array of strings or string
        "iat": SINGLE_REQUIRED_INT,
        "nonce": SINGLE_REQUIRED_STRING
    }


class Proof(Message):
    c_param = {
        "proof_type": SINGLE_REQUIRED_STRING
    }

    def verify(self, **kwargs):
        super(Proof, self).verify(**kwargs)
        if self["proof_type"] == "jwt":
            if 'jwt' not in self:
                raise MissingAttribute("jwt parameter missing")

            key_jar = kwargs.get("keyjar")
            # first get the key from JWT:jwk
            _jws = factory(self["jwt"])
            if "jwk" in _jws.jwt.headers:
                _key = key_from_jwk_dict(_jws.jwt.headers["jwk"])
                _payload = _jws.jwt.payload()
                key_jar.add_keys(_payload["iss"], [_key])

            # verify key_proof
            _verifier = JWT(key_jar=key_jar, msg_cls=ProofToken)
            _proof_token = _verifier.unpack(self["jwt"])

            # typ MUST be specified in the JWS header and MUST be 'openid4vci-proof+jwt'
            _header = _proof_token.jws_header
            if "typ" in _header and _header['typ'] == 'openid4vci-proof+jwt':
                pass
            else:
                raise ValueError("Wrong value type")

            self[verified_claim_name("proof")] = _proof_token


def proof_deser(val, sformat=dict):
    return deserialize_from_one_of(val, Proof, sformat)


SINGLE_OPTIONAL_PROOF = (Proof, False, msg_ser, proof_deser, False)

SINGLE_REQUIRED_PROOF_TOKEN = (Message, True, msg_ser, jwt_deser, False)


class ProofJWT(Proof):
    c_param = Proof.c_param.copy()
    c_param.update({
        "jwt": SINGLE_REQUIRED_STRING
    })

    def verify(self, **kwargs):
        super().verify(**kwargs)
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


OPTIONAL_DISPLAY_PROPERIES = ([DisplayProperty], False, msg_ser, disp_props_deser, False)


class ClaimsSupport(Message):
    c_param = {
        "mandatory": SINGLE_OPTIONAL_BOOLEAN,
        "value_type": SINGLE_OPTIONAL_STRING,
        "display": OPTIONAL_DISPLAY_PROPERIES
    }

    def verify(self, **kwargs):
        super(ClaimsSupport, self).verify(**kwargs)
        if "display" in self:
            for v in self["display"]:
                v.verify()


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
    CredentialSubject, False, msg_list_ser, cred_subj_deser, False)


class CredentialDefinition(Message):
    c_param = {
        "type": REQUIRED_LIST_OF_STRINGS,
        "credentialSubject": OPTIONAL_LIST_OF_CREDENTIALSUBJECTS
    }

    def verify(self, **kwargs):
        super(CredentialDefinition, self).verify(**kwargs)
        if "credentialSubject" in self:
            self["credentialSubject"].verify(**kwargs)


def cred_def_deser(val, sformat="json"):
    if sformat == "dict":
        return deserialize_from_one_of(val, CredentialDefinition, "dict")
    else:
        return deserialize_from_one_of(val, CredentialDefinition, "json")


SINGLE_REQUIRED_CREDENTIAL_DEFINITION = (
    CredentialDefinition, True, msg_ser, cred_def_deser, False
)
SINGLE_OPTIONAL_CREDENTIAL_DEFINITION = (
    CredentialDefinition, True, msg_ser, cred_def_deser, False
)


class CredentialResponseEncryption(Message):
    c_param = {
        "jwk": SINGLE_REQUIRED_STRING,
        "alg": SINGLE_REQUIRED_STRING,
        "enc": SINGLE_REQUIRED_STRING
    }


class CredentialRequest(Message):
    c_param = {
        "format": SINGLE_REQUIRED_STRING,
        "proof": SINGLE_OPTIONAL_PROOF,
        "credential_response_encryption": SINGLE_OPTIONAL_JSON,
        "credential_identifier": SINGLE_OPTIONAL_STRING
    }

    def verify(self, **kwargs):
        super().verify(**kwargs)
        _cre_spec = self.get("credential_response_encryption", None)
        if _cre_spec:
            if isinstance(_cre_spec, str):
                _cre = CredentialResponseEncryption(**json.loads(_cre_spec))
            else:
                _cre = CredentialResponseEncryption(**_cre_spec)
            _cre.verify()
            self["credential_response_encryption"] = _cre
            self["_key"] = key_from_jwk_dict(_cre["jwk"])

        if "proof" in self:
            _proof = self["proof"]
            if "proof_type" not in _proof:
                raise MissingAttribute("Missing proof_type in proof")
            if _proof["proof_type"] == "jwt":
                _jwt = _proof.get("jwt", None)
                if not _jwt:
                    raise MissingAttribute("Expected 'jwt' claim")
                _keyjar = kwargs.get("keyjar")
                _key = extract_key_from_jws(_jwt)
                _iss = jws_issuer(_jwt)
                _keyjar.add_keys(_iss, [_key])
                _jwt_proof = JwtKeyProof().from_jwt(_jwt, _keyjar)


class CredentialRequestJwtVcJson(CredentialRequest):
    c_param = {
        "format": SINGLE_REQUIRED_STRING,
        "proof": REQUIRED_MESSAGE,
        "credential_definition": SINGLE_REQUIRED_CREDENTIAL_DEFINITION
    }

    def verify(self, **kwargs):
        super(CredentialRequestJwtVcJson, self).verify(**kwargs)

        self['proof'] = ProofJWT(**self['proof'])
        self['proof'].verify(**kwargs)


class AuthorizationDetail(Message):
    c_param = {
        "type": SINGLE_REQUIRED_STRING,
        "format": SINGLE_REQUIRED_STRING,
        "locations": OPTIONAL_LIST_OF_STRINGS,
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

        _detail_type = {
            "jwt_vc_json": self._verify_jwt_vc_json,
            "ldp_vc": self._verify_ldp_vc,
            "mso_mdoc": self._verify_mso_mdoc
        }

        if self["type"] == "openid_credential":
            # Expect format
            if "format" not in self:
                raise MissingAttribute("Expected 'format' in authorization_detail")

            _verifier = _detail_type.get(self["format"])
            if _verifier:
                _verifier(**kwargs)
            else:
                raise SystemError(f"Unsupported format {self['format']}")


def auth_detail_deser(val, sformat="dict"):
    return deserialize_from_one_of(val, AuthorizationDetail, sformat)


def auth_detail_list_deser(val, sformat="dict"):
    if isinstance(val, list):
        return [auth_detail_deser(v, sformat) for v in val]
    else:
        if val.startswith("[") and val.endswith("]"):
            val = val[2:-2].split(",")
            return [auth_detail_deser(v, sformat) for v in val]

        return [auth_detail_deser(val, sformat)]


OPTIONAL_LIST_OF_AUTHORIZATION_DETAILS = ([AuthorizationDetail], False, msg_list_ser,
                                          auth_detail_list_deser, False)


# class AuthorizationRequest(oidc.AuthorizationRequest):
#     c_param = oidc.AuthorizationRequest.c_param.copy()
#     c_param.update({
#         "wallet_issuer": SINGLE_OPTIONAL_STRING,
#         "user_hint": SINGLE_OPTIONAL_STRING,
#         "issuer_state": SINGLE_OPTIONAL_STRING
#     })


class CredentialMetadata(Message):
    c_param = {
        "format": SINGLE_REQUIRED_STRING,
        "id": SINGLE_REQUIRED_STRING,
        "credential_definition": SINGLE_OPTIONAL_CREDENTIAL_DEFINITION,
        "cryptographic_binding_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "cryptographic_suites_supported": OPTIONAL_LIST_OF_STRINGS,
        "proof_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "display": OPTIONAL_DISPLAY_PROPERIES
    }

    def verify(self, **kwargs):
        super(CredentialMetadata, self).verify(**kwargs)
        if "credential_definition" in self:
            self["credential_definition"].verify()
        if "display" in self:
            for disp in self["display"]:
                disp.verify()


class AuthorizationGrantType(Message):
    c_param = {
        "issuer_state": SINGLE_OPTIONAL_STRING
    }


class PreAuthorizedGrantType(Message):
    c_param = {
        "pre-authorized_code": SINGLE_REQUIRED_STRING,
        "user_pin_required": SINGLE_OPTIONAL_BOOLEAN,
        "interval": SINGLE_OPTIONAL_INT
    }


def json_list_deser(val, sformat=dict):
    return [json_deserializer(v, sformat) for v in val]


def json_list_ser(val, sformat=dict):
    return [json_serializer(v, sformat) for v in val]


REQUIRED_LIST_OF_JSON = ([dict], True, json_list_ser, json_list_deser, False)


class CredentialsSupported(Message):
    c_param = {
        "format": SINGLE_REQUIRED_STRING,
        "scope": SINGLE_OPTIONAL_STRING,
        "cryptographic_binding_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "cryptographic_suites_supported": OPTIONAL_LIST_OF_STRINGS,
        "proof_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "display": OPTIONAL_DISPLAY_PROPERIES,
        "credential_definition": SINGLE_OPTIONAL_CREDENTIAL_DEFINITION
    }

    def verify(self, **kwargs):
        if self["format"] == "jwt_vc_json":
            if "credential_definition" not in self:
                raise ValueError("'credential_definition' MUST be present if format == jwt_vc_json")


def cred_deser(val, sformat=dict):
    return deserialize_from_one_of(val, CredentialsSupported, sformat)


def cred_list_des(val, sformat=dict):
    if isinstance(val, list):
        return [cred_deser(v, sformat) for v in val]
    else:
        return [cred_deser(val, sformat)]


REQUIRED_LIST_OF_CREDENTIAL_TYPES = (
    [CredentialsSupported], True, msg_list_ser, cred_list_des, False)


class CredentialOffer(Message):
    c_param = {
        "credential_issuer": SINGLE_REQUIRED_STRING,
        "credentials": OPTIONAL_LIST_OF_MESSAGES,
        "grants": SINGLE_OPTIONAL_JSON
    }

    def verify(self, **kwargs):
        super(CredentialOffer, self).verify(**kwargs)
        if 'grants' in self and self['grants']:
            kwargs = {}
            for k, v in self['grants'].items():
                _g = None
                if k == "authorization_code":
                    _g = AuthorizationGrantType(**v)
                elif k == "urn:ietf:params:oauth:grant-type:pre-authorized_code":
                    _g = PreAuthorizedGrantType(**v)

                if _g:
                    _g.verify()
                    kwargs[k] = _g
            for k, v in kwargs.items():
                self['grants'][k] = v

        if "credentials" in self:
            for credential in self["credentials"]:
                args = []
                if isinstance(credential, str):  # TODO - reference to credentials_supported
                    pass
                else:  # CredentialMetadata
                    args.append(CredentialMetadata(**credential))
                self['credentials'] = args

        if "credential_issuer" in self:
            part = urlsplit(self['credential_issuer'])
            if part.scheme != "https":
                raise ValueError("Wrong URL scheme on credential issuer")
            if part.query or part.fragment:
                raise ValueError("Credential issuer can not contain query or fragment")


class CredentialIssuerMetadata(Message):
    c_param = {
        "credential_issuer": SINGLE_REQUIRED_STRING,
        "authorization_server": SINGLE_OPTIONAL_STRING,
        "credential_endpoint": SINGLE_REQUIRED_STRING,
        "batch_credential_endpoint": SINGLE_OPTIONAL_STRING,
        "deferred_credential_endpoint": SINGLE_OPTIONAL_STRING,
        "credential_response_encryption_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "credential_response_encryption_enc_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "require_credential_response_encryption": SINGLE_OPTIONAL_BOOLEAN,
        "credential_configurations_supported": REQUIRED_LIST_OF_CREDENTIAL_TYPES,
        "display": OPTIONAL_DISPLAY_PROPERIES,
        "jwks": SINGLE_OPTIONAL_DICT,
        "jwks_uri": SINGLE_OPTIONAL_STRING
    }


class AuthorizationRequest(oauth2.AuthorizationRequest):
    c_param = oauth2.AuthorizationRequest.c_param.copy()
    c_param.update({"authorization_details": OPTIONAL_LIST_OF_AUTHORIZATION_DETAILS})

    def verify(self, **kwargs):
        super(AuthorizationRequest, self).verify(**kwargs)


class AccessTokenRequest(oauth2.AccessTokenRequest):
    c_param = oidc.AccessTokenRequest.c_param.copy()
    c_param.update({
        "pre-authorized_code": SINGLE_OPTIONAL_STRING,
        "user_pin": SINGLE_OPTIONAL_STRING,
    })


class AccessTokenResponse(oauth2.AccessTokenResponse):
    c_param = oauth2.AccessTokenResponse.c_param.copy()
    c_param.update({
        "c_nonce": SINGLE_OPTIONAL_STRING,
        "c_nonce_expires_in": SINGLE_OPTIONAL_INT
    })


class CredentialDefinition(Message):
    c_param = {
        "type": REQUIRED_LIST_OF_STRINGS
    }


class CredentialResponse(ResponseMessage):
    c_param = {
        "format": SINGLE_REQUIRED_STRING,
        "credential": SINGLE_OPTIONAL_STRING,
        "transaction_id": SINGLE_OPTIONAL_STRING,
        "c_nonce": SINGLE_OPTIONAL_STRING,
        "c_nonce_expires_in": SINGLE_OPTIONAL_INT
    }

    def verify(self, **kwargs):
        if "credential" in self and "transaction_id" in self:
            ValueError("'credential' and 'transaction_id' can not appear at the same time")
        if "credential" not in self and "transaction_id" not in self:
            MissingAttribute("One of 'credential' or 'transaction_id' must be given")

        if "credential" in self:
            recv = Holder(key_jar=kwargs.get("keyjar"))
            _msg = recv.parse(self["credential"])
            self[verified_claim_name("credential")] = recv.payload


class WalletProviderMetadata(Message):
    c_param = {
        "policy_uri": SINGLE_OPTIONAL_STRING,
        "tos_uri": SINGLE_OPTIONAL_STRING,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "jwks": SINGLE_REQUIRED_JSON,
        "token_endpoint": SINGLE_REQUIRED_STRING,
        "wallet_provider_challenge_endpoint": SINGLE_REQUIRED_STRING,
        "wallet_provider_registration_endpoint": SINGLE_OPTIONAL_STRING,
        "attested_security_context_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "grant_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "token_endpoint_auth_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "token_endpoint_auth_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS
    }


class DeviceIntegrityServiceMetadata(Message):
    c_param = {
        "device_integrity_endpoint": SINGLE_REQUIRED_STRING,
        "device_key_attestation_endpoint": SINGLE_REQUIRED_STRING
    }

class VerifierServiceMetadata(Message):
    c_param = {
        "resource_verifier_endpoint": SINGLE_REQUIRED_STRING
    }

class WalletAttestationRequestJWT(Message):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "aud": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
        "exp": SINGLE_REQUIRED_INT,
        "challenge": SINGLE_REQUIRED_STRING,
        "hardware_signature": SINGLE_REQUIRED_STRING,
        "integrity_assertion": SINGLE_REQUIRED_STRING,
        "hardware_key_tag": SINGLE_REQUIRED_STRING,
        "cnf": SINGLE_REQUIRED_JSON
    }


class WalletInstanceRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "assertion": SINGLE_REQUIRED_STRING
    }

    def verify(self, **kwargs):
        super(WalletInstanceRequest, self).verify(**kwargs)

        _allowed_sign_algs = kwargs.get("allowed_sign_algs", ["ES256"])
        _verifier = JWT(key_jar=kwargs["keyjar"], allowed_sign_algs=_allowed_sign_algs)
        # if the 'typ' parameter in the JWT header matches one of the keys in this dictionary then
        # the payload is mapped into the corresponding class
        _verifier.typ2msg_cls = {
            "wallet-attestation+jwt": WalletAttestationRequestJWT
        }

        _request = _verifier.unpack(self["assertion"])
        if isinstance(_request, Message):
            _request.verify()
        self[verified_claim_name("assertion")] = _request


class WalletInstanceAttestationJWT(Message):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        # "sub": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
        "exp": SINGLE_REQUIRED_INT,
        "aal": SINGLE_REQUIRED_STRING,
        "cnf": SINGLE_REQUIRED_JSON,
        # "attested_security_context": SINGLE_OPTIONAL_STRING,
        "authorization_endpoint": SINGLE_OPTIONAL_STRING,
        "response_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_modes_supported": OPTIONAL_LIST_OF_STRINGS,
        "vp_formats_supported": SINGLE_REQUIRED_JSON,
        "request_object_signing_alg_values_supported": REQUIRED_LIST_OF_STRINGS,
        "presentation_definition_uri_supported": SINGLE_OPTIONAL_BOOLEAN
    }


class WalletProvider(Message):
    c_param = {
        "jwks": SINGLE_REQUIRED_JSON,
        "token_endpoint": SINGLE_REQUIRED_STRING,
        "aal_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "grant_types_supported": REQUIRED_LIST_OF_STRINGS,
        "token_endpoint_auth_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "token_endpoint_auth_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS
    }


class WalletInstanceAttestationResponse(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "assertion": SINGLE_REQUIRED_STRING
    }

    def verify(self, **kwargs):
        super(WalletInstanceAttestationResponse, self).verify(**kwargs)

        _allowed_sign_algs = kwargs.get("allowed_sign_algs", ["ES256"])
        _verifier = JWT(key_jar=kwargs["keyjar"], allowed_sign_algs=_allowed_sign_algs)
        # if the 'typ' parameter in the JWT header matches one of the keys in this dictionary then
        # the payload is mapped into the corresponding class
        _verifier.typ2msg_cls = {
            "wallet-attestation+jwt": WalletInstanceAttestationJWT
        }

        _request = _verifier.unpack(self["assertion"])
        if isinstance(_request, Message):
            _request.verify()
        self[verified_claim_name("assertion")] = _request


class PidEaaJWT(Message):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
        "exp": SINGLE_REQUIRED_INT,
        "type": SINGLE_REQUIRED_STRING,
        "jti": SINGLE_REQUIRED_STRING,
        "status": SINGLE_OPTIONAL_STRING,
        "cnf": SINGLE_REQUIRED_JSON,
        "vct": SINGLE_REQUIRED_STRING,
        "verified_claims": REQUIRED_VERIFIED_CLAIMS
    }


class PidEaaRequest(AuthorizationRequest):
    c_param = {

    }


class JwtKeyProof(Message):
    c_param = {
        "iss": SINGLE_OPTIONAL_STRING,
        "aud": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
        "nonce": SINGLE_OPTIONAL_STRING
    }


class JwtKeyJOSEHeader(Message):
    c_param = {
        "alg": SINGLE_REQUIRED_STRING,
        "typ": SINGLE_REQUIRED_STRING,
        "kid": SINGLE_OPTIONAL_STRING,
        "jwk": SINGLE_OPTIONAL_JSON,
        "x5c": OPTIONAL_LIST_OF_STRINGS,
        "trust_chain": OPTIONAL_LIST_OF_STRINGS
    }


class ChallengeResponse(Message):
    c_param = {
        "nonce": SINGLE_REQUIRED_STRING
    }


class RegistrationRequest(Message):
    c_param = {
        "challenge": SINGLE_REQUIRED_STRING,
        "key_attestation": SINGLE_REQUIRED_STRING,
        "hardware_key_tag": SINGLE_REQUIRED_STRING
    }


MAP_TYP_MSG = {
    "openid4vci-proof+jwt": ProofJWT
}


class AuthorizationServerMetadata(fed_msg.AuthorizationServerMetadata):
    c_param = fed_msg.AuthorizationServerMetadata.c_param.copy()
    c_param.update({
        "pushed_authorization_request_endpoint": SINGLE_OPTIONAL_STRING,
        "acr_values_supported": REQUIRED_LIST_OF_STRINGS,
        "authorization_signing_alg_values_supported": REQUIRED_LIST_OF_STRINGS,
        "token_endpoint_auth_methods_supported": REQUIRED_LIST_OF_STRINGS,
        "token_endpoint_auth_signing_alg_values_supported": REQUIRED_LIST_OF_STRINGS,
        "request_object_signing_alg_values_supported": REQUIRED_LIST_OF_STRINGS,
        "jwks": SINGLE_REQUIRED_DICT,
        "jwks_uri": SINGLE_OPTIONAL_STRING
    })


class OpenidCredentialIssuer(Message):
    c_param = {
        "credential_issuer": SINGLE_REQUIRED_STRING,
        "credential_endpoint": SINGLE_REQUIRED_STRING,
        "revocation_endpoint": SINGLE_REQUIRED_STRING,
        "status_attestation_endpoint": SINGLE_REQUIRED_STRING,
        "display": OPTIONAL_LIST_OF_DICTS,
        "credential_configurations_supported": REQUIRED_LIST_OF_DICTS,
        "jwks": SINGLE_REQUIRED_DICT,
        "jwks_uri": SINGLE_OPTIONAL_STRING
    }
