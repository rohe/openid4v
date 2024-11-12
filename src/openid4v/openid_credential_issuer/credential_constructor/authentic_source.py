import json
import logging
from typing import Optional
from typing import Union

from cryptojwt.jwk.jwk import key_from_jwk_dict
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.exception import RequestError
from idpyoidc.message import Message
from satosa_idpyop.persistence import Persistence
from satosa_idpyop.utils import combine_client_subject_id

logger = logging.getLogger(__name__)

EXAMPLE = [
    {
        "credential_type": "sdjwt",
        "authentic_source": "authentic_source_se",
        "document_type": "EHIC",
        "collect_id": "collect_id_10",
        "authentic_source_person_id": "10",
        "family_name": "Castaneda",
        "given_name": "Carlos",
        "birth_date": "1970-01-10",
        "identity": {
            "schema": {
                "name": "SE",
            }
        }
    },
    {
        "credential_type": "sdjwt",
        "authentic_source": "authentic_source_at",
        "document_type": "EHIC",
        "collect_id": "collect_id_11",
        "authentic_source_person_id": "11",
        "family_name": "Howell",
        "given_name": "Lenna",
        "birth_date": "1935-02-21",
        "identity": {
            "schema": {
                "name": "AT",
            }
        }
    },
    {
        "credential_type": "sdjwt",
        "authentic_source": "authentic_source_dk",
        "document_type": "PDA1",
        "collect_id": "collect_id_20",
        "authentic_source_person_id": "20",
        "family_name": "Christiansen",
        "given_name": "Mats",
        "birth_date": "1983-03-27",
        "identity": {
            "schema": {
                "name": "DK",
            }
        }
    }
]

OVERRIDE = True


def matches_example(body):
    keys = list(body.keys())
    keys.remove("identity")
    base = {k: v for k, v in body.items() if k in keys}
    for ex in EXAMPLE:
        _cmp = {k: v for k, v in ex.items() if k in keys}
        if base == _cmp:
            return ex
    return None


def fetch_userinfo(body):
    ex = matches_example(body)
    if ex:
        body["identity"] = ex["identity"]
        _ava = {k: v for k, v in ex.items() if k in ["authentic_source_person_id", "family_name", "given_name",
                                                     "birth_date"]}
        body["identity"].update(_ava)

    return body


class CredentialConstructor(object):

    def __init__(self, upstream_get, **kwargs):
        self.upstream_get = upstream_get
        self.url = kwargs.get("url")  # MUST have a value
        self.jwks_url = kwargs.get("jwks_url", "")
        self.body = kwargs.get("body")
        if not self.body:
            self.body = {k: v for k, v in EXAMPLE[0].items() if
                         k in ["authentic_source", "document_type", "credential_type"]}
        self.key = []
        self.jwks_uri = self.jwks_url or f"{self.url}/.well-known/jwks.json"
        logger.debug(f"jwks_uri: {self.jwks_uri}")
        self.fetch_jwks()

    def fetch_jwks(self):
        # fetch public key from the credential constructor
        # Format
        # {"issuer":"https://vc-interop-1.sunet.se",
        # "jwks":{
        #   "keys":[
        #       {"kid":"singing_",
        #        "crv":"P-256","kty":"EC","x":"jBdJcpK9LCxRvd7kQnhonSsN_fQ6q8fEhclThBRYAt4",
        #        "y":"8rVwmwcFy85bUZn3h00sMiAiFygnhBs0CRL5xFKsuXQ",
        #        "d":"3h0daeEviT8O_VMt0jA0bF-kecfnQcaT8yM6wjWJU78"}]}

        httpc = self.upstream_get("attribute", "httpc")
        httpc_params = self.upstream_get("attribute", "httpc_params")
        try:
            resp = httpc("GET", self.jwks_uri, **httpc_params)
        except Exception as err:
            logger.exception("fetch_jwks")
            raise err

        if resp.status_code != 200:
            logger.error(f"Jwks fetch from Credential Constructor at {self.jwks_uri} failed")
            # raise SystemError(f"Jwks fetch from Credential Constructor at {_jwks_uri} failed")
        else:
            _info = json.loads(resp.text)
            logger.debug(f"Fetched Credential Constructors keys: {_info}")
            # Two keys
            if "issuer" in _info and "jwks" in _info:
                self.key = []
                for key_spec in _info["jwks"]["keys"]:
                    _key = key_from_jwk_dict(key_spec)
                    if _key not in self.key:
                        self.key.append(_key)
                logger.debug(f"Credential Constructors keys: {[k.serialize() for k in self.key]}")
            else:
                raise ValueError("Missing jwks_info parameter")

    def get_response(
            self,
            url: str,
            method: Optional[str] = "POST",
            body: Optional[dict] = None,
            headers: Optional[dict] = None,
            **kwargs
    ):
        """

        :param url:
        :param method:
        :param body:
        :param response_body_type:
        :param headers:
        :param kwargs:
        :return:
        """
        httpc = self.upstream_get("attribute", "httpc")
        httpc_params = self.upstream_get("attribute", "httpc_params")
        try:
            resp = httpc(method, url, data=json.dumps(body), headers=headers, **httpc_params)
        except Exception as err:
            logger.error(f"Exception on request: {err}")
            raise RequestError(f"HTTP request failed {err}")

        if 400 <= resp.status_code:
            logger.error("Error response ({}): {}".format(resp.status_code, resp.text))
            raise OidcServiceError(f"HTTP ERROR: {resp.text} [{resp.status_code}] on {resp.url}")
        elif 300 <= resp.status_code < 400:
            return {"http_response": resp}
        else:
            return resp.text

    def __call__(self,
                 user_id: str,
                 client_id: str,
                 request: Union[dict, Message],
                 grant: Optional[dict] = None,
                 id_token: Optional[str] = None,
                 authz_detail: Optional[dict] = None,
                 persistence: Optional[Persistence] = None,
                 ) -> str:
        logger.debug(":" * 20 + f"Credential constructor[authentic_source]" + ":" * 20)

        if not self.key:
            self.fetch_jwks()
            if not self.key:
                return json.dumps({"error": "failed to pick up keys"})

        # Get extra arguments from the authorization request if available
        _authz_args = {}
        for k in ["collect_id", "authentic_source", "document_type", "credential_type", "identity"]:
            _val = grant.authorization_request.get(k, None)
            if _val:
                _authz_args[k] = _val
            else:
                _authz_args[k] = EXAMPLE[0][k]

        logger.debug(f"Authorization request claims: {_authz_args}")
        _body = _authz_args

        # and more arguments from what the authentication returned
        # _persistence = self.upstream_get("attribute", "persistence")
        if persistence:
            ex = matches_example(_body)
            if ex:
                _body["identity"] = ex["identity"]
                _ava = {k: v for k, v in ex.items() if k in ["authentic_source_person_id", "family_name", "given_name",
                                                             "birth_date"]}
                _body["identity"].update(_ava)
            else:
                logger.debug(f"Using {persistence.name} persistence layer")
                client_subject_id = combine_client_subject_id(client_id, user_id)
                authn_claims = persistence.load_claims(client_subject_id)
                # filter on accepted claims
                _av = {}
                if {"family_name", "given_name", "birth_date"}.issubset(set(list(authn_claims.keys()))):
                    for attr, value in authn_claims.items():
                        if attr in ["family_name", "given_name", "birth_date"]:
                            _av[attr] = value
                else:
                    for attr in ["family_name", "given_name", "birth_date"]:
                        _av[attr] = EXAMPLE[0][attr]
                logger.debug(f"Authentication claims: {_av}")

            _body["identity"].update(_av)
        else:
            _body = fetch_userinfo(_body)

        _body["jwk"] = request["__verified_proof"].jws_header["jwk"]
        # http://vc-interop-1.sunet.se/api/v1/credential
        logger.debug(f"Combined body: {_body}")
        msg = self.get_response(url=self.url, body=_body, headers={"Content-Type": "application/json"})
        logger.debug(f"return message: {msg}")
        return msg
