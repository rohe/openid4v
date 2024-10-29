import json
import logging
from typing import Optional
from typing import Union

from cryptojwt.jwk.jwk import key_from_jwk_dict
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.exception import RequestError
from idpyoidc.message import Message
from satosa_idpyop.utils import combine_client_subject_id

from openid4v.message import AuthorizationRequest

logger = logging.getLogger(__name__)


class CredentialConstructor(object):

    def __init__(self, upstream_get, **kwargs):
        self.upstream_get = upstream_get
        self.url = kwargs.get("url")  # MUST have a value
        self.jwks_url = kwargs.get("jwks_url", "")
        self.body = kwargs.get("body")
        if not self.body:
            self.body = {
                "authentic_source": "sunet2",
                "document_type": "PDA1",
                "document_id": "document_id_7"
            }
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

        httpc = self.upstream_get('attribute', 'httpc')
        httpc_params = self.upstream_get("attribute", "httpc_params")
        try:
            resp = httpc("GET", self.jwks_uri, **httpc_params)
        except Exception as err:
            logger.exception("fetch_jwks")
            raise err

        if resp.status_code != 200:
            logger.error(f"Jwks fetch from Credential Constructor at {self.jwks_uri} failed")
            #raise SystemError(f"Jwks fetch from Credential Constructor at {_jwks_uri} failed")
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
        httpc = self.upstream_get('attribute', 'httpc')
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
                 request: Optional[Union[dict, Message]] = None,
                 grant: Optional[dict] = None,
                 id_token: Optional[str] = None,
                 authz_detail: Optional[dict] = None
                 ) -> str:
        logger.debug(":" * 20 + f"Credential constructor[authentic_source]" + ":" * 20)

        if not self.key:
            self.fetch_jwks()
            if not self.key:
                return json.dumps({"error": "failed to pick up keys"})

        # body = {
        #     "authentic_source": "sunet2",
        #     "document_type": "PDA1",
        #     "document_id": "document_id_7"
        # }
        _body = self.body.copy()
        logger.debug(f"Original body: {_body}")
        # Get extra arguments from the authorization request
        _authz_args = {k: v for k, v in grant.authorization_request.items() if k not in AuthorizationRequest.c_param}
        _authz_args = {k: v for k, v in _authz_args.items() if k not in ["code_challenge", "code_challenge_method",
                                                                         "authenticated"]}
        _authz_args["collect_id"] = "22bb1167-3a43-4eaa-b70e-f1826e38bbac"
        logger.debug(f"Authorization request claims: {_authz_args}")
        if _authz_args:
            _body.update(_authz_args)

        _identity = {
            "authentic_source_person_id": "c117b00c-4792-4d29-896d-55e8c54f6c5c",
            "schema": {
                "name": "SE",
                # "version": "1.0.2"
            }
        }
        # and more arguments from what the authentication returned
        _persistence = self.upstream_get("attribute", "persistence")
        if _persistence:
            client_subject_id = combine_client_subject_id(client_id, user_id)
            authn_claims = _persistence.load_claims(client_subject_id)
            # filter on accepted claims
            _av = {}
            for attr, value in authn_claims.items():
                if attr in ["familyname", "givenname","birthdate"]:
                    _av[attr] = value
            logger.debug(f"Authentication claims: {_av}")
            if _av:
                _identity.update(_av)
            _body["identity"] = _identity
        else:
            _body.update(_identity)

        # http://vc-interop-1.sunet.se/api/v1/credential
        logger.debug(f"Combined body: {_body}")
        msg = self.get_response(url=self.url, body=_body, headers={'Content-Type': 'application/json'})
        logger.debug(f"return message: {msg}")
        return msg
