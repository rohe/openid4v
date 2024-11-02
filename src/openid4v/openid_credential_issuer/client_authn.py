import logging
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt.exception import BadSignature
from cryptojwt.exception import Invalid
from cryptojwt.exception import IssuerNotFound
from cryptojwt.exception import MissingKey
from cryptojwt.jws.jws import factory
from fedservice.entity import get_verified_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.exception import NoTrustedChains
from fedservice.utils import get_jwks
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message
from idpyoidc.message.oidc import JsonWebToken
from idpyoidc.node import topmost_unit
from idpyoidc.server.client_authn import ClientAuthnMethod
from idpyoidc.server.exception import ClientAuthenticationError

from openid4v import ASSERTION_TYPE
from openid4v.message import WalletInstanceAttestationJWT

logger = logging.getLogger(__name__)


def verify_wallet_instance_attestation(client_assertion, keyjar, unit, attestation_class):
    _jws = factory(client_assertion)
    _payload = _jws.jwt.payload()
    if _payload["iss"] not in keyjar:
        if "trust_chain" in _jws.jwt.headers:
            _tc = verify_trust_chains(unit, [_jws.jwt.headers["trust_chain"]])
            if _tc:
                _entity_conf = _tc[0].verified_chain[-1]
                get_jwks(unit, keyjar, _entity_conf["metadata"]["wallet_provider"], _entity_conf["sub"])
        else:
            chains = get_verified_trust_chains(unit, _payload["iss"])
            if chains:
                _entity_conf = chains[0].verified_chain[-1]
                get_jwks(unit, keyjar, _entity_conf["metadata"]["wallet_provider"], _entity_conf["sub"])
            else:
                logger.debug(f"Found no Trust Chains for {_payload['iss']}")
                raise NoTrustedChains(_payload['iss'])

    _verifier = JWT(keyjar)
    if attestation_class:
        _verifier.typ2msg_cls = attestation_class

    try:
        _wia = _verifier.unpack(client_assertion)
    except (Invalid, MissingKey, BadSignature, IssuerNotFound) as err:
        # logger.info("%s" % sanitize(err))
        raise ClientAuthenticationError(f"{err.__class__.__name__} {err}")
    except Exception as err:
        raise err

    if isinstance(_wia, Message):
        _wia.verify()

    return _wia


class ClientAssertion(ClientAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server create a JWT using an HMAC SHA algorithm, such as HMAC SHA-256.
    The HMAC (Hash-based Message Authentication Code) is calculated using the
    bytes of the UTF-8 representation of the client_secret as the shared key.
    """

    tag = "client_assertion"
    attestation_class = None

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            http_info: Optional[dict] = None,
            **kwargs,
    ):
        oas = topmost_unit(self)["oauth_authorization_server"]
        _keyjar = oas.context.keyjar
        _wia = verify_wallet_instance_attestation(request["client_assertion"],
                                                  _keyjar,
                                                  self,
                                                  self.attestation_class)

        # Automatic registration
        _cinfo = {k: v for k, v in _wia.items() if k not in JsonWebToken.c_param.keys()}
        _client_id = _wia["sub"]
        _cinfo["client_id"] = _client_id

        # Add info from the request
        if "redirect_uri" in request:
            _cinfo["redirect_uris"] = [request["redirect_uri"]]
        if "response_type" in request:
            _cinfo["response_types"] = [" ".join(request["response_type"])]

        oas.context.cdb[_client_id] = _cinfo
        # register under both names
        if request["client_id"] != _client_id:
            oas.context.cdb[request["client_id"]] = _cinfo
        logger.debug(f"Storing the following client information about {_client_id}: {_cinfo}")

        # adding wallet key to keyjar
        _jwk = _wia["cnf"]["jwk"]
        _keyjar = import_jwks(_keyjar, {"keys": [_jwk]}, _jwk["kid"])
        _keyjar = import_jwks(_keyjar, {"keys": [_jwk]}, _wia["sub"])

        return {"client_id": _wia["sub"], "jwt": _wia}

    def is_usable(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            http_info: Optional[dict] = None
    ):
        ca_type = request.get("client_assertion_type")
        if ca_type == ASSERTION_TYPE:
            if "client_assertion" in request:
                return True

        return False


# AttestationJWTClientAuthentication
class ClientAuthenticationAttestation(ClientAuthnMethod):
    # based on https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-01.html
    tag = "attest_jwt_client_auth"
    assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"
    attestation_class = {"wallet-attestation+jwt": WalletInstanceAttestationJWT}
    metadata = {}

    def is_usable(self, request=None, authorization_token=None, http_info: Optional[dict] = 0):
        if request is None:
            return False

        _headers = http_info.get("headers", {})
        if "OAuth-Client-Attestation" in _headers and "OAuth-Client-Attestation-PoP" in _headers:
            return True

        return False

    def _verify(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
            endpoint=None,  # Optional[Endpoint]
            http_info: Optional[dict] = None,
            **kwargs,
    ):
        wia = http_info["headers"]["OAuth-Client-Attestation"]
        pop = http_info["headers"]["OAuth-Client-Attestation-PoP"]

        logger.debug(f"OAuth-Client-Attestation: {wia}")
        logger.debug(f"OAuth-Client-Attestation-PoP: {pop}")

        oas = topmost_unit(self)['oauth_authorization_server']
        _keyjar = oas.context.keyjar
        _wia = verify_wallet_instance_attestation(wia,
                                                  _keyjar,
                                                  self,
                                                  self.attestation_class)

        logger.debug(f"Verified WIA")
        # Should be a key in there
        _jwk = _wia["cnf"]["jwk"]
        _keyjar = import_jwks(_keyjar, {"keys": [_jwk]}, _wia["sub"])
        if _wia["cnf"]["jwk"]["kid"] != _wia["sub"]:
            _keyjar = import_jwks(_keyjar, {"keys": [_jwk]}, _wia["cnf"]["jwk"]["kid"])

        # have already saved the key that comes in the wia
        _verifier = JWT(_keyjar)

        logger.debug("Verifying the PoP")
        try:
            _pop = _verifier.unpack(pop)
        except (Invalid, MissingKey, BadSignature, IssuerNotFound) as err:
            logger.exception("unpacking PoP")
            raise ClientAuthenticationError(f"{err.__class__.__name__} {err}")
        except Exception as err:
            logger.exception("unpacking PoP")
            raise err

        if isinstance(_pop, Message):
            _pop.verify()

        # Dynamically add/register client
        _c_info = {"client_id": _wia["sub"]}
        # Add metadata from the WIE/WIA
        for key, val in self.metadata.items():
            _val = _wia.get(key, None)
            if _val:
                _c_info[key] = _val

        oas.context.cdb[_wia["sub"]] = _c_info

        # Synchronize with other guise
        oci = topmost_unit(self)['openid_credential_issuer']
        oci.context.keyjar = oas.context.keyjar
        oci.context.cdb = oas.context.cdb

        return {"client_id": _wia["sub"], "jwt": _wia}
