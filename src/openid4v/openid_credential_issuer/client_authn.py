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
from idpyoidc.message import Message
from idpyoidc.message.oidc import JsonWebToken
from idpyoidc.node import topmost_unit
from idpyoidc.server.client_authn import ClientAuthnMethod
from idpyoidc.server.exception import ClientAuthenticationError

from openid4v import ASSERTION_TYPE
from openid4v.message import WalletInstanceAttestationJWT


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
            **kwargs,
    ):
        _keyjar = self.upstream_get("attribute", "keyjar")
        _jws = factory(request["client_assertion"])
        _payload = _jws.jwt.payload()
        if _payload["iss"] not in _keyjar:
            if "trust_chain" in _jws.jwt.headers:
                _tc = verify_trust_chains(self, [_jws.jwt.headers["trust_chain"]])
                if _tc:
                    _entity_conf = _tc[0].verified_chain[-1]
                    _keyjar.import_jwks(_entity_conf["metadata"]["wallet_provider"]["jwks"],
                                        _entity_conf["sub"])
            else:
                chains = get_verified_trust_chains(self, _payload["iss"])
                if chains:
                    _entity_conf = chains[0].verified_chain[-1]
                    _keyjar.import_jwks(_entity_conf["metadata"]["wallet_provider"]["jwks"],
                                        _entity_conf["sub"])

        _verifier = JWT(_keyjar)
        if self.attestation_class:
            _verifier.typ2msg_cls = self.attestation_class

        try:
            _wia = _verifier.unpack(request["client_assertion"])
        except (Invalid, MissingKey, BadSignature, IssuerNotFound) as err:
            # logger.info("%s" % sanitize(err))
            raise ClientAuthenticationError(f"{err.__class__.__name__} {err}")
        except Exception as err:
            raise err

        if isinstance(_wia, Message):
            _wia.verify()

        # Automatic registration
        root = topmost_unit(self)
        oci = root["openid_credential_issuer"]  # Should not be static
        _cinfo = {k: v for k, v in _wia.items() if k not in JsonWebToken.c_param.keys()}
        _cinfo["client_id"] = _wia["sub"]
        oci.context.cdb[_wia["sub"]] = _cinfo
        # register under both names
        _cinfo["client_id"] = request["client_id"]
        oci.context.cdb[request["client_id"]] = _cinfo

        # adding wallet key to keyjar
        _keyjar.import_jwks({"keys": [_wia["cnf"]["jwk"]]}, _wia["sub"])

        return {"client_id": _wia["sub"], "jwt": _wia}

    def is_usable(
            self,
            request: Optional[Union[dict, Message]] = None,
            authorization_token: Optional[str] = None,
    ):
        ca_type = request.get("client_assertion_type")
        if ca_type == ASSERTION_TYPE:
            if "client_assertion" in request:
                return True

        return False


class WalletInstanceAttestation(ClientAssertion):
    attestation_class = {"wallet-attestation+jwt": WalletInstanceAttestationJWT}
