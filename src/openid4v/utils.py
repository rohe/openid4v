import hashlib
import json

from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory
from cryptojwt.utils import as_bytes


def extract_key_from_jws(token):
    # key can be in cnf:jwk in payload or jwk in header
    _jws = factory(token)
    _jwk = _jws.jwt.headers.get("jwk", None)
    if _jwk is None:
        _payload = _jws.jwt.payload()
        _jwk = _payload['cnf'].get('jwk', None)
    if _jwk:
        return key_from_jwk_dict(_jwk)
    else:
        return None


def jws_issuer(token):
    _jws = factory(token)
    return _jws.jwt.payload()["iss"]


def create_client_data_hash(challenge: str, ephemeral_key_tag: str):
    client_data = {
        "challenge": challenge,
        "jwk_thumbprint": ephemeral_key_tag
    }

    return hashlib.sha256(as_bytes(json.dumps(client_data))).digest()
