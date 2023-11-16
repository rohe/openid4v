from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory

from openid4v.client.client_authn import ClientAuthenticationAttestation


def test_construction():
    signing_key = new_ec_key(crv="P-256", key_ops=["sign"])
    attestation = ClientAuthenticationAttestation()(
        entity_id="https://example.com",
        signing_key=signing_key,
        audience="https://server.example.com",
        jwt_lifetime=3600,
        jwt_pop_lifetime=300,
        nonce="nonce"
    )

    assert "~" in attestation
    part = attestation.split("~")
    assert len(part) == 2
    _jws = factory(part[0])
    payload1 = _jws.verify_compact(part[0], keys=[signing_key])
    assert payload1
    assert set(payload1.keys()) == {"iss", "iat", "exp", "cnf", "sub"}

    _key = key_from_jwk_dict(payload1["cnf"]["jwk"])
    _jws = factory(part[1])
    payload2 = _jws.verify_compact(part[1], keys=[_key])
    assert payload2
    assert set(payload2.keys()) == {"aud", "nonce", "iss", "iat", "exp", "jti"}
