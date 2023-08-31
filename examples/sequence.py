# wallet_instance_attestation_request
from cryptojwt import JWT
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import build_keyjar
from fedservice.build_entity import FederationEntityBuilder
from fedservice.entity import FederationEntity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.util import rndstr

from examples import create_trust_chain
from federation import federation_setup
from oidc4vci.message import WalletInstanceAttestation
from oidc4vci.message import WalletInstanceRequest

federation_entity = federation_setup()

# Build the federation

WALLET_ID = "s6BhdRkqt3"
WALLET_PROVIDER_ID = "https://wallet-provider.example.org"

WALLET_FE = FederationEntityBuilder(
    WALLET_ID,
    key_conf={"key_defs": DEFAULT_KEY_DEFS}
)
WALLET_FE.add_functions()

wallet_fed = FederationEntity(**WALLET_FE.conf)

wallet_fed.keyjar.import_jwks(wallet_fed.keyjar.export_jwks(private=True), WALLET_ID)

# Gotten from the Wallet Provider in some undefined way
NONCE = rndstr()

# ----------------- Wallet does Wallet Instance Attestation Request -----------------
# create new key pair
ec_key = new_ec_key(crv="P-256", key_ops=["sign"])
wallet_fed.keyjar.add_keys(issuer_id=WALLET_ID, keys=[ec_key])
thumb_print = ec_key.thumbprint("SHA-256")

_jwt = JWT(key_jar=wallet_fed.keyjar, sign_alg='ES256', iss=WALLET_ID)
_jwt.with_jti = True

payload = {
    "type": "WalletInstanceAttestationRequest",
    "nonce": NONCE,
    "cnf": {
        "jwk": ec_key.serialize()
    }
}

_jws = _jwt.pack(payload,
                 aud=WALLET_PROVIDER_ID,
                 kid=ec_key.kid,
                 issuer_id=WALLET_ID,
                 jws_headers={"typ": "var+jwt"}
                 )

_wiar = factory(_jws)
_wiar_payload = _wiar.jwt.payload()

# Payload should look something like this:
#
# payload = {
#     "iss": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
#     "aud": "https://wallet-provider.example.org",
#     "jti": "6ec69324-60a8-4e5b-a697-a766d85790ea",
#     "type": "WalletInstanceAttestationRequest",
#     "nonce": ".....",
#     "cnf": {
#         "jwk": {
#             "crv": "P-256",
#             "kty": "EC",
#             "x": "4HNptI-xr2pjyRJKGMnz4WmdnQD_uJSq4R95Nj98b44",
#             "y": "LIZnSB39vFJhYgS3k7jXE4r3-CoGFQwZtPBIRqpNlrg",
#             "kid": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c"
#         }
#     },
#     "iat": 1686645115,
#     "exp": 1686652315
# }
# parsed by the Wallet Provider

WP_KEYJAR = build_keyjar(DEFAULT_KEY_DEFS)
WP_KEYJAR.import_jwks(WP_KEYJAR.export_jwks(private=True), WALLET_PROVIDER_ID)
WP_KEYJAR.import_jwks(wallet_fed.keyjar.export_jwks(private=True, issuer_id=WALLET_ID), WALLET_ID)

_jwt = JWT(key_jar=WP_KEYJAR, allowed_sign_algs=['ES256'])
# _jwt.msg_cls = WalletInstanceRequest
# if the 'typ' parameter in the JWT header matches one of the keys in this then
# the payload is mapped into the corresponding class
_jwt.typ2msg_cls = {
    "var+jwt": WalletInstanceRequest
}

_msg = _jwt.unpack(_jws)
assert isinstance(_msg, WalletInstanceRequest)
_msg.verify()

# -------------- Wallet provider creates a Wallet Instance Attestation ------------------

_jwt = JWT(key_jar=WP_KEYJAR, sign_alg='ES256', iss=WALLET_PROVIDER_ID)
_jwt.with_jti = True

payload = {
    "sub": _wiar_payload["iss"],
    "policy_uri": "https://wallet-provider.example.org/privacy_policy",
    "tos_uri": "https://wallet-provider.example.org/info_policy",
    "logo_uri": "https://wallet-provider.example.org/logo.svg",
    "attested_security_context": "https://wallet-provider.example.org/LoA/basic",
    "type": "WalletInstanceAttestation",
    "cnf": _wiar_payload["cnf"],
    "authorization_endpoint": "eudiw:",
    "response_types_supported": [
        "vp_token"
    ],
    "vp_formats_supported": {
        "jwt_vp_json": {
            "alg_values_supported": ["ES256"]
        },
        "jwt_vc_json": {
            "alg_values_supported": ["ES256"]
        }
    },
    "request_object_signing_alg_values_supported": [
        "ES256"
    ],
    "presentation_definition_uri_supported": False,
    "iat": utc_time_sans_frac(),
    "exp": utc_time_sans_frac() + 300  # Valid for 5 minutes
}

trust_chain = create_trust_chain(federation_entity["wp"],
                                 federation_entity["im2"],
                                 federation_entity["ta"])

_wallet_instance_assertion = _jwt.pack(payload,
                                       aud=WALLET_ID,
                                       issuer_id=WALLET_PROVIDER_ID,
                                       jws_headers={
                                           "typ": "wallet-attestation+jwt",
                                           "trust_chain": trust_chain
                                       })

# Wallet parsing Wallet Instance Attestation
# Need wallet provider's public keys in my key jar
wallet_fed.keyjar.import_jwks(WP_KEYJAR.export_jwks(issuer_id=WALLET_PROVIDER_ID),
                              WALLET_PROVIDER_ID)

_verifier = JWT(key_jar=wallet_fed.keyjar, allowed_sign_algs=['ES256'])
# _jwt.msg_cls = WalletInstanceRequest
# if the 'typ' parameter in the JWT header matches one of the keys in this then
# the payload is mapped into the corresponding class
_verifier.typ2msg_cls = {
    "wallet-attestation+jwt": WalletInstanceAttestation
}

_msg = _verifier.unpack(_wallet_instance_assertion)
assert isinstance(_msg, WalletInstanceAttestation)
_msg.verify()

# Collect Trust Chain if necessary, calculate metadata

if "trust_chain" in _msg.jws_header:
    ess = _msg.jws_header["trust_chain"][:]
    ess.reverse()
    trust_chain = wallet_fed.function.verifier(ess)
    if not trust_chain:
        raise ValueError("Trust chain didn't validate")
    wallet_fed.function.policy(trust_chain)

# ------------------------ Wallet search for PID Provider -------------------------------

# GET /list?entity_type=pid_provider

# Collect trust chain, calculate metadata

# create new EC key pair
keyjar = build_keyjar([{"type": "EC", "crv": "P-256", "use": ["sig"]}])

# Authz query

# response_type=code
# &client_id=$thumprint-of-the-jwk-in-the-cnf-wallet-attestation$
# &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
# &code_challenge_method=S256
# &request=eyJhbGciOiJSUzI1NiIsImtpZCI6ImsyYmRjIn0.ew0KIC Jpc3MiOiAiczZCaGRSa3F0MyIsDQogImF1ZCI6ICJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsDQo gInJlc3BvbnNlX3R5cGUiOiAiY29kZSBpZF90b2tlbiIsDQogImNsaWVudF9pZCI6ICJzNkJoZFJrcXQz IiwNCiAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vY2xpZW50LmV4YW1...
# &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-key-attestation
# &client_assertion=$WalletInstanceAttestation$

# request
# {
# "response_type":"code",
# "client_id":"$thumprint-of-the-jwk-in-the-cnf-wallet-attestation$",
# "state":"fyZiOL9Lf2CeKuNT2JzxiLRDink0uPcd",
# "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
# "code_challenge_method":"S256",
# "authorization_details":[
# {
#     "type":"openid_credential",
#     "format": "vc+sd-jwt",
#     "credential_definition": {
#         "type": ["PersonIdentificationData"]
#     }
# }
# ],
# "redirect_uri":"eudiw://start.wallet.example.org",
# "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-key-attestation",
# }
