# wallet_instance_attestation_request
from cryptojwt import JWT
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.util import rndstr

from oidc4vc.message import WalletInstanceRequest

JWT_ISSUER = "s6BhdRkqt3"
WALLET_PROVIDER_ID = "https://wallet-provider.example.org"

KEYJAR = build_keyjar(DEFAULT_KEY_DEFS)
KEYJAR.import_jwks(KEYJAR.export_jwks(private=True), JWT_ISSUER)

# ----------------- Wallet does Wallet Instance Attestation Request -----------------
# create new key pair
ec_key = new_ec_key(crv="P-256", key_ops=["sign"])
KEYJAR.add_keys(issuer_id=JWT_ISSUER, keys=[ec_key])
thumb_print = ec_key.thumbprint("SHA-256")

_jwt = JWT(key_jar=KEYJAR, sign_alg='ES256', iss=JWT_ISSUER)
_jwt.with_jti = True

payload = {
    "type": "WalletInstanceAttestationRequest",
    "nonce": rndstr(),  # create nonce
    "cnf": {
        "jwk": ec_key.serialize()
    }
}

_jws = _jwt.pack(payload,
                 aud=WALLET_PROVIDER_ID,
                 kid=ec_key.kid,
                 issuer_id=JWT_ISSUER,
                 jws_headers={"typ": "var+jwt"}
                 )

_wiar = factory(_jws)
_wiar_payload = _wiar.jwt.payload()


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
WP_KEYJAR.import_jwks(KEYJAR.export_jwks(private=True), JWT_ISSUER)

_jwt = JWT(key_jar=KEYJAR, allowed_sign_algs=['ES256'])
# _jwt.msg_cls = WalletInstanceRequest
_jwt.typ2msg_cls = {
    "var+jwt": WalletInstanceRequest
}
_msg = _jwt.unpack(_jws)
assert isinstance(_msg, WalletInstanceRequest)

# -------------- Wallet provider creates a Wallet Instance Attestation ------------------

WP_KEYJAR = build_keyjar(DEFAULT_KEY_DEFS)
WP_KEYJAR.import_jwks(WP_KEYJAR.export_jwks(private=True), WALLET_PROVIDER_ID)

_jwt = JWT(key_jar=KEYJAR, sign_alg='ES256', iss=WALLET_PROVIDER_ID)
_jwt.with_jti = True

#         "alg": "ES256",
#         "kid": "5t5YYpBhN-EgIEEI5iUzr6r0MR02LnVQ0OmekmNKcjY",
#         "trust_chain": [
#             "eyJhbGciOiJFUz...6S0A",
#             "eyJhbGciOiJFUz...jJLA",
#             "eyJhbGciOiJFUz...H9gw",
#         ],
#         "typ": "wallet-attestation+jwt",
#         "x5c": ["MIIBjDCC ... XFehgKQA=="]
#     }
#
# payload = {
#     "type": "WalletInstanceAttestationRequest",
#     "nonce": rndstr(),  # create nonce
#     "cnf": {
#         "jwk": ec_key.serialize()
#     }
# }

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
}

_jws = _jwt.pack(payload,
                 aud=WALLET_PROVIDER_ID,
                 kid=ec_key.kid,
                 issuer_id=JWT_ISSUER,
                 jws_headers={
                     "typ": "wallet-attestation+jwt",
                     "trust_chain": [
                         "eyJhbGciOiJFUz...6S0A",
                         "eyJhbGciOiJFUz...jJLA",
                         "eyJhbGciOiJFUz...H9gw",
                     ]
                 })
_wia = factory(_jws)
_wia_payload = _wia.jwt.payload()
print(_wia_payload)

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
#{
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