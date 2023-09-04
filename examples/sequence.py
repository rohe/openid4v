# wallet_instance_attestation_request
from cryptojwt import JWT
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.key_jar import build_keyjar
from fedservice.build_entity import FederationEntityBuilder
from fedservice.entity import FederationEntity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.util import rndstr

from examples import create_trust_chain
from federation import federation_setup
from oidc4vci.message import WalletInstanceAttestationJWT

# Build the federation
federation_entity = federation_setup()

# Building the things that emulate a wallet

WALLET_ID = "s6BhdRkqt3"
WALLET_PROVIDER_ID = "https://wallet-provider.example.org"

WALLET_FE = FederationEntityBuilder(
    WALLET_ID,
    key_conf={"key_defs": DEFAULT_KEY_DEFS}
)
WALLET_FE.add_functions()

fed_wallet = FederationEntity(**WALLET_FE.conf)

fed_wallet.keyjar.import_jwks(fed_wallet.keyjar.export_jwks(private=True), WALLET_ID)

# ============== SEQUENCE START =======================

# Gotten from the Wallet Provider in some undefined way
NONCE = rndstr()

# ----------------- Wallet does a Wallet Instance Attestation Request -----------------
# create new key pair
ec_key = new_ec_key(crv="P-256", key_ops=["sign"])
# Store it in the key jar
fed_wallet.keyjar.add_keys(issuer_id=WALLET_ID, keys=[ec_key])
thumb_print = ec_key.thumbprint("SHA-256")

_signer = JWT(key_jar=fed_wallet.keyjar, sign_alg='ES256', iss=WALLET_ID)
_signer.with_jti = True

payload = {
    "type": "WalletInstanceAttestationRequest",
    "nonce": NONCE,
    "cnf": {
        "jwk": ec_key.serialize()
    }
}

_wallet_instance_attestation_request = _signer.pack(payload,
                                                    aud=WALLET_PROVIDER_ID,
                                                    kid=ec_key.kid,
                                                    issuer_id=WALLET_ID,
                                                    jws_headers={"typ": "var+jwt"}
                                                    )

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

# The WalletInstanceAttestationRequest message

wiar_message = {
    "grant_type": "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
    "assertion": _wallet_instance_attestation_request
}

# --------------------------------------------
# parsed by the Wallet Provider
# --------------------------------------------

wallet_provider = federation_entity["wp"]
token_endpoint = wallet_provider["wallet_provider"].get_endpoint("token")
_req = token_endpoint.parse_request(request=wiar_message)

# ---------- Wallet provider creates response with a Wallet Instance Attestation --------------

# Build a trust chain that goes from the wallet provider to the TA
trust_chain = create_trust_chain(federation_entity["wp"],
                                 federation_entity["im2"],
                                 federation_entity["ta"])

_response = token_endpoint.process_request(request=_req, trust_chain=trust_chain)

# ========= Back in the Wallet ==========

# Wallet parsing Wallet Instance Attestation
# Need wallet provider's public keys in my key jar
fed_wallet.keyjar.import_jwks(
    wallet_provider["wallet_provider"].context.keyjar.export_jwks(
        issuer_id=wallet_provider.entity_id),
    wallet_provider.entity_id)

_verifier = JWT(key_jar=fed_wallet.keyjar, allowed_sign_algs=['ES256'])
# _jwt.msg_cls = WalletInstanceRequest
# if the 'typ' parameter in the JWT header matches one of the keys in this then
# the payload is mapped into the corresponding class
_verifier.typ2msg_cls = {
    "wallet-attestation+jwt": WalletInstanceAttestationJWT
}

_msg = _verifier.unpack(_response["response_args"]["attestation"])
assert isinstance(_msg, WalletInstanceAttestationJWT)
_msg.verify()

# Collect Trust Chain if necessary, calculate metadata

if "trust_chain" in _msg.jws_header:
    ess = _msg.jws_header["trust_chain"][:]
    ess.reverse()
    trust_chain = fed_wallet.function.verifier(ess)
    if not trust_chain:
        raise ValueError("Trust chain didn't validate")
    fed_wallet.function.policy(trust_chain)

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
# &request=eyJhbGciOiJSUzI1NiIsImtpZCI6ImsyYmRjIn0.ew0KIC
# Jpc3MiOiAiczZCaGRSa3F0MyIsDQogImF1ZCI6ICJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsDQo
# gInJlc3BvbnNlX3R5cGUiOiAiY29kZSBpZF90b2tlbiIsDQogImNsaWVudF9pZCI6ICJzNkJoZFJrcXQz
# IiwNCiAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vY2xpZW50LmV4YW1...
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
