#!/usr/bin/env python3

import json

from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from fedservice.utils import make_federation_combo
from idpyoidc.util import rndstr


WALLET_PROVIDER_ID = "https://127.0.0.1:4000"
TRUST_ANCHORS = json.loads(open("trust_anchors.json", "r").read())

entity = make_federation_combo(
    "entity_id",
    httpc_params={"verify": False},
    key_config={
        "key_defs": [
            {"type": "RSA", "use": ["sig"]},
            {"type": "EC", "crv": "P-256", "use": ["sig"]},
        ]
    },
    trust_anchors=TRUST_ANCHORS,
    entity_type={
        "wallet": {
            'class': "idpyoidc.client.oauth2.Client",
            'kwargs': {
                'config': {
                    # "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                    "services": {
                        "wallet_instance_attestation": {
                            "class":
                                "openid4v.client.wallet_instance_attestation.WalletInstanceAttestation",
                            "kwargs": {
                                "wallet_provider_id": WALLET_PROVIDER_ID
                            }
                        }
                    }
                }
            }
        },
        "pid_eaa_consumer": {
            'class': "openid4v.client.pid_eaa_consumer.PidEaaHandler",
            'kwargs': {
                'config': {
                    # "base_url": "",
                    # "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                    "add_ons": {
                        "pkce": {
                            "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                            "kwargs": {"code_challenge_length": 64,
                                       "code_challenge_method": "S256"},
                        },
                        "dpop": {
                            "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
                            "kwargs": {
                                'dpop_signing_alg_values_supported': ["ES256"]
                            }
                        },
                        # "pushed_authorization": {
                        #     "function": "idpyoidc.client.oauth2.add_on.par.add_support",
                        #     "kwargs": {
                        #         "body_format": "jws",
                        #         "signing_algorithm": "RS256",
                        #         "http_client": None,
                        #         "merge_rule": "lax",
                        #     },
                        # }
                    },
                    "preference": {
                        "client_authn_methods": ["private_key_jwt"],
                        "response_types_supported": ["code"],
                        "response_modes_supported": ["query", "form_post"],
                        "request_parameter_supported": True,
                        "request_uri_parameter_supported": True,
                        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                        "token_endpoint_auth_signing_alg_values_supported": ["ES256"]
                    },
                    "services": {
                        "pid_eaa_authorization": {
                            "class": "openid4v.client.pid_eaa.Authorization",
                            "kwargs": {
                                "client_authn_methods": {
                                    "client_assertion": "openid4v.client.client_authn.ClientAssertion"
                                }
                            },
                        },
                        "pid_eaa_token": {
                            "class": "openid4v.client.pid_eaa.AccessToken",
                            "kwargs": {}
                        },
                        "credential": {
                            "path": "credential",
                            "class": 'openid4v.client.pid_eaa.Credential',
                            "kwargs": {}
                        }
                    }
                }
            }
        }
    }
)

federation_entity = entity["federation_entity"]
wallet_entity = entity["wallet"]

print(30 * "=" + f" Collecting Trust Chain for {WALLET_PROVIDER_ID} " + 30 * "=")
_chain = federation_entity.get_trust_chain(WALLET_PROVIDER_ID)
trust_chain = federation_entity.trust_chain[WALLET_PROVIDER_ID][0]

print(f"Trust Chain Path: {trust_chain.iss_path}")

print(">>> Getting the token endpoint from the metadata")
print(f"token_endpoint={trust_chain.metadata['wallet_provider']['token_endpoint']}")
federation_entity.trust_chain[WALLET_PROVIDER_ID] = trust_chain

print(">>> Constructing the Wallet Instance Attestation Request")
_service = wallet_entity.get_service("wallet_instance_attestation")
request_args = {"nonce": rndstr(), "aud": WALLET_PROVIDER_ID}
req_info = _service.get_request_parameters(request_args,
                                           endpoint=trust_chain.metadata['wallet_provider'][
                                               'token_endpoint'])
print(f"request_info: {req_info}")
resp = wallet_entity.do_request("wallet_instance_attestation", request_args=request_args,
                                endpoint=trust_chain.metadata['wallet_provider']['token_endpoint'])
print(f"Wallet Instance Attestation: {resp}")

# Search for all credential issuers
print("**** Find one Credential Issuer that issues credentials of type {"
      "credential_type} ****")
res = []
ta_id = list(TRUST_ANCHORS.keys())[0]
list_resp = federation_entity.do_request('list', entity_id=ta_id)
print(f"Subordinates to TA: {list_resp}")
for entity_id in list_resp:
    res.extend(federation_entity.trawl(ta_id, entity_id, entity_type="openid_credential_issuer"))

print(f"Credential Issuers: {res}")

_oci = {}
credential_type = "PersonIdentificationData"
for pid in res:
    oci_metadata = federation_entity.get_verified_metadata(pid)
    # logger.info(json.dumps(oci_metadata, sort_keys=True, indent=4))
    for cs in oci_metadata['openid_credential_issuer']["credentials_supported"]:
        if credential_type in cs["credential_definition"]["type"]:
            _oci[pid] = oci_metadata
            break

print(f"{_oci}")

for eid, metadata in _oci.items():
    _trust_chain = federation_entity.get_trust_chain(eid)
    _ec = _trust_chain.verified_chain[-1]
    if "trust_marks" in _ec:
        for _mark in _ec["trust_marks"]:
            _jws = factory(_mark)
            issuer = _jws.jwt.payload()["iss"]
            _chains = federation_entity.get_trust_chain(issuer)
            federation_entity.keyjar.import_jwks(_chains[0].verified_chain[-1]["jwks"], issuer)
            verifier = JWT(key_jar=federation_entity.keyjar)
            _mark_payload = verifier.unpack(_mark)
