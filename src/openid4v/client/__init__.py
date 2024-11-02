import base64
import json
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import as_unicode
from cryptojwt import KeyJar
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.dsa import ECDSASigner
from fedservice.entity.utils import get_federation_entity
from idpyoidc.client.oauth2 import Client
from idpyoidc.configure import Configuration
from idpyoidc.context import OidcContext
from idpyoidc.key_import import import_jwks

from openid4v.utils import create_client_data_hash


class Wallet(Client):

    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            services: Optional[dict] = None,
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            context: Optional[OidcContext] = None,
            upstream_get: Optional[Callable] = None,
            key_conf: Optional[dict] = None,
            entity_id: Optional[str] = "",
            verify_ssl: Optional[bool] = True,
            jwks_uri: Optional[str] = "",
            client_type: Optional[str] = "",
            **kwargs
    ):
        Client.__init__(self, keyjar=keyjar, config=config, services=services, httpc=httpc,
                        httpc_params=httpc_params, context=context, upstream_get=upstream_get,
                        key_conf=key_conf, entity_id=entity_id, verify_ssl=verify_ssl,
                        jwks_uri=jwks_uri, client_type=client_type, **kwargs)

        self.context.wallet_instance_attestation = {}
        self.context.wia_flow = {}
        self.context.init_reg = {}
        self.context.crypto_hardware_key = new_ec_key('P-256')
        self.context.ephemeral_key = {}

    def get_trust_chains(self, wallet_provider_id: str) -> Optional[list]:
        federation_entity = get_federation_entity(self)
        return federation_entity.get_trust_chains(wallet_provider_id)

    def mint_new_key(self):
        ephemeral_key = new_ec_key(crv="P-256")
        ephemeral_key.use = "sig"
        self.context.wia_flow[ephemeral_key.kid] = {}
        self.context.ephemeral_key[ephemeral_key.kid] = ephemeral_key

        _jwks = {"keys": [ephemeral_key.serialize(private=True)]}
        _keyjar = self.context.keyjar
        _keyjar = import_jwks(_keyjar, _jwks, self.context.entity_id)
        _keyjar = import_jwks(_keyjar, _jwks, "")

        return ephemeral_key

    def mint_ephemeral_key(self):
        return self.mint_new_key()

    def get_ephemeral_key(self, key_tag):
        return self.context.ephemeral_key[key_tag]

    def create_hardware_signature(self, challenge: str, ephemeral_key_tag: str) -> str:
        """

        :param challenge:
        :param ephemeral_key_tag:
        :return:
        """
        client_data_hash = create_client_data_hash(challenge, ephemeral_key_tag)
        # Step 8-10
        # signing the client_data_hash with the Wallet Hardware's private key
        _signer = ECDSASigner()
        _signature = _signer.sign(msg=client_data_hash,
                                  key=self.context.crypto_hardware_key.private_key())
        hardware_signature = as_unicode(base64.b64encode(_signature))
        # Store
        self.context.wia_flow[ephemeral_key_tag]["hardware_signature"] = hardware_signature
        return hardware_signature

    def request_challenge(self, wallet_provider_id) -> str:
        trust_chains = self.get_trust_chains(wallet_provider_id)

        _service = self.get_service("challenge")
        _service.wallet_provider_id = wallet_provider_id

        request_args = {}
        resp = self.do_request(
            "challenge",
            request_args=request_args,
            endpoint=trust_chains[0].metadata['wallet_provider']['wallet_provider_challenge_endpoint'])

        self.context.init_reg[resp["nonce"]] = {}
        return resp["nonce"]

    def request_key_attestation(self, wallet_provider_id: str, challenge: str) -> dict:
        # New hardware key. This must eventually change !!!!
        crypto_hardware_key_tag = as_unicode(self.context.crypto_hardware_key.kid)

        trust_chains = self.get_trust_chains(wallet_provider_id)

        # Key attestation request
        _service = self.get_service("key_attestation")
        _service.wallet_provider_id = wallet_provider_id

        request_args = {
            "challenge": challenge,
            # "crypto_hardware_key_tag": crypto_hardware_key_tag
            "crypto_hardware_key": json.dumps(self.context.crypto_hardware_key.serialize())
        }
        resp = self.do_request(
            "key_attestation",
            request_args=request_args,
            endpoint=trust_chains[0].metadata['device_integrity_service']['device_key_attestation_endpoint'])

        # Store result
        self.context.init_reg[challenge] = {
            "key_attestation": resp["key_attestation"],
            "crypto_hardware_key_tag": crypto_hardware_key_tag
        }

        return resp

    def request_registration(self, wallet_provider_id, challenge) -> dict:
        """

        :param wallet_provider_id:
        :return:
        """
        trust_chains = self.get_trust_chains(wallet_provider_id)

        # Registration request
        _service = self.get_service("key_attestation")
        _service.wallet_provider_id = wallet_provider_id

        _init_reg_info = self.context.init_reg[challenge]
        request_args = {
            "challenge": challenge,
            "key_attestation": as_unicode(_init_reg_info["key_attestation"]),
            "hardware_key_tag": _init_reg_info["crypto_hardware_key_tag"]
        }

        return self.do_request(
            "registration",
            request_args=request_args,
            endpoint=trust_chains[0].metadata['wallet_provider']['wallet_provider_registration_endpoint'])

    def request_integrity_assertion(self, wallet_provider_id, challenge):
        """

        :param wallet_provider_id:
        :param challenge:
        :return:
        """

        trust_chains = self.get_trust_chains(wallet_provider_id)

        # Step 3 generate an ephemeral key pair
        ephemeral_key = self.mint_new_key()
        self.context.wia_flow[ephemeral_key.kid]["ephemeral_key_tag"] = ephemeral_key.kid

        hardware_signature = self.create_hardware_signature(challenge, ephemeral_key.kid)
        request_args = {"hardware_signature": hardware_signature}

        resp = self.do_request(
            "integrity",
            request_args=request_args,
            endpoint=trust_chains[0].metadata['device_integrity_service']['device_integrity_endpoint'])

        self.context.wia_flow[ephemeral_key.kid]["integrity_assertion"] = resp["integrity_assertion"]

        return resp, ephemeral_key, hardware_signature

    def request_wallet_instance_attestation(self, wallet_provider_id, challenge, ephemeral_key_tag,
                                            integrity_assertion, hardware_signature,
                                            crypto_hardware_key_tag):
        trust_chains = self.get_trust_chains(wallet_provider_id)

        _service = self.get_service("wallet_instance_attestation")
        _service.wallet_provider_id = wallet_provider_id
        _wia_flow = self.context.wia_flow[ephemeral_key_tag]

        # get initialization and registration
        # if challenge != '__not__applicable__':
        #     _init_reg_info = self.context.init_reg[challenge]

        _ephemeral_key = self.context.ephemeral_key[ephemeral_key_tag]

        war_payload = {
            "challenge": challenge,
            "hardware_signature": hardware_signature,
            "integrity_assertion": integrity_assertion,
            "hardware_key_tag": crypto_hardware_key_tag,
            "cnf": {
                "jwk": _ephemeral_key.serialize()
            },
            "vp_formats_supported": {
                "jwt_vc_json": {
                    "alg_values_supported": ["ES256K", "ES384"],
                },
                "jwt_vp_json": {
                    "alg_values_supported": ["ES256K", "EdDSA"],
                },
            }
        }

        resp = self.do_request(
            'wallet_instance_attestation',
            request_args=war_payload,
            endpoint=trust_chains[0].metadata['wallet_provider']["token_endpoint"],
            ephemeral_key=_ephemeral_key
        )

        return resp, war_payload
