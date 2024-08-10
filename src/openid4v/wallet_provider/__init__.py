from typing import Any
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from idpyoidc.message import Message
from idpyoidc.metadata import get_signing_algs
from idpyoidc.server import ASConfiguration
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server.claims import Claims
from idpyoidc.server.util import execute

from openid4v import ServerEntity
from openid4v import message


class WalletProviderClaims(Claims):
    _supports = {
        "attested_security_context_values_supported": [],
        "grant_types_supported": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
        "response_types_supported": ["vp_token"],
        "vp_formats_supported": {
            "jwt_vp_json": {
                "alg_values_supported": get_signing_algs
            },
            "jwt_vc_json": {
                "alg_values_supported": get_signing_algs
            }
        },
        "request_object_signing_alg_values_supported": get_signing_algs,
        "presentation_definition_uri_supported": False
    }

    def provider_info(self, supports: dict, schema: Optional[Message] = None):
        _info = {}
        if schema is None:
            schema = message.WalletProvider

        for key in schema.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val not in [None, []]:
                _info[key] = _val

        return _info


class TestWalletInstanceDiscovery(object):
    def __call__(self, *args, **kwargs) -> dict:
        return {
            #     "authorization_endpoint": "eudiw:",
            #     "response_types_supported": [
            #         "vp_token"
            #     ],
            #     "response_modes_supported": [
            #         "form_post.jwt"
            #     ],
            #     "vp_formats_supported": {
            #         "vc+sd-jwt": {
            #             "sd-jwt_alg_values": [
            #                 "ES256",
            #                 "ES384"
            #             ]
            #         }
            #     },
            #     "request_object_signing_alg_values_supported": [
            #         "ES256"
            #     ],
            #     "presentation_definition_uri_supported": False,
            "aal": "https://trust-list.eu/aal/high"}


class WalletProvider(ServerEntity):
    name = 'wallet_provider'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}
    claims_class = WalletProviderClaims

    def __init__(
            self,
            config: Optional[Union[dict, ASConfiguration]] = None,
            upstream_get: Optional[Callable] = None,
            keyjar: Optional[KeyJar] = None,
            cwd: Optional[str] = "",
            cookie_handler: Optional[Any] = None,
            httpc: Optional[Any] = None,
            httpc_params: Optional[dict] = None,
            entity_id: Optional[str] = "",
            key_conf: Optional[dict] = None
    ):
        ServerEntity.__init__(self, config=config, upstream_get=upstream_get, keyjar=keyjar,
                              cwd=cwd, cookie_handler=cookie_handler, httpc=httpc,
                              httpc_params=httpc_params, entity_id=entity_id, key_conf=key_conf)

        self.wallet_instance_discovery = execute(
            config.get("wallet_instance_discovery",
                       {
                           "class": TestWalletInstanceDiscovery,
                           "kwargs": {}
                       }))

        if config and "wallet_db" in config:
            self.context.wallet_db = execute(config["registration_service"])
        else:
            self.context.wallet_db = {}

        self.context.crypto_hardware_key = {}

    def get_metadata(self, *args):
        # static ! Should this be done dynamically ?
        _metadata = self.context.provider_info
        if "jwks" not in _metadata:
            _metadata["jwks"] = self.context.keyjar.export_jwks()

        return {self.name: _metadata}
