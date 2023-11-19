from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from idpyoidc.client.oauth2 import Client
from idpyoidc.configure import Configuration
from idpyoidc.context import OidcContext


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
