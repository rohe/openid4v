from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.utils import importer
from idpyoidc.client.configure import Configuration
from idpyoidc.client.oauth2.add_on.dpop import dpop_header
from idpyoidc.client.oauth2.stand_alone_client import StandAloneClient
from idpyoidc.node import Unit
from requests import request


def build_instance(spec, upstream_get):
    kwargs = spec.get("kwargs", {})
    conf = kwargs.get("config", {})
    if conf == {}:
        conf = kwargs

    # class can be a string (class path) or a class reference
    if isinstance(spec["class"], str):
        _instance = importer(spec["class"])(upstream_get=upstream_get, **conf)
    else:
        _instance = spec["class"](upstream_get=upstream_get, **conf)
    return _instance


class PidEaaHandler(Unit):
    client_type = "oauth2"

    def __init__(
            self,
            config: Optional[Union[dict, Configuration]] = None,
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            key_conf: Optional[dict] = None,
            entity_id: Optional[str] = "",
            **kwargs
    ):
        """

        :type client_type: str
        :param client_type: What kind of client this is. Presently 'oauth2' or 'oidc'
        :param keyjar: A py:class:`idpyoidc.key_jar.KeyJar` instance
        :param config: Configuration information passed on to the
            :py:class:`idpyoidc.client.service_context.ServiceContext`
            initialization
        :param httpc: A HTTP client to use
        :param httpc_params: HTTP request arguments
        :param services: A list of service definitions
        :param jwks_uri: A jwks_uri
        :return: Client instance
        """

        self.entity_id = entity_id or config.get("entity_id")
        if not self.entity_id:
            self.entity_id = self.upstream_get("attribute", "entity_id")
        self.key_conf = key_conf
        self.config = config

        if httpc:
            self.httpc = httpc
        else:
            self.httpc = request

        self.httpc_params = httpc_params or config.get("httpc_params", {})
        self.kwargs = kwargs

        Unit.__init__(self,
                      httpc=self.httpc,
                      httpc_params=self.httpc_params,
                      key_conf=key_conf,
                      issuer_id=entity_id,
                      **kwargs)

        if "key_conf" in self.config:
            del self.config["key_conf"]

        self._consumer = {}

    def new_consumer(self, issuer_id):
        _consumer = StandAloneClient(
            config=self.config,
            httpc=self.httpc,
            httpc_params=self.httpc_params,
            upstream_get=self.unit_get,
            entity_id=self.entity_id
        )
        _consumer.context.issuer = issuer_id
        _consumer.context.issuer_metadata = {}
        _consumer.context.claims.prefer["client_id"] = _consumer.entity_id
        _federation_entity = self.upstream_get("unit")["federation_entity"]
        _entity_metadata = _federation_entity.get_verified_metadata(issuer_id)
        if _entity_metadata:
            _consumer.context.issuer_metadata = _entity_metadata
            _consumer.context.provider_info = _entity_metadata["openid_credential_issuer"]
        # Not doing any registration anyway
        _consumer.context.map_preferred_to_registered()
        if "dpop" in _consumer.context.add_on:
            _cred_srv = _consumer.get_service('credential')
            _cred_srv.construct_extra_headers.append(dpop_header)

        self._consumer[issuer_id] = _consumer
        return _consumer

    def get_consumer(self, issuer_id):
        return self._consumer.get(issuer_id, None)

    def issuers(self):
        return list(self._consumer.keys())
