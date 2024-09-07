__author__ = "Roland Hedberg"
__version__ = "0.3.0"

from typing import Any
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.utils import importer
from fedservice.message import ProviderConfigurationResponse
from fedservice.server import ServerUnit
from idpyoidc.configure import Base
from idpyoidc.message import Message
from idpyoidc.node import topmost_unit
from idpyoidc.server import ASConfiguration
from idpyoidc.server import authz
from idpyoidc.server import build_endpoints
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server.claims.oauth2 import Claims as OAUTH2_Claims
from idpyoidc.server.client_authn import client_auth_setup
from idpyoidc.server.endpoint_context import init_service
from idpyoidc.server.user_authn.authn_context import populate_authn_broker

from openid4v.message import AuthorizationServerMetadata
from openid4v.message import OpenidCredentialIssuer

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"

GUISE_MAP = {
    'oauth_authorization_server': AuthorizationServerMetadata,
    'openid_credential_issuer': OpenidCredentialIssuer,
    'openid_provider': ProviderConfigurationResponse
}


def do_endpoints(conf, upstream_get):
    _endpoints = conf.get("endpoint")
    if _endpoints:
        return build_endpoints(_endpoints, upstream_get=upstream_get, issuer=conf["issuer"])
    else:
        return {}


class ServerEntity(ServerUnit):
    name = 'noname'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}
    claims_class = OAUTH2_Claims

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
            key_conf: Optional[dict] = None,
            entity_type: Optional[str] = "",
            metadata_schema: Optional[Union[str, Message]] = None
    ):
        if config is None:
            config = {}

        self.metadata_schema = ""
        if not metadata_schema:
            metadata_schema = config.get("metadata_schema", "")
            if metadata_schema:
                if isinstance(metadata_schema, str):
                    self.metadata_schema = importer(metadata_schema)
                else:
                    self.metadata_schema = metadata_schema

        ServerUnit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                            httpc_params=httpc_params, entity_id=entity_id, key_conf=key_conf,
                            config=config)

        if not isinstance(config, Base):
            if not entity_id:
                entity_id = config.get("entity_id", config.get("issuer"))
            config['issuer'] = entity_id
            config['base_url'] = entity_id
            config = ASConfiguration(config)

        self.config = config

        self.endpoint = do_endpoints(config, self.unit_get)
        server_type = config.get("server_type", config["conf"].get("server_type", ""))
        self.entity_type = entity_type

        self.context = EndpointContext(
            conf=config,
            upstream_get=self.unit_get,
            cwd=cwd,
            cookie_handler=cookie_handler,
            httpc=httpc,
            claims_class=self.claims_class(),
            server_type=server_type
        )

        self.context.claims_interface = init_service(
            config["claims_interface"], self.unit_get
        )

        self.context.do_add_on(endpoints=self.endpoint)

        if self.metadata_schema:
            _required = self.metadata_schema().required_parameters()
            for parameter in ['issuer', "credential_issuer"]:
                if parameter in _required:
                    self.context.set_preference(parameter, self.context.entity_id)

        self.context.provider_info = self.context.claims.get_server_metadata(
            endpoints=self.endpoint.values(),
            metadata_schema=self.metadata_schema,
        )
        self.context.metadata = self.context.provider_info


    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_context(self, *arg):
        return self.context

    def get_server(self, *args):
        return self

    def get_metadata(self, entity_type="", *args):
        if not entity_type:
            entity_type = self.name
        _claims = self.get_context().claims
        metadata = _claims.get_server_metadata(endpoints=self.endpoint.values(),
                                               metadata_schema=self.metadata_schema)
        # remove these from the metadata
        # for item in ["jwks", "jwks_uri", "signed_jwks_uri"]:
        #     try:
        #         del metadata[item]
        #     except KeyError:
        #         pass
        # collect endpoints
        return {entity_type: metadata}
    def get_guise(self):
        return self.name

    def pick_guise(self, entity_type: Optional[str] = "", *args):
        if not entity_type:
            entity_type = self.name

        return topmost_unit(self).get(entity_type, None)

    def setup_authz(self):
        authz_spec = self.config.get("authz")
        if authz_spec:
            return init_service(authz_spec, self.unit_get)
        else:
            return authz.Implicit(self.unit_get)

    def setup_authentication(self, target):
        _conf = self.config.get("authentication")
        if _conf:
            target.authn_broker = populate_authn_broker(
                _conf, self.unit_get, target.template_handler
            )
        else:
            target.authn_broker = {}

        target.endpoint_to_authn_method = {}
        for method in target.authn_broker:
            try:
                target.endpoint_to_authn_method[method.action] = method
            except AttributeError:
                pass

    def setup_client_authn_methods(self):
        self.context.client_authn_methods = client_auth_setup(
            self.unit_get, self.config.get("client_authn_methods")
        )
