import logging

from idpyoidc.client.service import Service
from idpyoidc.message import oidc

from oidc4vci.message import CredentialRequest
from oidc4vci.message import CredentialResponse

logger = logging.getLogger(__name__)


class Credential(Service):
    msg_type = CredentialRequest
    response_cls = CredentialResponse
    error_msg = oidc.ResponseMessage
    endpoint_name = "credential_endpoint"
    service_name = "credential"
    default_authn_method = "bearer_header"
    response_body_type = "jose"
