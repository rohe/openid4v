import base64
import logging
from typing import Optional
from typing import Union

from cryptojwt import as_unicode
from cryptojwt import JWT
from cryptojwt.utils import as_bytes
from idpyoidc.message import Message
from idpyoidc.node import topmost_unit
from idpyoidc.server import Endpoint
from idpyoidc.server.util import execute

from openid4v.message import RegistrationRequest
from openid4v.wallet_provider.token import InvalidNonce

logger = logging.getLogger(__name__)


class Validation(object):

    def __init__(self, upstream_get):
        self.upstream_get = upstream_get

    def __call__(self, *args, **kwargs):
        # get the oem key
        dsi = topmost_unit(self)["device_integrity_service"]
        _jwt = JWT(dsi.oem_keyjar)
        try:
            _val = _jwt.unpack(as_unicode(base64.b64decode(as_bytes(args[0]))))
            return True
        except Exception as err:
            return False


class DeviceVerification(object):

    def __init__(self, upstream_get):
        self.upstream_get = upstream_get

    def __call__(self, *args, **kwargs):
        return True


class RegistrationService(object):

    def __init__(self, upstream_get, conf: Optional[dict] = None):
        self.upstream_get = upstream_get

        if conf and "challenge_service" in conf:
            self.key_assertion_validation = execute(conf["key_assertion_validation"], upstream_get=upstream_get)
        else:
            self.key_assertion_validation = Validation(upstream_get=upstream_get)

        if conf and "device_verification" in conf:
            self.device_verification = execute(conf["device_verification"], upstream_get=upstream_get)
        else:
            self.device_verification = DeviceVerification(upstream_get=upstream_get)

    def __call__(self, challenge, key_attestation, hardware_key_tag, **kwargs) -> Optional[dict]:
        # Verify the challenge
        _wallet_provider = self.upstream_get("unit")
        challenge_endpoint = _wallet_provider.get_endpoint("challenge")
        try:
            challenge_endpoint.challenge_service.verify_nonce(challenge)
        except InvalidNonce as err:
            return {"error": "xyz", "error_description": f"Invalid Nonce {err}"}

        # Validate the key attestation

        if not self.key_assertion_validation(key_attestation):
            return {"error": "xyz", "error_description": "Could not validate key assertion"}

        # Verify the device

        if not self.device_verification():
            return {"error": "xyz", "error_description": "Could not verify device"}

        # register the wallet
        # associate to user ? How ?

        _wallet_info = {
            "device_type": "local",
            "user_id": "me"
        }
        _wallet_provider.context.wallet_db.update({hardware_key_tag: _wallet_info})

        return


class Registration(Endpoint):
    request_cls = RegistrationRequest
    response_cls = Message
    request_format = "json"
    name = "registration"
    endpoint_type = "oauth2"
    endpoint_name = "wallet_provider_registration_endpoint"
    response_format = None

    def __init__(self, upstream_get, conf=None, **kwargs):
        Endpoint.__init__(self, upstream_get, conf=conf, **kwargs)
        if conf and "registration_service" in conf:
            self.registration_service = execute(conf["registration_service"])
        else:
            self.registration_service = RegistrationService(upstream_get=upstream_get)

    def process_request(self, request=None, **kwargs):
        _resp = self.registration_service(**request)
        if _resp:
            self.do_response(**_resp)
        else:
            return self.do_response(response_code=204)

    def do_response(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            error: Optional[str] = "",
            **kwargs
    ) -> dict:
        if error:
            return Endpoint.do_response(self, error=error)
        else:
            return {"response_code": kwargs.get("response_code")}
