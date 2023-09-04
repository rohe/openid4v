import json
from json import JSONDecodeError
from typing import Optional
from typing import Union
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from idpyoidc.message import Message

from examples.federation import federation_setup

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
WP_ID = "https://wp.example.org"
IM1_ID = "https://im1.example.org"
IM2_ID = "https://im2.example.org"


def get_entity(federation_entity, entity_id):
    for tag, entity in federation_entity.items():
        if entity.entity_id == entity_id:
            return entity


SRV2FUNC_MAP = {
    "entity_configuration": "entity_configuration",
    "list": "list",
    "fetch": "entity_statement",
    "resolve": "resolve"
}


class Federation():
    def __init__(self):
        self.federation_entity = federation_setup()

    def request_response(self,
                         sender_id: str,
                         receiver_id: str,
                         service: str,
                         request_args: Optional[dict] = None,
                         **kwargs) -> Union[Message, dict]:
        sender = self.federation_entity[sender_id]
        _service = sender.get_service(SRV2FUNC_MAP[service])
        _service.upstream_get('unit').context.issuer = receiver_id

        if request_args is None:
            req_info = _service.get_request_parameters(**kwargs)
        else:
            req_info = _service.get_request_parameters(request_args, **kwargs)

        receiver = get_entity(self.federation_entity, receiver_id)
        endpoint = receiver.get_endpoint(service)
        if "url" in req_info:
            part = urlsplit(req_info["url"])
            if part.query:
                query = {}
                for key, val in parse_qs(part.query).items():
                    if len(val) == 1:
                        query[key] = val[0]
                    else:
                        query[key] = val
            else:
                query = None
            response = endpoint.process_request(query)
        else:
            if "request" in req_info:
                areq = req_info["request"]
                _args = endpoint.parse_request(areq)
            else:
                _args = req_info["request_args"]
            response = endpoint.process_request(_args)

        if "response_msg" in response:
            try:
                _resp = json.loads(response["response_msg"])
            except JSONDecodeError:
                _resp = _service.parse_response(response["response_msg"], sformat="jws")
        else:
            _resp = _service.parse_response(response["response"])
        return _resp

    def do_layer(self, origin_id, authority_id, subordinate_id):
        # First get entity configuration
        _ec = self.request_response(origin_id, authority_id, "entity_configuration",
                                    request_args={"entity_id": authority_id})
        # Then entity statement about subordinate
        _es = self.request_response(origin_id, authority_id, "entity_statement",
                                    issuer=authority_id, subject=subordinate_id)

    def step_down(self, origin_id, authority_id, subordinate_id):
        # First get subordinates configuration
        # Order doesn't really matter
        _ec = self.request_response(origin_id, subordinate_id, "entity_configuration",
                                    request_args={"entity_id": subordinate_id})
        # Then entity statement about subordinate
        _es = self.request_response(origin_id, authority_id, "entity_statement",
                                    issuer=authority_id, subject=subordinate_id)

    def trawl(self, superior, subordinate, entity_type):
        _es = self.request_response("rp", superior, "fetch", issuer=superior,
                                    subject=subordinate)
        # add subjects key/-s to keyjar
        self.federation_entity["rp"].keyjar.import_jwks(_es["jwks"], _es["sub"])

        _ec = self.request_response("rp", subordinate, "entity_configuration",
                                    {"entity_id": subordinate})
        _pid_issuers = self.request_response("rp", subordinate, "list", entity_id=subordinate,
                                             entity_type=entity_type)
        _intermediates = self.request_response("rp", subordinate, "list",
                                               entity_id=subordinate,
                                               intermediate=True)
        for entity_id in _intermediates:
            _pidi = self.trawl(subordinate, entity_id, entity_type)
            if _pidi:
                _pid_issuers.extend(_pidi)
        return _pid_issuers


_federation = Federation()

# get entity configuration for TA
resp = _federation.request_response("rp", TA_ID, "entity_configuration",
                                    {"entity_id": TA_ID})
print(resp)
# list all intermediates to the TA
list_resp = _federation.request_response("rp", TA_ID, "list", entity_id=TA_ID)
print(list_resp)

res = {}
for entity_id in list_resp:
    _federation.trawl(TA_ID, entity_id)