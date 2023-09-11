import json
from json import JSONDecodeError
from typing import Dict
from typing import List
from typing import Optional
from typing import Union
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from cryptojwt.jws.jws import factory
from fedservice.combo import FederationCombo
from fedservice.entity.function import apply_policies
from fedservice.entity.function import verify_trust_chains
from idpyoidc.message import Message
from idpyoidc.util import rndstr

from examples.federation import federation_setup
from examples.federation import wallet_setup
from oidc4vci.wallet_provider.token import Token

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
    "resolve": "resolve",
    "fetch": "entity_statement"
}

EUDI_SRV2ENDP_MAP = {
    "wallet_instance_attestation": "wallet_provider_token",
    "list": "list",
    "fetch": "entity_statement",
    "resolve": "resolve",
    "authorization": "authorization"
}


class Federation():

    def __init__(self):
        self.federation_entity = federation_setup()
        self.requestor = wallet_setup(self.federation_entity)

    def federation_query(self,
                         receiver_id: str,
                         service: str,
                         collecting: Optional[bool] = False,
                         request_args: Optional[dict] = None,
                         **kwargs) -> Union[Message, dict]:
        _service = self.requestor["federation_entity"].get_service(SRV2FUNC_MAP[service])
        _service.upstream_get('unit').context.issuer = receiver_id

        if request_args is None:
            req_info = _service.get_request_parameters(**kwargs)
        else:
            req_info = _service.get_request_parameters(request_args, **kwargs)

        receiver = get_entity(self.federation_entity, receiver_id)

        if isinstance(receiver, FederationCombo):
            endpoint = receiver["federation_entity"].get_endpoint(service)
        else:
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
            if service == "entity_configuration" and collecting:
                _jws = factory(response["response"])
                _payload = _jws.jwt.payload()
                _payload["_jws"] = response["response"]
                _keyjar = _service.upstream_get("attribute", "keyjar")
                _keyjar.import_jwks(_payload['jwks'], receiver_id)
                _resp = _payload
            else:
                _resp = _service.parse_response(response["response"])
        return _resp

    def do_layer(self, entity_id, subordinate_id):
        # First get entity configuration
        _ec = self.federation_query(entity_id, "entity_configuration", collecting=True,
                                    request_args={"entity_id": entity_id})
        # Then entity statement about subordinate
        _endpoint = _ec["metadata"]["federation_entity"]['federation_fetch_endpoint']
        _es = self.federation_query(entity_id, "fetch", collecting=True,
                                    issuer=entity_id, subject=subordinate_id,
                                    fetch_endpoint=_endpoint)
        return _ec, _es

    # def step_down(self, origin_id, authority_id, subordinate_id):
    #     # First get subordinates configuration
    #     # Order doesn't really matter
    #     _ec = self.federation_query(origin_id, subordinate_id, "entity_configuration",
    #                                 request_args={"entity_id": subordinate_id})
    #     # Then entity statement about subordinate
    #     _es = self.federation_query(origin_id, authority_id, "entity_statement",
    #                                 issuer=authority_id, subject=subordinate_id)

    def _trust_chain(self,
                     leaf: Optional[Message] = None,
                     stop_at: List[str] = None):
        _superior = {}
        if "authority_hints" in leaf:
            for authority_hint in leaf["authority_hints"]:
                _ec, _es = self.do_layer(authority_hint, leaf["sub"])
                if authority_hint in stop_at:
                    _superior[authority_hint] = [_es._jws, {}]
                else:
                    _superior[authority_hint] = [_es._jws, self._trust_chain(_ec, stop_at=stop_at)]
        return _superior

    def collect_trust_tree(self,
                           entity_id: str,
                           stop_at: List[str] = None,
                           leaf: Optional[Message] = None) -> List:
        if not leaf:
            # First the entity configuration
            leaf = _federation.federation_query(entity_id, "entity_configuration", collecting=True,
                                                request_args={"entity_id": entity_id})
        _superior = {}
        if "authority_hints" in leaf:
            for authority_hint in leaf["authority_hints"]:
                _ec, _es = self.do_layer(authority_hint, entity_id)
                _superior[authority_hint] = [_es._jws, self._trust_chain(_ec, stop_at=stop_at)]

        return [leaf["_jws"], _superior]

    def get_verified_metadata(self, entity_id: str, stop_at: List[str]) -> Dict:
        trust_tree = self.collect_trust_tree(entity_id=entity_id, stop_at=stop_at)
        ll = tree2chains(trust_tree)
        trust_chains = verify_trust_chains(self.requestor["federation_entity"], ll)
        trust_chains = apply_policies(self.requestor["federation_entity"], trust_chains)

        # Store away for later usage
        for tc in trust_chains:
            self.requestor["federation_entity"].trust_chain[tc.iss_path[0]] = tc

        # I know there is only one
        return trust_chains[0].metadata

    def trawl(self, superior, subordinate, entity_type):
        _es = self.federation_query(superior,
                                    "fetch",
                                    issuer=superior,
                                    subject=subordinate)
        # add subjects key/-s to keyjar
        self.requestor["federation_entity"].keyjar.import_jwks(_es["jwks"], _es["sub"])

        _ec = self.federation_query(subordinate,
                                    "entity_configuration",
                                    sender_id="rp",
                                    request_args={"entity_id": subordinate})
        _pid_issuers = self.federation_query(subordinate,
                                             "list",
                                             sender_id="rp",
                                             entity_id=subordinate,
                                             entity_type=entity_type)
        _intermediates = self.federation_query(subordinate,
                                               "list",
                                               sender_id="rp",
                                               entity_id=subordinate,
                                               intermediate=True)
        for entity_id in _intermediates:
            _pidi = self.trawl(subordinate, entity_id, entity_type)
            if _pidi:
                _pid_issuers.extend(_pidi)
        return _pid_issuers

    def eudi_query(self,
                   receiver_id: str,
                   service_name: str,
                   requester_part: Optional[str] = "",
                   opponent: Optional[str] = "",
                   request_args: Optional[dict] = None,
                   **kwargs):

        actor = self.requestor[requester_part]
        if requester_part == "pid_eaa_consumer":
            _actor = actor.get_consumer(opponent)
            if _actor is None:
                actor = actor.new_consumer(opponent)
            else:
                actor = _actor
            _w_service = self.requestor["wallet"].get_service("wallet_instance_attestation")
            wia = _w_service.wallet_instance_attestations[kwargs.get('client_assertion_kid')]
            kwargs["wallet_instance_attestation"] = wia["assertion"]

        _service = actor.get_service(service_name)
        if request_args is None:
            req_info = _service.get_request_parameters(**kwargs)
        else:
            req_info = _service.get_request_parameters(request_args, **kwargs)

        # talk to the non-federation_entity part
        non_fed_role = [k for k in self.federation_entity[receiver_id].keys() if
                        k != "federation_entity"]
        _receiver = self.federation_entity[receiver_id][non_fed_role[0]].get_endpoint(
            EUDI_SRV2ENDP_MAP[service_name])
        _data = req_info.get("data", req_info.get("body"))
        _args = _receiver.parse_request(_data)
        if isinstance(_receiver, Token):
            _chain = self.requestor["federation_entity"].get_trust_chain(
                self.federation_entity[receiver_id].entity_id)
            _response = _receiver.process_request(_args, trust_chain=_chain)
        else:
            _response = _receiver.process_request(_args)

        if isinstance(_response, Message):
            _resp = _service.parse_response(_response, sformat="dict")
        elif 'response' in _response:
            _resp = _service.parse_response(_response["response"])
        else:
            _resp = _service.parse_response(_response["response_args"], sformat="dict")
        return _resp


# ================================================================================================
def tree2chains(node):
    res = []
    statement, branches = node
    if branches == {}:
        res.append([statement])
    else:
        for key, item in branches.items():
            _esl = tree2chains(item)
            for l in _esl:
                l.append(statement)
            if not res:
                res = _esl
            else:
                res.extend(_esl)
    return res


# ================================================================================================

_federation = Federation()

print(10 * "-", "Collect trust chain", 10 * "-")
tas = list(
    _federation.requestor["federation_entity"].function.trust_chain_collector.trust_anchors.keys())
print(tas)

# get entity configuration for TA
ta_entity_configuration = _federation.federation_query(tas[0], "entity_configuration",
                                                       request_args={"entity_id": tas[0]})
print(ta_entity_configuration)

wallet_provider_entity_id = _federation.federation_entity["wp"].entity_id
wpi_metadata = _federation.get_verified_metadata(wallet_provider_entity_id, stop_at=tas)

# wallet_provider = _federation.federation_entity["wp"]
# token_endpoint = wallet_provider["wallet_provider"].get_endpoint("wallet_provider_token")

wallet_instance_attestation = _federation.eudi_query("wp",
                                                     "wallet_instance_attestation",
                                                     "wallet",
                                                     request_args={
                                                         "nonce": rndstr(),
                                                         "aud": wallet_provider_entity_id
                                                     },
                                                     # endpoint=token_endpoint.endpoint_path
                                                     endpoint=wpi_metadata["wallet_provider"][
                                                         "token_endpoint"]
                                                     )

print(wallet_instance_attestation)
thumbprint_in_cnf_jwk = wallet_instance_attestation["__verified_assertion"]["cnf"]["jwk"]["kid"]

# Search for all credential issuers
res = []
list_resp = _federation.federation_query(TA_ID, "list", entity_id=TA_ID)
for entity_id in list_resp:
    res.extend(_federation.trawl(TA_ID, entity_id, "openid_credential_issuer"))

print(f"openid_credential_issuers: {res}")

my_oci = None
oci = ''
for oci in res:
    print(10 * "-", f"OpenID Credential Issuer {oci} Metadata", 10 * "-")
    oci_metadata = _federation.get_verified_metadata(oci, stop_at=tas)
    # print(json.dumps(oci_metadata, sort_keys=True, indent=4))
    for cs in oci_metadata['openid_credential_issuer']["credentials_supported"]:
        if "PersonIdentificationData" in cs["credential_definition"]["type"]:
            my_oci = oci_metadata
            break

request_args = {
    "authorization_details": [
        {
            "type": "openid_credential",
            "format": "vc+sd-jwt",
            "credential_definition": {
                "type": "PersonIdentificationData"
            }
        }
    ],
    "response_type": "code",
    "client_id": thumbprint_in_cnf_jwk,
    "redirect_uri": "eudiw://start.wallet.example.org"
}

authorization_response = _federation.eudi_query(
    receiver_id='oci',
    service_name="authorization",
    requester_part="pid_eaa_consumer",
    opponent=oci,
    request_args=request_args,
    endpoint=my_oci["openid_credential_issuer"]["authorization_endpoint"],
    client_assertion_kid=thumbprint_in_cnf_jwk
)

print(authorization_response)
