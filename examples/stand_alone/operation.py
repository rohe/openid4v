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
from idpyoidc.logging import configure_logging
from idpyoidc.message import Message
from idpyoidc.util import rndstr

from examples.stand_alone.federation import federation_setup
from examples.stand_alone.wallet_setup import wallet_setup
from openid4v.wallet_provider.token import Token

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
    "authorization": "authorization",
    "accesstoken": "token",
    "credential": "credential"
}


class Federation():

    def __init__(self):
        self.federation_entity = federation_setup()
        self.requestor = wallet_setup(self.federation_entity)
        self.state = ""

    def get_request(self, req_info):
        if "url" in req_info:
            part = urlsplit(req_info["url"])
            if part.query:
                query = {}
                for key, val in parse_qs(part.query).items():
                    if len(val) == 1:
                        query[key] = val[0]
                    else:
                        query[key] = val
                return query

        if "request" in req_info:
            return req_info["request"]
        elif "request_args" in req_info:
            return req_info["request_args"]
        elif "data" in req_info:
            return req_info["data"]
        elif "body" in req_info:
            return req_info["body"]

    def federation_query(self,
                         receiver_id: str,
                         service: str,
                         collecting: Optional[bool] = False,
                         request_args: Optional[dict] = None,
                         **kwargs) -> Union[Message, dict]:
        _service = self.requestor["federation_entity"].get_service(SRV2FUNC_MAP[service])
        _service.upstream_get('unit').context.issuer = receiver_id
        logger.info(f"==== Service name: {_service.service_name}")

        if request_args is None:
            req_info = _service.get_request_parameters(**kwargs)
        else:
            req_info = _service.get_request_parameters(request_args, **kwargs)

        logger.info(f"==== Request Info: {req_info} ====")
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

        logger.info(f"==== Endpoint Response: {response} ====")

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

        logger.info(f"==== Response parsed by the Service: {_resp} ====")
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

            if service_name == "authorization":
                _w_service = self.requestor["wallet"].get_service("wallet_instance_attestation")
                wia = _w_service.wallet_instance_attestations[kwargs.get('client_assertion_kid')]
                kwargs["wallet_instance_attestation"] = wia["assertion"]

            if not self.state:
               self.state = rndstr(16)
            kwargs["state"] = self.state

        _service = actor.get_service(service_name)
        if request_args is None:
            req_info = _service.get_request_parameters(**kwargs)
        else:
            req_info = _service.get_request_parameters(request_args, **kwargs)

        http_info = {k: v for k, v in req_info.items() if k in ["url", "headers", "method"]}

        # talk to the non-federation_entity part
        non_fed_role = [k for k in self.federation_entity[receiver_id].keys() if
                        k != "federation_entity"]
        _receiver = self.federation_entity[receiver_id][non_fed_role[0]].get_endpoint(
            EUDI_SRV2ENDP_MAP[service_name])
        _data = self.get_request(req_info)
        _request_args = _receiver.parse_request(_data, http_info)
        if isinstance(_receiver, Token):
            _chain = self.requestor["federation_entity"].get_trust_chain(
                self.federation_entity[receiver_id].entity_id)
            _response = _receiver.process_request(_request_args, trust_chain=_chain)
        else:
            _response = _receiver.process_request(_request_args, http_info=http_info)

        if isinstance(_response, Message):
            _resp = _service.parse_response(_response, sformat="dict")
        elif 'response' in _response:
            _resp = _service.parse_response(_response["response"])
        elif "response_args" in _response:
            _resp = _service.parse_response(_response["response_args"], sformat="dict")
        else:
            _resp = _service.parse_response(_response, sformat="dict")

        if requester_part == "pid_eaa_consumer":
            if service_name == "authorization":
                self.state = request_args["state"]

        if self.state:
            _service.update_service_context(_resp, key=self.state)

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


def get_credential_issuer(credential_type: Optional[str] = "PersonIdentificationData"):
    # Search for all credential issuers
    logger.info("**** Find one Credential Issuer that issues credentials of type {"
                "credential_type} ****")
    res = []
    list_resp = _federation.federation_query(TA_ID, "list", entity_id=TA_ID)
    for entity_id in list_resp:
        res.extend(_federation.trawl(TA_ID, entity_id, "openid_credential_issuer"))

    logger.info(f"**** ALL openid_credential_issuers: {res} ****")

    _oci = {}
    for pid in res:
        oci_metadata = _federation.get_verified_metadata(pid, stop_at=tas)
        # logger.info(json.dumps(oci_metadata, sort_keys=True, indent=4))
        for cs in oci_metadata['openid_credential_issuer']["credentials_supported"]:
            if credential_type in cs["credential_definition"]["type"]:
                _oci[pid] = oci_metadata
                break
    return _oci


def get_credentials(authz_request_args: dict,
                    credential_type: Optional[str] = "PersonIdentificationData",
                    receiver_id: Optional[str] = "pid"
                    ):
    logger.info(f"Looking for credential issuers of {credential_type}")
    oci_dict = get_credential_issuer(credential_type)
    for key, val in oci_dict.items():
        logger.info(f"{key} **** OpenID Credential Issuer {val} Metadata ****")

    pid = list(oci_dict.keys())[0]
    my_oci = oci_dict[pid]

    logger.info(">>>> Send the authorization request >>>>")
    authorization_response = _federation.eudi_query(
        receiver_id=receiver_id,
        service_name="authorization",
        requester_part="pid_eaa_consumer",
        opponent=pid,
        request_args=authz_request_args,
        endpoint=my_oci["openid_credential_issuer"]["authorization_endpoint"],
        client_assertion_kid=thumbprint_in_cnf_jwk
    )

    logger.info(f"<<<< Authorization response: {authorization_response} <<<<")

    token_request_args = {
        "state": authorization_response["state"],
        "grant_type": "authorization_code",
        "code": authorization_response["code"],
        "redirect_uri": authz_request_args["redirect_uri"],
        "client_id": thumbprint_in_cnf_jwk,
    }

    logger.info(">>>> The Token Request >>>>")
    token_response = _federation.eudi_query(
        receiver_id=receiver_id,
        service_name="accesstoken",
        requester_part="pid_eaa_consumer",
        opponent=pid,
        request_args=token_request_args,
        endpoint=my_oci["openid_credential_issuer"]["token_endpoint"],
        client_assertion_kid=thumbprint_in_cnf_jwk,
        kid=thumbprint_in_cnf_jwk,
        # client_id = thumbprint_in_cnf_jwk
    )

    logger.info(f"<<<< Token response: {token_response} <<<<")

    # ---------------- Credential request -------------------

    _federation.requestor.get_keyjar().import_jwks(my_oci["openid_credential_issuer"]["jwks"],
                                                   my_oci["openid_credential_issuer"]["issuer"])

    credential_request_args = {
        "format": "vc+sd-jwt",
        "credential_definition": {
            "type": [credential_type]
        }
    }

    logger.info(">>>> The Credential Request >>>>")
    credential_response = _federation.eudi_query(
        receiver_id=receiver_id,
        service_name="credential",
        requester_part="pid_eaa_consumer",
        opponent=pid,
        request_args=credential_request_args,
        endpoint=my_oci["openid_credential_issuer"]["credential_endpoint"],
    )

    logger.info(f"<<<< {credential_type} Credential response: {credential_response} <<<<")


# ================================================================================================

LOGG_CONFIG = {
    "version": 1,
    "root": {
        "handlers": [
            "default"
        ],
        "level": "DEBUG"
    },
    "handlers": {
        "default": {
            "class": "logging.FileHandler",
            "filename": "debug.log",
            "formatter": "default"
        },
    },
    "formatters": {
        "default": {
            "format": "[%(asctime)s] [%(levelname)s] [%(name)s.%(funcName)s] %(message)s"
        }
    }
}

logger = configure_logging(config=LOGG_CONFIG)
logger.info("Starting")

logger.info("##### Building the federation #####")
_federation = Federation()

tas = list(
    _federation.requestor["federation_entity"].function.trust_chain_collector.trust_anchors.keys())
logger.info(f"#### Trust Anchors: {tas}")

# get entity configuration for TA
logger.info(f">>>> Get entity configuration for {tas[0]} >>>>")
ta_entity_configuration = _federation.federation_query(tas[0], "entity_configuration",
                                                       request_args={"entity_id": tas[0]})
logger.info(f"<<<< Trust anchor entity configuration: {ta_entity_configuration} <<<<")

wallet_provider_entity_id = _federation.federation_entity["wp"].entity_id
logger.info(">>>> Collect Wallet Provider Metadata >>>>")
wpi_metadata = _federation.get_verified_metadata(wallet_provider_entity_id, stop_at=tas)
logger.info(f"<<<< Wallet Provider Metadata: {wpi_metadata}")

logger.info(">>>> The wallet asks the Wallet Provider for a Wallet Instance Attestation >>>>")
wallet_instance_attestation = _federation.eudi_query(
    "wp", "wallet_instance_attestation", "wallet",
    request_args={"nonce": rndstr(), "aud": wallet_provider_entity_id},
    endpoint=wpi_metadata["wallet_provider"]["token_endpoint"])

logger.info("<<<< The returned Wallet Instance Attestation <<<<")
logger.info(wallet_instance_attestation)
thumbprint_in_cnf_jwk = wallet_instance_attestation["__verified_assertion"]["cnf"]["jwk"]["kid"]

authz_request_args = {
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

logger.info("**** PersonIdentificationData ****")
get_credentials(authz_request_args, "PersonIdentificationData", receiver_id="pid")
logger.info("**** OpenBadgeCredential ****")
get_credentials(authz_request_args, "OpenBadgeCredential", receiver_id="qeea")
