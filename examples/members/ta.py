from typing import List
from typing import Optional

from fedservice.build_entity import FederationEntityBuilder
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.entity import FederationEntity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None):
    TA = FederationEntityBuilder(
        entity_id,
        preference=preference,
        key_conf={"key_defs": DEFAULT_KEY_DEFS}
    )
    TA.add_endpoints(None, **TA_ENDPOINTS)
    ta = FederationEntity(**TA.conf)
    return ta
