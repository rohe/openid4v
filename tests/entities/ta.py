from typing import List
from typing import Optional

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.utils import make_federation_entity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None):
    ta = make_federation_entity(
        entity_id,
        preference=preference,
        key_config={"key_defs": DEFAULT_KEY_DEFS},
        endpoints=TA_ENDPOINTS
    )

    return ta
