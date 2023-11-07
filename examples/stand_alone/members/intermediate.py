from typing import List
from typing import Optional

from fedservice.utils import make_federation_entity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS


def main(entity_id: str,
         authority_hints: Optional[List[str]],
         trust_anchors: Optional[dict],
         preference: Optional[dict] = None):
    entity = make_federation_entity(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        key_config={"key_defs": DEFAULT_KEY_DEFS},
        trust_anchors=trust_anchors,
    )
    return entity
