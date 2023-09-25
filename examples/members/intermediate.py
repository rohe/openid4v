from typing import List
from typing import Optional

from fedservice.build_entity import FederationEntityBuilder
from fedservice.entity import FederationEntity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS


def main(entity_id: str,
         authority_hints: List[str],
         trust_anchors: dict,
         preference: Optional[dict]=None):
    entity = FederationEntityBuilder(
        entity_id,
        preference=preference,
        key_conf={"key_defs": DEFAULT_KEY_DEFS},
        authority_hints=authority_hints
    )
    entity.add_services()
    entity.add_functions()
    entity.add_endpoints()

    federation_entity = FederationEntity(**entity.conf)
    federation_entity.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
        'trust_anchors'] = trust_anchors
    return federation_entity