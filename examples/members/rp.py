from typing import List
from typing import Optional

from fedservice.build_entity import FederationEntityBuilder
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS


def main(entity_id: str,
         authority_hints: List[str],
         trust_anchors: dict,
         preference: Optional[dict] = None):
    entity = FederationEntityBuilder(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        key_conf={"key_defs": DEFAULT_KEY_DEFS}
    )
    entity.add_services()
    entity.add_functions()
    entity.add_endpoints({}, **LEAF_ENDPOINT)
    entity.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
        'trust_anchors'] = trust_anchors

    fe = FederationEntity(**entity.conf)
    for id, jwk in trust_anchors.items():
        fe.keyjar.import_jwks(jwk, id)

    return fe
