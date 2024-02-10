from dataclasses import dataclass
from itertools import groupby
from operator import itemgetter
from typing import Any, Callable, NamedTuple

from loguru import logger
from pydantic import Field

from binnacle import model
from binnacle.adapters.typedb.typedb_utils import get_alias_lookup_table
from binnacle.model import k8s_object as k8s_model
from binnacle.utils import kebap_case_to_pascal_case


def map_entity_to_domain_object(entity: dict) -> k8s_model.Thing:
    """Instantiate a new object from the domain model from the given dict, based on the field 'kind'.

    :param entity: a dict describing a Kubernetes object
    :return: the instantiated domain object
    """
    assert "kind" in entity, "The field 'kind' MUST exist on the entity"
    domain_obj_name = kebap_case_to_pascal_case(entity["kind"])

    ctor = getattr(model, domain_obj_name, None)
    if ctor is None:
        logger.warning(f"Received unknown kind '{entity['kind']}' from query")
        # to avoid 'loosing' entities, map it to a generic thing
        ctor = model.Thing

    attributes = map_attributes(entity.pop("attributes", []))

    obj = ctor(**entity, **attributes)
    return obj


@dataclass
class Ref:
    """An implicit reference between domain objects. This is not mapped to the knowledge base."""

    # subject: str | Thing
    relationship: str
    target: str | model.DomainObject
    target_type: str | None = None


class RelationData(NamedTuple):
    id: str
    ctor: Callable
    attributes: dict
    refs: list[Ref]

    def __hash__(self) -> int:
        return hash(self.id)


def map_relation(relation: dict) -> RelationData:
    """Instantiate a new relation from the given dict, based on the field 'kind'.

    :param relation: a dict describing a relation
    :return: a dict with prepared entries for later conversion to domain object
    """

    domain_rel_name = kebap_case_to_pascal_case(relation["kind"])
    ctor = getattr(model, domain_rel_name, None)
    if ctor is None:
        logger.warning(f"Received unknown kind '{relation['kind']}' from query")
        ctor = model.Relation

    refs = []
    # meta_infos = model.get_meta_infos(ctor)
    alias_lookup = get_alias_lookup_table(ctor)
    for e in relation["edges"]:
        # make sure to use the relatinoship name of the model and not the TypeDB variable
        field_name = alias_lookup.get(e["relationship"], e["relationship"])

        field_info = Field() if (field := ctor.model_fields.get(field_name)) is None else field
        if field_info.exclude:
            logger.warning(f"Excluding refrence {field_name} on {domain_rel_name}")
            continue
        # is_passive_relation = meta_infos[field_name].get(model.FieldConfig.IsPassive, False)
        label = field_info.alias or field_name
        ref = Ref(
            relationship=field_name,
            target=e["target"],
            target_type=e["target_type"],
            # is_passive=is_passive_relation,
        )
        refs.append(ref)

    attributes = map_attributes(relation.pop("attributes", []))
    return RelationData(id=relation["id"], ctor=ctor, attributes=relation | attributes, refs=refs)


def map_attributes(attributes: list[tuple]) -> dict[str, Any]:
    res = {}

    for key, value_iter in groupby(sorted(attributes), itemgetter(0)):
        # grouby returns same iterator with key and value -> extract only values
        _, values = zip(*value_iter)
        res[key] = values[0] if len(values) == 1 else list(values)

    return res
