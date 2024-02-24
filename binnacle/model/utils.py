from collections import defaultdict
from functools import reduce
from typing import Iterable

from loguru import logger

from binnacle.model.primitives import DomainObject, FieldConfig, get_meta_infos
from binnacle.utils import measure


def map_kind_to_resource_type(kind: str) -> str:
    """Map the Kubernetes kind into its string representation used for API endpoints, RBAC, etc.

    :param kind: the kind of the Kubernetes object, that will be mapped
    :return: the converted string representation of the resource
    """
    res_type = kind.lower()

    if res_type.endswith(("class", "ingress")):
        res_type += "es"
    elif res_type.endswith("policy"):
        res_type = res_type.replace("policy", "policies")
    elif res_type.endswith("capacity"):
        res_type = res_type.replace("capacity", "capacities")
    else:
        res_type += "s"
    return res_type


@measure
def consolidate_objects(objects: list[DomainObject], merge_similar_objects: bool = False) -> list[DomainObject]:
    """Simplifies the list of objects by deduplicating and combining similar objects
     where possible without loosing any of the semantic information.
    For example some objects whiche are the same except for a reference to another object my be
    merged so just one such object has multiple references to the referenced objects.

    :param res: the list of objects, which will be simplified
    :return: the simplified version with ideally less objects but the same information
    """

    # merge all objects with the exact same id
    object_index = {}
    for o in objects:
        if o.id not in object_index:
            object_index[o.id] = o
        else:
            assert type(o) == type(object_index[o.id])
            update_object(object_index[o.id], o)

    if merge_similar_objects:
        return consolidate_similar_objects(object_index.values())
    else:
        return list(object_index.values())


def consolidate_similar_objects(objects: Iterable[DomainObject]) -> list[DomainObject]:
    """If possible try to combine similar objects into a single objects across a list of various objects.

    :param objects: _description_
    :return: _description_
    """
    results = []
    print(f"Before: {len(objects)} objects")

    type_groups = defaultdict(list)
    for o in objects:
        type_groups[type(o)].append(o)

    integrated_objects = {}
    for group in type_groups.values():
        consolidated_objects, mapping = reduce(integrate_object_into_collection, group, ([], defaultdict(list)))
        results += consolidated_objects
        integrated_objects.update(mapping)

    # update any dangling requirements to the consolidated object
    for o in results:
        for i, requirement in enumerate(getattr(o, "requires", [])):
            # update the requirement to the resulting consolidated object
            if requirement.id in integrated_objects:
                o.requires[i] = integrated_objects[requirement.id]

    print(f"After: {len(results)} objects")
    return results


AccumulatedObjectsAndMapping = tuple[list[DomainObject], dict[str, DomainObject]]


def integrate_object_into_collection(
    accumulated_objects_and_mapping: AccumulatedObjectsAndMapping, new_object: DomainObject
) -> AccumulatedObjectsAndMapping:
    """Try to merge the given object with any of the objects in the collection if they differ only in combinable fields.
    If it's not possible to merge the original objects will be added to the collection

    :param objects: a list of objects
    :param new_object: the object, which will be merged into an existing object or added to the collection
    :return: a list of objects with the new object integrated
    """
    objects, consolidated_object_mapping = accumulated_objects_and_mapping
    for o in objects:
        if is_similar(o, new_object):
            update_object(o, new_object)
            consolidated_object_mapping[new_object.id] = o
            break  # no need to try merging it with other objects
    else:  # no match was found, so add it to the collection
        objects.append(new_object)
    return objects, consolidated_object_mapping


def update_object(updated_object: DomainObject, source_object: DomainObject) -> None:
    """Updated the given object with the fields from the source object.

    :param updated_object: the object, that will be updated in place
    :param source_object: the object with the new values
    """
    updated_dict = updated_object.__dict__

    for field_name, new_value in source_object.__dict__.items():
        if new_value is not None:
            old_value = updated_dict[field_name]
            if old_value is None:
                updated_dict[field_name] = new_value
            elif isinstance(old_value, list):
                # only add new values, ignore duplicates
                old_value += [v for v in new_value if v not in updated_dict[field_name]]
            elif isinstance(old_value, dict):
                overwritten_keys = [
                    k for k, v in new_value.items() if (old := old_value.get(k, None)) is not None and old != new_value
                ]
                if len(overwritten_keys) > 0:
                    logger.warning(
                        f'The keys "{ ", ".join(overwritten_keys) }" of field {field_name} on object {updated_object.id} will be overwritten!'
                    )
                old_value.update(new_value)


def is_similar(object1: DomainObject, object2: DomainObject) -> bool:
    """Compare to objects if they are similar with regard to the type and mandatory fields.

    :param object1: the first object for the comparison
    :param object2: the other object for the comparison
    :return: True if the objects are similar, False otherwise
    """

    if type(object1) == type(object2):
        if object1.id == object2.id:  # exact match
            return True

        obj1_meta = get_meta_infos(object1)

        # TODO get mandatory fields and compare them
        for field_name, config in type(object1).model_fields.items():
            if field_name == "id":  # ignore the id
                continue

            if obj1_meta[field_name].get(FieldConfig.Mergable, False) or config.exclude:
                continue

            val1 = getattr(object1, field_name, None)
            val2 = getattr(object2, field_name, None)

            if val1 is not None and val2 is not None and val1 != val2:
                return False
        return True

    return False
