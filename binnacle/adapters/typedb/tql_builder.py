import enum
import inspect
from collections import defaultdict
from enum import Enum
from functools import reduce
from types import NoneType, UnionType
from typing import Annotated, Any, Iterable, Type, get_args, get_origin

from loguru import logger
from pydantic import BaseModel
from pydantic.fields import FieldInfo

from binnacle import model
from binnacle.adapters.typedb.typedb_utils import get_alias_lookup_table
from binnacle.model.primitives import DomainObject, Thing
from binnacle.utils import to_kebab_case


def is_primitive(field: FieldInfo) -> bool:
    """Check if the type of the field is considered a 'primitive' type.
        e.g. int, str, bool, None
    In case of a union type it's considered primitive, if all choices are primitive as well.

    :param field: the field to inspect
    :return: True if the field type is primitive, False otherwise
    """
    primitive_types = (int, str, bool, NoneType, model.SpecialField)
    match field.annotation:
        case UnionType():
            return all(a in primitive_types for a in get_args(field.annotation))
        case enum.EnumMeta():
            return True
    return field.annotation in primitive_types


class TqlBuilder:
    """A generic builder to transform domain objects in to their corresponding representation in the TypeDB query language.
    Depending on the type of the query this representation is different.
    """

    def __init__(self, *objects: BaseModel | Type[BaseModel]) -> None:
        self.objects = objects or []
        self.variables = {}

    def as_tql(
        self,
        var_name: str | None = None,
        include_subtypes: bool = False,
        as_single_query: bool = True,
        prefix_fields: bool = False,
    ) -> str | list[str]:
        tqls = []
        for obj in self.objects:
            if isinstance(obj, DomainObject):
                tqls.append(self._map_object(obj, var_name=var_name, prefix_fields=prefix_fields))
            elif inspect.isclass(obj):
                tqls.append(self._map_class(obj, var_name=var_name))
                if include_subtypes:
                    sub_types = [cls for cls in obj.__subclasses__()]
                    tqls += [self._map_class(sub) for sub in sub_types]
            elif isinstance(obj, list):
                tqls.extend((TqlBuilder(o).as_tql() for o in obj))
            else:
                logger.error(f'Unsure how to map "{obj}" to a query')
        return " ".join(tqls) if as_single_query else tqls

    def as_get_query(self, include_subtypes: bool = False, as_single_query: bool = False) -> str | list[str]:
        tqls = self.as_tql(include_subtypes=include_subtypes, as_single_query=as_single_query)
        if as_single_query:
            return "match " + str(tqls)
        return [f"match {tql}" for tql in tqls]

    def set_variables(self, **vars) -> "TqlBuilder":
        self.variables.update(vars)
        # add TQL alias with '-' instead of '_' as well
        vars = {k.replace("_", "-"): v for k, v in vars.items()}
        self.variables.update(vars)
        return self

    def _map_object(
        self, obj: DomainObject, var_name: str | None = None, prefix_fields: bool = False, type_name: str | None = None
    ) -> str:
        obj_type = to_kebab_case(str(obj)) if type_name is None else type_name
        if var_name is None:
            # default to the object_type as the variable name, if there is no better match
            var_name = self.variables.get(obj_type, obj_type)

        var_prefix = f"{var_name}_" if prefix_fields else None

        attributes, constraints, relations = self._parse_fields(obj, var_prefix=var_prefix)

        # relations specify their "players" in brackets after the variable name
        # e.g. `$relation (player1: $var1, player2: $var2) isa relation;``
        rel_variables = _get_variables_from_relations(relations)

        rel_definition = ""
        if len(rel_variables) > 0:
            refs = []

            for role, vars in rel_variables.items():
                for i, v in enumerate(vars):
                    # user defined variable names have priority
                    rel_var_name = self.variables.get(role, v)
                    sfx = "" if len(vars) <= 1 else f"_{i}"
                    refs.append(f"{role}: ${rel_var_name}{sfx}")

            # refs = [f"{role}: ${var}" for role, var in rel_variables.items()]
            rel_definition = f' ({", ".join(refs)})'

        init = f"${var_name}{rel_definition} isa {obj_type}"
        base = ", ".join([init] + attributes)

        # append the constraints at the end, because they are dedicated statemen:w
        tql = "; ".join([base] + constraints)
        return tql + ";"

    def _map_class(self, thing_class: Type[DomainObject], var_name: str | None = None) -> str:
        obj_type = to_kebab_case(thing_class.__name__)
        if var_name is None:
            var_name = self.variables.get(obj_type, obj_type)

        attributes, constraints, relations = self._parse_fields(thing_class)

        # relations specify their "players" in brackets after the variable name
        # e.g. `$relation (player1: $var1, player2: $var2) isa relation;``
        rel_variables = _get_variables_from_relations(relations)
        rel_variables.update(self.variables)  # user defined variables have priority
        rel_definition = ""

        alias_lookup = get_alias_lookup_table(thing_class)

        refs = []
        # unpack the 'var' because in the 'template', there is always just 1 entry of the var
        for role, [var] in rel_variables.items():
            refs.append(f"{role}: ${var}")
            # get mandatory attributes of relations as constraints for this query
            field_name = alias_lookup.get(role, role)
            rel_type = thing_class.model_fields[field_name].annotation

            # 2nd order relations are not relevant this role
            rel_attrs, rel_constraints, _rel_relations = self._parse_fields(rel_type, var_prefix=f"{role}-")

            # explicitely state the constraints for the related variable
            constraints += [f"${var} {constraint};" for constraint in (rel_attrs + rel_constraints)]

        if len(refs) > 0:
            rel_definition = f' ({", ".join(refs)})'

        init = f"${var_name}{rel_definition} isa {obj_type}"
        base = ", ".join([init] + attributes) + ";"

        # append the constraints at the end, because they are dedicated statement
        tql = " ".join([base] + constraints)
        return tql

    def _parse_fields(self, obj: BaseModel, var_prefix: str | None = None) -> tuple[list, list, list]:
        attributes = []
        constraints = []
        relations = []

        if not hasattr(obj, "model_fields"):
            return self._parse_union_field(obj, var_prefix=var_prefix)
        meta_infos = model.get_meta_infos(obj)

        for field_name, field in obj.model_fields.items():
            if field.exclude:
                continue

            meta = meta_infos[field_name]
            tql_field_name = to_kebab_case(field.alias or field_name)

            value = getattr(obj, field_name, None)

            if value is None:
                if field.is_required() or meta.get(model.FieldConfig.Required, False):
                    if (
                        is_primitive(field) and model.FieldConfig.RelationPart not in meta
                    ):  # complex fields are either nested attributes or relations
                        attr, constraint = self._format_attribute(tql_field_name, value, var_prefix=var_prefix)
                        attributes.append(attr)
                        continue
                else:  # ignore any other fields
                    continue

            if model.FieldConfig.RelationPart in meta:
                # i.e. field like 'portS' should turn into singular form 'port' if the type of the
                # object is of type Port
                if type(value) != list:
                    value = [value]
                for i, entry in enumerate(value):
                    relations.append((tql_field_name, entry))
            elif (related_by := meta.get(model.FieldConfig.IsRelatedBy, None)) is not None:
                logger.info(f'Passive relation "{related_by}" is not yet supported!')
            elif is_primitive(field):
                # these are attributes with basic types like str, int, bool, etc.
                attr, constraint = self._format_attribute(tql_field_name, value, var_prefix=var_prefix)
                attributes.append(attr)
                if constraint is not None:
                    constraints.append(constraint)
            elif type(value) == list:
                selector = meta.get(model.FieldConfig.Selector, None)
                for i, entry in enumerate(value):
                    entry_value = self.get_entry_value(entry, selector)
                    attr, constraint = self._format_attribute(
                        tql_field_name, entry_value, var_prefix=var_prefix, count=i
                    )
                    attributes.append(attr)
                    if constraint is not None:
                        constraints.append(constraint)
            elif isinstance(value, model.LabelSelector):
                for i, entry in enumerate(value.items()):
                    attr, constraint = self._format_attribute(tql_field_name, entry, var_prefix=var_prefix, count=i)
                    attributes.append(attr)
                    if constraint is not None:
                        constraints.append(constraint)
            elif type(value) == dict:
                for i, (k, v) in enumerate(value.items()):
                    entry_value = self.get_entry_value(v)
                    if isinstance(entry_value, (str, int, float)):
                        # ensure the information of they key is not lost for primitive types
                        entry_value = f"{k}:{entry_value}"
                    attr, constraint = self._format_attribute(
                        tql_field_name, entry_value, var_prefix=var_prefix, count=i
                    )

                    attributes.append(attr)
                    if constraint is not None:
                        constraints.append(constraint)
            else:
                prefixed_var_name = ("" if var_prefix is None else var_prefix) + field_name
                var_name = self.variables.get(field_name, prefixed_var_name)
                attr, constraint = self._format_attribute(tql_field_name, value, var_name=var_name)
                attributes.append(attr)
                if constraint is not None:
                    constraints.append(constraint)
        return attributes, constraints, relations

    def _parse_union_field(self, obj: BaseModel, var_prefix: str | None = None) -> tuple[list, list, list]:
        if get_origin(obj) == Annotated:
            # annotated fields specify the type as the 1st arg
            obj = get_args(obj)[0]

        # filter out NoneType, because NoneType has no properties
        union_types = [a for a in get_args(obj) if a != type(None)]

        properties = zip(*(self._parse_fields(t, var_prefix=var_prefix) for t in union_types))
        properties = tuple(list_intersection(props) for props in properties)

        return properties

    def _format_attribute(
        self,
        field_name: str,
        value: Any,
        var_name: str | None = None,
        var_prefix: str | None = None,
        count: int | None = None,
    ) -> tuple[str, str | None]:
        v = None
        constraint = None
        if var_name is None:
            if field_name in self.variables:
                var_name = self.variables.get(field_name)
            else:
                var_name = ("" if var_prefix is None else var_prefix) + field_name
                if count is not None:
                    var_name += f"_{count}"

        match value:
            case str() | Enum():
                escaped_value = str(value).replace('"', '\\"')
                v = f'"{escaped_value}"'
            case bool():
                v = str(value).lower()  # in TypeDB booleans are lower case
            case int():  # Note: must be below case for bool, because True is also treated as int
                v = str(value)
            case model.Attribute():
                v = f"${var_name}"
                constraint = self._map_object(value, var_name, prefix_fields=True, type_name=field_name)
                constraint += f'${var_name} "{value.value}"'
            case model.SpecialField():
                v, constraint = _format_special_field(value, field_name)
            case model.ObjectReference():
                v = f'"{value.name}"'
            case _:
                if hasattr(value, "value"):  # if it has a value, then retry as primitive attribute
                    return self._format_attribute(
                        field_name=field_name,
                        value=value.value,  # <--  use the attributes value instead
                        var_name=var_name,
                        var_prefix=var_prefix,
                        count=count,
                    )
                logger.warning(f"using default attribute formatter for {var_name} : {value}")
                v = f"${var_name}"

        return f"has {field_name} {v}", constraint

    def schema(self) -> str:
        raise NotImplementedError()

    def get_entry_value(self, entry, selector: str | None = None) -> Any:
        if selector is None:
            return entry

        value = getattr(entry, selector, None)
        if callable(value):
            value = value()
        return value


def list_intersection(iterable: Iterable) -> list:
    return list(reduce(set.intersection, (set(i) for i in iterable)))


def _format_special_field(field: model.SpecialField, key: str) -> tuple[str, str | None]:
    var = "$" + key
    # field_def = f"has {key} {var}"
    if field.regex is not None:
        # TODO because of this the handling must be specified the last field of the object;
        # - handle this better, so multiple special fields can co-exist
        return var, f'{var} like "{field.regex}"'
    elif field.is_variable:
        return var, None
    return "", None


def _get_variables_from_relations(relations: list[tuple[str, Thing]]) -> dict[str, list[str]]:
    mapping = defaultdict(list)
    for role, ref in relations:
        # there can be references for other types as will, these will be ignored
        # TQL notation is: `<relation>:<role>`
        if ":" in role:
            # ignore relation information for now
            # TODO check if relation information can be dropped
            _, role = role.split(":", 1)

        if ref is None:  # if no valid relation, then default to the role name as the variable
            ref = role
        mapping[role].append(to_kebab_case(str(ref)))

    return mapping
