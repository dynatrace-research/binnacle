from __future__ import annotations

import inspect
import ipaddress
import typing
from enum import auto
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from strenum import SnakeCaseStrEnum
from typing_extensions import Self  # for compatiability with Python <3.11

from binnacle.utils import to_kebab_case


class FieldConfig(SnakeCaseStrEnum):
    Alias = auto()  # str
    Exclude = auto()  # bool
    IsPassive = auto()  # bool
    IsRelatedBy = auto()  # bool
    Required = auto()  # bool
    Selector = auto()  # str
    Mergable = auto()  # bool
    RelationPart = auto()  # str


class RelationPart(SnakeCaseStrEnum):
    Source = auto()
    Target = auto()


def get_meta_infos(object: BaseModel) -> dict[str, Any]:
    # this seems to be the official approach to access annotated type info:
    # https://docs.python.org/3/library/typing.html#typing.Annotated
    cls = object if inspect.isclass(object) else object.__class__
    hints = typing.get_type_hints(cls, include_extras=True)
    res = {}

    for name, hint in hints.items():
        entries = getattr(hint, "__metadata__", {})
        meta = {}

        for entry in entries:
            match entry:
                case RelationPart():
                    # if isinstance(entry, RelationPart):
                    meta[FieldConfig.RelationPart] = entry
                case dict():
                    # use the entry as is
                    meta.update(entry)
                case _:
                    # assume it's just a boolean flag
                    meta[entry] = True

        res[name] = meta

    return res


def get_required_fields(obj: BaseModel) -> list[str]:
    meta_infos = get_meta_infos(obj)
    fields = [
        to_kebab_case(field.alias or name)
        for name, field in obj.model_fields.items()
        if meta_infos[name].get(FieldConfig.Required, False)
    ]
    return fields


def to_tql_name(field_name: str) -> str:
    return to_kebab_case(field_name)


class DomainObject(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()), exclude=True)
    model_config = ConfigDict(populate_by_name=True, alias_generator=to_tql_name)

    def __eq__(self, other):
        if other is None:
            return False
        return self.id == other.id

    def __hash__(self, *args):
        return hash(self.id)

    def __str__(self):
        return self.__class__.__name__


class Attribute(DomainObject):
    _value: Any | None = None

    @property
    def value(self):
        return self._value


class Thing(DomainObject):
    pass


class SpecialField(Thing):
    is_variable: bool = False
    regex: str | None = None


class Relation(DomainObject):
    kind: str | None = None
    label: str | None = None
    relates: dict[str, str | Thing | Any] = {}

    def __str__(self):
        return type(self).__name__


class Reference(Relation):
    label: str = "references"
    referrer: Annotated[DomainObject | None, RelationPart.Source] = None
    object: Annotated[DomainObject | None, RelationPart.Target] = None


class Asset(Thing):
    name: str


class Contains(Relation):
    # label = "contains"
    container: Annotated[str | Thing, RelationPart.Source] = "?"
    thing: Annotated[Thing | None, RelationPart.Target] = None


class Ruleset(Relation):
    # label = "contains"
    owner: Annotated[str | Thing, RelationPart.Target] = "?"
    entries: Annotated[list[Thing] | None, RelationPart.Target] = Field(None, alias="entry")

    def __iter__(self):
        return self.entries.__iter__()

    def __next__(self):
        return self.entries.__next__()


class Port(Attribute):
    id: str | None = Field(None, exclude=True)
    name: str | None = Field(None, alias="port-name")  # must be an IANA_SVC_NAME; name must be unique per pod
    number: int = Field(None, alias="port-number")

    @property
    def value(self):
        return self.id or self.name or str(self.number)

    @model_validator(mode="after")
    def at_least_name_or_number_must_be_set(cls, self: Self) -> Self:
        assert any([self.name, self.number])
        return self


class TargetPort(Port):
    pass


class LabelSelector(Attribute):
    entries: dict[str, str] = {}
    select_all: bool = Field(False, exclude=True)

    def items(self):
        if self.select_all:
            yield "*"
        else:
            yield from (f"{k}:{v}" for k, v in self.entries.items())

    @property
    def value(self):
        if self.select_all:
            return "*"
        else:
            return self.entries


class IpAddress(Attribute):
    ip: str | IPv4Address | IPv6Address = Field(..., exclude=True)  # exclude since it's the value itself
    ip_value: int | None = None

    @property
    def value(self) -> str:
        return str(self.ip)

    @model_validator(mode="after")
    def compute_ip_value(cls, self: Self) -> Self:
        if self.ip_value is None:
            self.ip_value = int(self.ip)
        return self

    @field_validator("ip")
    def convert_ip_to_ipaddress(cls, value: str | IPv4Address | IPv6Address):
        return ipaddress.ip_address(value)


class Cidr(Attribute):
    cidr: str = Field(..., exclude=True)
    min_ip_value: int | None = None
    max_ip_value: int | None = None

    @model_validator(mode="after")
    def set_min_max_ip_values(cls, self: Self) -> Self:
        net = ipaddress.IPv4Network(self.cidr, strict=False)
        # ip, subnet = self.cidr.split("/", maxsplit=1)
        self.min_ip_value = int(net[0])
        self.max_ip_value = int(net[-1])
        return self

    @property
    def value(self):
        return self.cidr


class PodCidr(Cidr):  # TODO remove once types are properly used in TQL statement
    pass
