from __future__ import annotations

from enum import auto
from typing import Any

from pydantic import BaseModel
from strenum import LowercaseStrEnum

from binnacle.model.primitives import DomainObject, Relation


class Node(BaseModel):
    id: str | None = None
    name: str | None = None
    attributes: dict = {}
    type: str | None = None
    kind: str | None = None
    namespace: str | None = None
    parent: str | None = None  # the compound node containing this node
    part_of: str | None = None  # the compound node containing this node
    # mitigation: Mitigation | None = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.name is None:
            self.name = self.id
        elif self.id is None:
            name = self.name.lower().replace(" ", "_")
            self.id = f"{self.kind}/{name}" if self.kind is not None else name
            # self.id = self.name.lower().replace(" ", "_")
            # self.id = str(uuid.uuid4())


class Edge(BaseModel):
    source: str | Node
    target: str | Node
    relation: str | None = None
    attributes: dict = {}

    def __init__(self, **data: Any) -> None:
        # ensure only the id is used as reference
        if isinstance(data["source"], Node):
            data["source"] = data["source"].id
        if isinstance(data["target"], Node):
            data["target"] = data["target"].id

        super().__init__(**data)


# class Layer(BaseModel):
#     name: str | None = None
#     nodes: list[Node] = []
#     edges: list[Edge] = []


class Graph(DomainObject):
    """A graph is a collection of nodes and their relations.
    (Not implemented: A graph can also have a hierarchy, either explictely via 'layers')
    or implicitely by 'part-of'/'has-child' relations between nodes.

    :param DomainObject: the graph is part of the domain model
    """

    root_node_id: str | None = ""
    nodes: list[Node] = []
    edges: list[Edge] = []
    # layers: list[Layer] = []  # a subset of nodes and edges comprising the layer

    # def __getitem__(self, key: str, default: Any) -> Graph | Any:
    #     for l in self.layers:
    #         if l.name == key:
    #             return l
    #     return default

    # def add_layer(self, layer: Layer, index: int | None = None):
    #     if index is None:
    #         self.layers.append(layer)
    #     else:
    #         self.layers.insert(index, layer)


class GraphType(LowercaseStrEnum):
    Reachability = auto()
    Full = auto()

