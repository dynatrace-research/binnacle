from collections import defaultdict
from typing import Any, Callable, List, Type

import matplotlib.pyplot as plt
import networkx as nx
from diagrams import Cluster, Diagram
from diagrams import Edge as DiagramEdge
from diagrams import Node as DiagramNode
from diagrams.k8s.compute import Deployment, Pod
from diagrams.k8s.group import Namespace
from diagrams.k8s.network import Ingress, Service
from loguru import logger
from plum import dispatch

from binnacle import model
from binnacle.adapters.typedb.tql_builder import is_primitive
from binnacle.model.graph import Edge, Graph, Node
from binnacle.model.primitives import DomainObject, FieldConfig, RelationPart
from binnacle.utils import to_kebab_case


@dispatch
def get_edges_from_object(obj: DomainObject) -> List[Edge]:
    """Look at all fields of a domain object and create an edge for every reference
    to another complex object. If the field is a passive, then it will be the target of the edge.

    :param obj: the object from which edges will be retrieved
    :return: a list of retrieved edges
    """
    edges = []
    meta_infos = model.get_meta_infos(obj)
    for name, field in ((n, f) for n, f in obj.model_fields.items() if not is_primitive(f)):
        value = getattr(obj, name)
        if value is None or name == "targets":
            continue

        # ensure the mapping is a dict, where the key is the label
        rel_mapping = value
        edge_label = field.alias or name
        if isinstance(value, (model.Relation, model.Thing)):
            rel_mapping = {edge_label: value}
        elif isinstance(value, list):
            rel_mapping = {edge_label: v for v in value}

        is_passive = meta_infos[name].get(model.FieldConfig.IsPassive, False)
        for label, value in rel_mapping.items():
            source_id, target_id = obj.id, value.id
            if is_passive:  # flip direction when it's a passive relation
                source_id, target_id = target_id, source_id
            edges.append(Edge(source=source_id, target=target_id, relation=label))

    return edges


@dispatch
def get_edges_from_object(obj: model.Relation) -> List[Edge]:
    source, target = get_source_and_target(obj)

    # if not both 'source' and 'target' then the connection is 'out of scope'
    if source is None or target is None:
        return get_edges_from_object.invoke(DomainObject)(obj)

    obj_type = to_kebab_case(obj.__class__.__name__)
    return [Edge(source=source.id, target=target.id, relation=obj_type)]


def get_source_and_target(relation: model.Relation) -> tuple[None | DomainObject, None | DomainObject]:
    """Retrieve the source and target objects from a relation if possible.
    The corresponding source and target are identified by the RelationPart FieldConfig.

    :param relation: the relation from which the source and target will be returned
    :return: a tuple containing the source and the target of the relation
    """
    source, target = None, None
    source_name, target_name = get_source_and_target_field_names(relation)
    if source_name is not None:
        source = getattr(relation, source_name)
    if target_name is not None:
        target = getattr(relation, target_name)
    return source, target


def get_source_and_target_field_names(relation: model.Relation) -> tuple[str | None, str | None]:
    """Retrieve the field names of the source and target objects from a relation if possible.
    The corresponding source and target names are identified by the RelationPart FieldConfig and only if they are not passive.

    :param relation: the relation from which the field names will be returned
    :return: a tuple containing the names of source and the target of the relation
    """
    # TODO handle case when there are multiple sources/targets defined
    source_name, target_name = None, None
    meta_infos = model.get_meta_infos(relation)
    for name, f in relation.model_fields.items():
        is_passive = meta_infos[name].get(FieldConfig.IsPassive, False)
        if not is_passive and (relation_part := meta_infos[name].get(FieldConfig.RelationPart, None)):
            # if relation_part := f.field_info.extra.get(FieldConfig.RelationPart, None):
            match relation_part:
                case RelationPart.Source:
                    source_name = name
                case RelationPart.Target:
                    target_name = name

    return source_name, target_name


def convert_graph_to_nx(graph: Graph) -> nx.DiGraph:
    """Convert the given graph to a NetworkX Digraph

    :param graph: the graph, which will be converted
    :return: the converted NetworkX graph
    """
    g = nx.MultiDiGraph()

    nodes = [(n.id, n.attributes) for n in graph.nodes]
    # nodes = [(n.id, n.dict() | n.attributes) for n in graph.nodes]
    g.add_nodes_from(nodes)
    edges = [(e.source, e.target, {"label": e.relation} | e.attributes) for e in graph.edges]
    g.add_edges_from(edges)

    return g


def convert_to_reachability_graph(entities: list[model.Thing], relations: list[model.Relation]) -> Graph:
    nodes = [Node(id=readable_id(e), name=e.name, kind=e.kind, namespace=e.namespace) for e in entities]
    edges = [
        Edge(
            source=readable_id(r.source),
            target=readable_id(r.destination),
            relation=str(r),
            attributes={"port": 0},
        )
        for r in relations
        if isinstance(r, model.CanReach) and r.source is not None and r.destination is not None
    ]
    graph = Graph(nodes=nodes, edges=edges)
    return graph


@dispatch
def readable_id(obj: model.NamespacedObject) -> str:
    return f"{obj.namespace}:{obj.kind}/{obj.name}"


def convert_to_graph(
    objects: list[model.MicroService], relations: list[model.Relation], detailed: bool = False
) -> Graph:
    nodes = []
    edges = []

    for obj in objects:
        part_of = obj.part_of.id if getattr(obj, "part_of", None) is not None else None
        ns = getattr(obj, "namespace", None)
        if part_of is None and ns is not None:
            part_of = ns
            # part_of = f"namespace/{ns}"
        kind = getattr(obj, "kind", None)
        name = getattr(obj, "name", str(obj))

        # TODO: temporary workaround to get compound nodes for namespaces
        # node_id = obj.id if not isinstance(obj, model.Namespace) else f"{obj.kind}/{obj.name}"
        node_id = obj.id
        nodes.append(
            Node(
                id=node_id,
                type=str(obj),
                name=name,
                kind=kind,
                namespace=ns,
                part_of=part_of,
                parent=part_of,
            )
        )

        if detailed:
            for obj in obj.pods + obj.objects:
                if isinstance(obj, model.K8sObject):
                    node_type = obj.kind
                    kind = obj.kind
                    part_of = obj.part_of.name if obj.part_of else None
                    nodes.append(Node(id=obj.id, type=node_type, name=obj.name, kind=kind, part_of=part_of))
                else:
                    logger.warning(f"Can't convert {obj.kind} to either node or edge")

    for relation in relations:
        new_edges = get_edges_from_object(relation)
        for e in new_edges:
            if e.relation == "reference":
                e.attributes["weight"] = 100
            elif e.relation is not None and e.relation.startswith("can-reach"):
                color = "#a9a9a970"
                e.attributes["style"] = "dashed"
                e.attributes["color"] = color
                e.attributes["fontcolor"] = color
                e.attributes["constraint"] = "false"
        edges += new_edges

    graph = Graph(nodes=nodes, edges=edges)
    # graph.root_node_id = "unguard-ingress"  # TODO remove this manually set root node
    return graph


def generate_image(graph: Graph, file_path: str = "graph.png") -> str:
    """Generates an image visualizing the provided graph.
    The image will be stored at the location specified with `file_path`

    :param graph: the graph to visualize
    :param file_path: the path for the resulting image, defaults to "graph.png"
    :return: the path to the resulting image
    """
    if isinstance(graph, model.Graph):
        graph = convert_to_graph(graph.nodes, graph.edges)
    g = convert_graph_to_nx(graph)
    node_labels = {n.id: n.name for n in graph.nodes}
    edge_labels = {(e.source, e.target): e.relation for e in graph.edges}
    # pos = nx.spring_layout(g, scale=1000)
    # pos = nx.nx_pydot.pydot_layout(g, root=graph.root_node_id, prog="dot")

    pos = nx.nx_agraph.pygraphviz_layout(g, root="ingress", prog="dot")

    plt.figure(1, (15, 10), dpi=200)
    nx.draw_networkx(g, pos=pos, labels=node_labels, node_size=80, verticalalignment="bottom")
    nx.draw_networkx_edge_labels(g, pos, edge_labels=edge_labels)

    A = nx.nx_agraph.to_agraph(g)

    print(A.string())

    plt.tight_layout(pad=0)
    plt.savefig(file_path)

    return file_path


def generate_diagram(graph: model.Graph, name: str, max_level: int = 100) -> str:
    file_path = ""

    graph_attr = {
        "layout": "dot",
        # "concentrate": "true",  # sadly, this combines edges of different types, so it results in false information :()
        "compound": "true",
        "ordering": "in",
        "nodesep": "0.25",  # keep compact to avoid edges flailing around
        # "splines": "ortho",
        "splines": "spline",
    }

    with Diagram(name=name, graph_attr=graph_attr):
        # with Diagram(name=name, graph_attr=graph_attr, outformat=["png", "dot"], filename="testing_topo"):
        created_nodes = draw_diagram_layer(graph.nodes, max_level=max_level)

        for edge in graph.edges:
            source, target = get_source_and_target(edge)
            src_node = created_nodes[source.id]
            target_node = created_nodes[target.id]

            edge_attrs = {}

            # connecting clusters doesn't work out of the box
            # for clusters a node in the cluster has to be used as proxy
            # see issue: https://github.com/mingrammer/diagrams/issues/452
            if isinstance(src_node, Cluster):
                edge_attrs["ltail"] = src_node.name
                src_node = created_nodes[source.objects[0].id]
            if isinstance(target_node, Cluster):
                edge_attrs["lhead"] = target_node.name
                target_node = created_nodes[target.objects[0].id]

            edge_label = edge.label or edge.kind or ""

            # put the edges for possible reachability into the background
            if isinstance(edge, model.CanReach):
                color = "#a9a9a970"
                edge_attrs["style"] = "dashed"
                edge_attrs["color"] = color
                edge_attrs["fontcolor"] = color
                edge_attrs["constraint"] = "false"  # exclude it from the layouting
            elif isinstance(edge, model.Route):
                edge_attrs["minlen"] = "2"

            src_node >> DiagramEdge(xlabel=edge_label, **edge_attrs) >> target_node

    return file_path


def drop_dangling_edges(graph: Graph) -> Graph:
    """For a valid graph all referenced nodes and edges must match up.
    Any edges, which point node ids which are not part of the graph will be dropped.

    :param graph: the graph containing a set of nodes and edges, which will be validated
    :return: a 'cleaned' version of the graph
    """
    node_ids = {n.id for n in graph.nodes}
    cleaned_edges = [e for e in graph.edges if e.source in node_ids and e.target in node_ids]

    num_dropped_edges = len(graph.edges) - len(cleaned_edges)
    if num_dropped_edges > 0:
        logger.debug(f"Dropped {num_dropped_edges} dangling edges from graph")

    return Graph(root_node_id=graph.root_node_id, nodes=graph.nodes, edges=cleaned_edges)


def groupby(iter: list[Any], pred: Callable) -> dict[str, Any]:
    groups = defaultdict(list)
    for i in iter:
        groups[pred(i)].append(i)
    return groups


def draw_diagram_layer(
    elements: list[model.Thing], current_level: int = 1, max_level: int = 100
) -> dict[str, DiagramNode]:
    """Draw nodes in the diagram, which determine the effective layout.
    Nodes are grouped by their namespace (if the are ns-scoped).

    :param elements: all nodes which will be added to the diagram
    :param current_level: the current layer level, defaults to 1
    :param max_level: the maximum number of layers, defaults to 100
    :return: a dict of created nodes
    """
    created_nodes = {}
    namespaces = groupby(elements, lambda x: x.namespace)

    for group, group_elements in namespaces.items():
        if group is not None:
            with Cluster(group):
                created_nodes |= draw_nodes(group_elements, current_level=current_level, max_level=max_level)
        else:  # cluster scoped elements have no namespace
            created_nodes |= draw_nodes(group_elements, current_level=current_level, max_level=max_level)

    return created_nodes


def draw_nodes(elements: list, current_level: int = 1, max_level: int = 100) -> dict:
    """Draw the given nodes in the diagram

    :param elements: all nodes which will be added to the diagram
    :param current_level: the current layer level, defaults to 1
    :param max_level: the maximum number of layers, defaults to 100
    :return: a dict of created nodes
    """
    created_nodes = {}
    for element in elements:
        sub_elements = getattr(element, "objects", [])

        if len(sub_elements) > 0 and current_level < max_level:
            with Cluster(label=getattr(element, "name", "?")) as cluster:
                created_nodes |= draw_diagram_layer(sub_elements, current_level=current_level + 1, max_level=max_level)
            created_nodes[element.id] = cluster
        else:
            node_ctor = get_node_constructor(element)
            # simply calling the constructur adds it to the parent cluster, as its within that context mngr
            label = getattr(element, "name") or element.id
            node = node_ctor(node_id=element.id, label=label)
            created_nodes[element.id] = node
    return created_nodes


def get_node_constructor(element: model.Thing) -> Type[DiagramNode]:
    match element:
        case model.Pod():
            return Pod
        case model.MicroService():
            if element.name == "ingress":
                return Ingress
            return Pod
        case model.Deployment():
            return Deployment
        case model.Service():
            return Service
        case model.Namespace():
            return Namespace
        case model.Ingress():
            return Ingress
    return DiagramNode
