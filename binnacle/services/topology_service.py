from collections import defaultdict

from loguru import logger

from binnacle import model
from binnacle.model.graph import GraphType, TopologyGraph
from binnacle.services.graph_utils import get_source_and_target_field_names
from binnacle.services.unit_of_work import AbstractDatabaseUnitOfWork


def get_topology(
    uow: AbstractDatabaseUnitOfWork,
    namespaces: list[str] | None = None,
    exclude_namespaces: list[str] | None = None,
    simplified: bool = False,
    detailed: bool = False,
    include_infra: bool = True,
    type: GraphType = GraphType.Full,
) -> TopologyGraph:
    """Generate a topology graph for specified namespaces.

    :param uow: the unit of work to handle the queries to the knowledge base
    :param namespaces: an optional list of namespaces to include.
        If no namespaces are specified the topology will span the entire cluster.
    :param simplified: flag if the resulting topology reduces exact K8s objects to their corresponding micro-service.
    :param detailed: if simplified is true, then actual K8s objects will be kept alongside the abstracted micro-services.
    :param type: the type of graph to infer.
    :return: the generated topology as graph
    """

    if exclude_namespaces is None:
        exclude_namespaces = ["kube-system", "local-path-storage"]

    queries = [
        # get_objects_selecting_pods_query(namespaces=namespaces),
        get_pods_in_scope(namespaces=namespaces, exclude_namespaces=exclude_namespaces),
        get_configured_service_topology_query(namespaces=namespaces, exclude_namespaces=exclude_namespaces),
        get_configured_routes_query(namespaces=namespaces, exclude_namespaces=exclude_namespaces),
        get_possible_connections_query(
            namespaces=namespaces, exclude_namespaces=exclude_namespaces, include_infra=include_infra
        ),
        get_conncections_allowed_by_network_policies_query(
            namespaces=namespaces, exclude_namespaces=exclude_namespaces
        ),
        "match $rel ($inet) isa relation; $inet isa internet;"
        # get_managing_workloads_query(namespaces=namespaces),
    ]

    if include_infra:
        queries.append("match $c ($node) isa can-reach; $node isa cluster-node, has name $name;")

    with uow:
        # res = uow.query(model.Route, model.Thing).where
        # queries = TqlBuilder(model.Route).as_get_query(**kwargs, as_single_query=False)

        objects = uow.query_str(queries)
        # service_topology_objects = uow.query(get_configured_service_topology_query(namespaces=namespaces))
        # route_objects = uow.query(get_configured_routes_query(namespaces=namespaces))
        # possible_connection_objects = uow.query(get_possible_connections_query(namespaces=namespaces))
    # objects = service_topology_objects + route_objects + possible_connection_objects

    # graph = convert_to_graph(objects)

    # graph = convert_to_graph(micro_services, micro_service_relations, detailed=detailed)
    # graph.layers.append(Layer(name="microservices", nodes=micro_services, edges=micro_service_relations))

    if simplified:
        nodes, edges = aggregate_objects_to_microservices(objects, detailed=detailed)
    else:
        nodes, edges = partition_entites_and_relations(objects)

        # graph = convert_to_graph(micro_services, micro_service_relations, detailed=detailed)
    graph = TopologyGraph(nodes=nodes, edges=edges)
    return graph
    # return micro_services, micro_service_relations


def _apply_ns_filter(
    vars: str | list[str], namespaces: list[str] | None, exclude_namespaces: list[str] | None = None
) -> list[str]:
    if namespaces is None:
        namespaces = []
    if exclude_namespaces is None:
        exclude_namespaces = []

    query_parts = []

    if isinstance(vars, str):
        vars = [vars]

    for var in vars:
        ns_conditions = [f'{{ {var} == "{ns}"; }}' for ns in namespaces]
        ns_filter = " or ".join(ns_conditions)
        if ns_filter:
            query_parts.append(ns_filter + ";")

        for excl_ns in exclude_namespaces:
            query_parts.append(f'not {{ {var} == "{excl_ns}"; }};')

    return query_parts


def get_pods_in_scope(
    namespaces: list[str] | None = None,
    exclude_namespaces: list[str] | None = None,
):
    query_parts = [
        "$pod isa pod, has name $name, has ns $ns, has label $label, has ns $ns-name;",
        # "$namespace isa namespace, has name $ns-name;",
        # "$ns-name == $ns;",
    ]
    # query_parts += _apply_ns_filter(["$ns"], namespaces=namespaces, exclude_namespaces=exclude_namespaces)
    query_parts += _apply_ns_filter(["$ns-name"], namespaces=namespaces, exclude_namespaces=exclude_namespaces)

    return "match " + "".join(query_parts)


def get_possible_connections_query(
    namespaces: list[str] | None = None,
    exclude_namespaces: list[str] | None = None,
    include_infra: bool = False,
) -> str:
    """Get a query for all possible connections between workloads within the given scope.

    :param namespaces: an optional list of namespaces to include.
        If no namespaces are specified the scope will span the entire cluster.
    :param include_infra: flag if possible connections to nodes
    :return: the query to retrieve all possible connections
    """
    query_parts = [
        "$c (source: $src-pod, destination: $dst-pod) isa! can-reach;",
        "$src-pod isa pod, has name $src-name, has ns $src-ns;",
        "$dst-pod isa pod, has name $dst-name, has ns $dst-ns;",
    ]
    query_parts += _apply_ns_filter(
        ["$src-ns", "$dst-ns"], namespaces=namespaces, exclude_namespaces=exclude_namespaces
    )

    return "match " + "".join(query_parts)


def get_configured_routes_query(
    namespaces: list[str] | None = None, exclude_namespaces: list[str] | None = None
) -> str:
    """Get a query of all configured routes within the scope.

    :param namespaces: an optional list of namespaces to include.
        If no namespaces are specified the scope will span the entire cluster.
    :return: the query to retrieve all configured routes within the scope
    """
    query_parts = [
        "$route ($object) isa route;",
        "$object has name $object-name, has ns $object-ns, has label $object-lbl;",
        f'$object-lbl has key "{model.RecommendedLabel.Name}";',
    ]
    query_parts += _apply_ns_filter("$object-ns", namespaces=namespaces, exclude_namespaces=exclude_namespaces)

    return "match " + "".join(query_parts)


def get_conncections_allowed_by_network_policies_query(
    namespaces: list[str] | None = None, exclude_namespaces: list[str] | None = None
) -> str:
    """Get a query of all configured routes within the scope.

    :param namespaces: an optional list of namespaces to include.
        If no namespaces are specified the scope will span the entire cluster.
    :return: the query to retrieve all configured routes within the scope
    """
    query_parts = [
        "$c (source: $src, destination: $dst) isa connection-allowed-by-network-policy;",
        # "$object has name $object-name, has ns $object-ns, has label $object-lbl;",
        "$src has name $src-name, has ns $src-ns;",
        "$dst has name $dst-name, has ns $dst-ns;",
        # f'$object-lbl has key "{model.RecommendedLabel.Name}";',
    ]
    query_parts += _apply_ns_filter(
        ["$src-ns", "$dst-ns"], namespaces=namespaces, exclude_namespaces=exclude_namespaces
    )

    return "match " + "".join(query_parts)


def get_configured_service_topology_query(
    namespaces: list[str] | None = None, exclude_namespaces: list[str] | None = None
) -> str:
    """Get a query to retrieve the configered topology.
        This topology is inferred from the workloads referencing other services.

    :param namespaces: an optional list of namespaces to include.
        If no namespaces are specified the scope will span the entire cluster.
    :return: the query to retrieve the configured topology
    """
    query_parts = [
        "$ref (referrer: $pod, object: $svc) isa reference;",
        "$pod isa pod, has name $pod-name, has ns $pod-ns, has label $pod-lbl;",
        "$svc isa service, has name $svc-name, has ns $svc-ns, has label $svc-lbl;",
        f'$pod-lbl has key "{model.RecommendedLabel.Name}";',
        f'$svc-lbl has key "{model.RecommendedLabel.Name}";',
    ]
    query_parts += _apply_ns_filter("$svc-ns", namespaces=namespaces, exclude_namespaces=exclude_namespaces)

    return "match " + "".join(query_parts)


def get_managing_workloads_query(
    namespaces: list[str] | None = None, excluded_namespaces: list[str] | None = None
) -> str:
    query_parts = [
        "$wl isa workload, has ns $wl-ns;",
        "$manages (manager: $wl, resource: $pod) isa manages;",
        "$pod isa pod;",
    ]
    query_parts += _apply_ns_filter("$wl-ns", namespaces=namespaces, exclude_namespaces=excluded_namespaces)

    return "match " + "".join(query_parts)


def partition_entites_and_relations(
    objects: list[model.DomainObject],
) -> tuple[list[model.Thing], list[model.Relation]]:
    entities, relations = [], []

    for obj in objects:
        if isinstance(obj, model.NamespacedObject):
            entities.append(obj)
        elif isinstance(obj, model.LabelSelection):
            pass  # ignore: this relationship is only relevant within the objects
        elif isinstance(obj, model.Relation):
            relations.append(obj)
        elif isinstance(obj, (model.K8sObject, model.Internet)):
            entities.append(obj)
        else:
            name = getattr(obj, "name", str(obj))
            logger.info(
                f"Skipping '{name}' ({obj.kind}) for partitioning to entities and relations, because unclear how to handle it."
            )
    return entities, relations


def aggregate_objects_to_microservices(
    objects: list[model.DomainObject],
    detailed: bool = False,
) -> tuple[list[model.MicroService], list[model.Relation]]:
    """Group several objects into MicroServices. The membership is determinaed by several criteria in this order:
    1) if recommended 'name' label is present on the object: use this as the microservice name
    2) if the object is not controlled by another resources, use its name  (t.b.d)
    3) if the resources is controlled by another resources, use the owners name (e.g. Replicaset: use Deployment name) (t.b.d)

    :param objects: a list of objects, which will be grouped to microservices
    :param detailed: if True keep the original resources which are part of a microservice as well and add a refernce to it
    :return: a tuple of a list of inferred microservices and (transitive) relations
    """
    ms_groups = defaultdict(list)
    non_ms_entities = []
    entities, relations = partition_entites_and_relations(objects)

    for e in entities:
        if not isinstance(e, (model.Pod, model.Workload, model.Service)):
            non_ms_entities.append(e)
            continue

        ms_name = infer_microservice_name(obj=e)
        if ms_name is not None:
            ms_groups[ms_name].append(e)
        else:
            logger.warning(f"Can't determine microservice name of object '{e.name}' ({e.kind})")

    micro_services = []
    for name, parts in ms_groups.items():
        ms = model.MicroService(id=name, name=name)

        for part in parts:
            # the actual pod(s) determine the associated namespace of the MicroService
            if ms.namespace is None:
                ms.namespace = part.namespace
            match type(part):
                case model.Pod:
                    ms.pods.append(part)
            ms.objects.append(part)
            part.part_of = ms  # set back-ref to the parent MicroService
        micro_services.append(ms)

    transitive_relations = infer_transitive_relations_from_objects_to_microservice(relations)

    if detailed:
        return micro_services + entities, relations
        # return micro_services + entities, relations + transitive_relations
    else:
        return micro_services, transitive_relations


def infer_microservice_name(obj: model.K8sObject) -> str:
    """Infer the name of the objects micro-service following several heuristics until first success:
    1) if recommended label 'Name' label is present, use this for the micro-service name
    2) (t.b.d) if it is a service and references a pod, use the pods micro-service name
    3) (t.b.d) if it is a workload controlling a pod, use its own name
    4) (t.b.d) if the object is controlled by another resource, use the controlling objects' micro-service name
    5) otherwise: use the name of the object itself

    :param obj: the object for which the name of its micro-service will be inferred
    :return: the inferred name of the micro-service
    """
    # 1. heuristic
    name_label = obj.labels.get(model.RecommendedLabel.Name, None)
    if name_label is not None:
        return name_label.data

    # 5. fallback to own name
    return obj.name


def infer_transitive_relations_from_objects_to_microservice(relations: list[model.Relation]) -> list[model.Relation]:
    """Infer relations among basic objects also on the micro-service level.
    For this the corresponding 'part_of' field on the K8s objects has to be set to the respective micro-service.

    :param relations: list of relations between the Kubernetes objects
    :return: a list of inferred transitive relations
    """
    trans_relations = []

    for relation in relations:
        source_name, target_name = get_source_and_target_field_names(relation)
        if source_name is None or target_name is None:
            logger.debug(f"Could not get the source and target field names of {relation}")
            continue  # skip incomplete relations, as these most likely point to objects, which are out of scope

        source = getattr(relation, source_name)
        target = getattr(relation, target_name)

        if not isinstance(source, model.MicroService) and not isinstance(target, model.MicroService):
            continue  # if no
        elif source is None or target is None:
            continue  # skip incomplete relations, as these most likely point to objects, which are out of scope

        # skip all relations within the micro-service as they are not of interest at a higher level
        if hasattr(source, "part_of") and hasattr(target, "part_of") and source.part_of == target.part_of:
            continue

        # Pydantic v1 runs into MaxRecursion Exception problems with recursive model
        # workaround: copy set fields from old relation and initialize new object with update source and target
        values = {k: getattr(relation, k) for k in relation.__fields_set__}
        values[source_name] = getattr(source, "part_of", source)
        values[target_name] = getattr(target, "part_of", target)
        r = type(relation)(**values)
        trans_relations.append(r)

    return trans_relations
