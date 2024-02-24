import re
from typing import Any, List, Tuple, Union

from plum import dispatch

from binnacle import model
from binnacle.adapters.typedb.tql_builder import TqlBuilder
from binnacle.model import k8s_object as k8s
from binnacle.model.networking import NetworkPolicyPeer
from binnacle.model.primitives import Thing
from binnacle.utils import to_kebab_case

ENTITY_TYPE_PATTERN = re.compile(r"(?<!^)(?=[A-Z])")


def get_var_from_tql(tql: str) -> str | None:
    """Return the first variable from the given TQL.
    A variable starts witih the symbol '$'.

    :param tql: the TypeQL statement from where the variable will be extracted
    :return: the first variable in the TypeQL statement.
    :raises StopIteration: if no variable is found
    """
    var = next((word for word in tql.split(" ") if word.startswith("$")), None)
    return var.lstrip("$") if var is not None else var


QueryType = Union[str, List[str], TqlBuilder]


@dispatch  # type:ignore
def map_field(value: str, key: str) -> str:
    return f'has {key} "{value}"'


@dispatch  # type:ignore
def map_field(value: bool, key: str) -> str:
    return f"has {key} {str(value).lower()}"


@dispatch  # type:ignore
def map_field(field: model.SpecialField, key: str) -> str:
    """Map a special field to the corresponding TypeQL representation.
    The actual result depends on the properties set for the field

    :param field: the field that will be mapped
    :param key: the name of the field
    :return: the field in the TQL representation as string
    """
    var = "$" + key
    field_def = f"has {key} {var}"
    if field.regex is not None:
        # TODO because of this the handling must be specified the last field of the object;
        # - handle this better, so multiple special fields can co-exist
        return f'{field_def}; {var} like "{field.regex}"'
    elif field.is_variable:
        return field_def
    return ""


@dispatch  # type: ignore
def get_insert_query(obj: Thing) -> QueryType:
    """Promote a TypeQL representation of an object into a valid insert statement.
    This is the default function if no special treatment is required

    :param obj: the object for which the insert statement will be generated
    :return: the corresponding insert statement
    """
    tql = to_typeql(obj)

    #  TODO temporary workaround until migration is done!
    if type(tql) == list:
        tql = ", ".join(tql) + ";"

    return [f"insert {tql}"]


# @dispatch  # type: ignore
# def to_typeql(obj: k8s.K8sObject) -> QueryType:
#     logger.warning(f"to_typeql(K8sObject) is deprecated and shouldn't be called!")
#     entity_type = ENTITY_TYPE_PATTERN.sub("-", obj.kind).lower()
#     res_type = entity_type.replace("-", "")  # resource type is always in plural without any hyphens
#     lines = [
#         f"${entity_type} isa {entity_type}",
#         f'has kind "{obj.kind}"',
#         f'has resource-type "{res_type}s"',  # TODO: check this when resource ends with 's': this leads to  'ingresss'
#         map_field(obj.name, "name"),
#     ]

#     if obj.labels is not None:
#         lines += [f'has label "{k}:{v}"' for k, v in obj.labels.items()]
#     return lines
#     builder = TqlBuilder(obj)
#     return builder.as_tql()


# @dispatch   # type: ignore
# def to_typeql(obj: k8s.NamespacedObject) -> QueryType:
#     lines = to_typeql.invoke(k8s.K8sObject)(obj)
#     lines += [map_field(obj.ns, "ns")]
#     return lines


@dispatch  # type: ignore
def to_typeql(obj: Any, var_name: str | None = None, **vars: dict) -> str:
    return TqlBuilder(obj).set_variables(**vars).as_tql(var_name=var_name)



@dispatch  # type: ignore
def to_typeql(obj: NetworkPolicyPeer, var_name: str | None = None, **vars: dict) -> str:
    return TqlBuilder(obj).set_variables(**vars).as_tql(var_name=var_name, prefix_fields=True)

@dispatch  # type: ignore
def get_insert_query(pod: k8s.Pod) -> QueryType:
    pod_tql = TqlBuilder(pod).as_tql()
    queries = [f"insert {pod_tql}"]

    for i, container in enumerate(pod.containers):
        container_var = f"container_{container.name}"
        container_tql = TqlBuilder(container).as_tql(var_name=container_var, prefix_fields=True)
        queries.append(container_tql)

        contains = model.Contains(container=pod, thing=container)
        rel_var = f"contains_{container.name}"
        contains_tql = TqlBuilder(contains).set_variables(contains=rel_var, thing=container_var).as_tql()
        queries.append(contains_tql)

    # insert produces only 1 query per insert, so relation between objects can be done without matches
    return [" ".join(queries)]


@dispatch  # type: ignore
def get_insert_query(container: k8s.Container) -> QueryType:
    queries = []

    container_tql = to_typeql(container)
    queries.append(f"insert {container_tql}")

    # volume mounts
    if len(container.volume_mounts) > 0:
        mounts, mount_inserts = zip(*[get_insert_query(vm, container) for vm in container.volume_mounts])
        queries += mount_inserts

    return queries


# @dispatch   # type: ignore
# def to_typeql(container: k8s.Container) -> str:
#     attr_inserts = ""

#     lines = [
#         "$c isa container",
#         f'has container-name "{container.name}"',
#         f'has image-name "{container.image_name}"',
#     ]

#     # ports
#     if len(container.ports) > 0:
#         ports, port_inserts = zip(*[get_insert_query(p) for p in container.ports])
#         lines += [f"has port {p}" for p in ports]
#         attr_inserts += " ".join(port_inserts)

#     # env vars
#     # if len(container.env_vars) > 0:
#     #     env_vars, env_var_inserts = zip(
#     #         *[get_insert_query(p) for p in container.env_vars]
#     #     )
#     #     lines += [f"has env-var {e}" for e in env_vars]
#     #     attr_inserts += " ".join(env_var_inserts)

#     # # env from sources
#     # if len(container.env_from_sources or []) > 0:
#     #     envfroms, envfrom_inserts = zip(*[get_insert_query(p) for p in container.env_from_sources])
#     #     lines += [f"has env-from-source {e}" for e in envfroms]
#     #     attr_inserts += " ".join(envfrom_inserts)

#     core_container_tql = ", ".join(lines)
#     return f"{attr_inserts} {core_container_tql};".strip()


@dispatch  # type: ignore
def get_insert_query(role: k8s.Role) -> QueryType:
    # Note: the naming of the rule must match the one for formatting attributes in the TqlBuilder
    rule_queries = {f"$rule_{i}": to_typeql(r, f"rule_{i}") for i, r in enumerate(role.rules)}
    role_query = to_typeql(role)

    queries = list(rule_queries.values())
    queries.append(role_query)
    queries += [f"(owner: $role, entry: {rule_name}) isa ruleset;" for rule_name in rule_queries.keys()]

    return [f"insert {' '.join(queries)}"]


@dispatch  # type: ignore
def get_insert_query(role_binding: k8s.RoleBinding) -> QueryType:
    user_and_group_inserts = []

    role_ref_query = to_typeql(role_binding.role_ref)
    query = "match " + role_ref_query
    ref_var = get_var_from_tql(role_ref_query)

    player_references = [f"role-ref: ${ref_var}"]

    for i, sbj in enumerate(role_binding.subjects):
        var_name = f"subj_{i}"
        qry = to_typeql(sbj, var_name=var_name)

        # users and groups are defined outside of k8s and have to be inserted in
        # the KG in the context of role-bindings as there is no other reference
        if sbj.kind.lower() in ["user", "group"]:
            user_and_group_inserts.append(qry)
        query += " " + qry

        player_references.append(f"subject: ${var_name}")

    query += f'insert $rb ({", ".join(player_references)}) isa role-binding, '
    query += f'has name "{role_binding.name}", '
    query += f'has ns "{role_binding.namespace}";'

    if len(user_and_group_inserts) > 0:
        subj_inserts = "insert " + " ".join(user_and_group_inserts)
        return [subj_inserts, query]
    else:
        return [query]


@dispatch
def get_insert_query(rule: model.IngressRule, var_name: str) -> QueryType:
    path_var = f"{var_name}-path"
    backend_var = f"{var_name}-backend"
    tql = to_typeql(rule, var_name=var_name, path=path_var, backend=backend_var)

    path_tql = to_typeql(rule.path, var_name=path_var)
    backend_tqls = to_typeql(rule.backend, var_name=backend_var, port=f"{backend_var}_port")

    return [tql, path_tql, backend_tqls]


@dispatch  # type: ignore
def get_insert_query(ingress: model.Ingress) -> QueryType:
    ingress_query = to_typeql(ingress)
    rule_queries = {f"$rule_{i}": get_insert_query(r, f"rule_{i}") for i, r in enumerate(ingress.rules)}
    # rule_queries = {f"$rule_{i}": to_typeql(r, f"rule_{i}") for i, r in enumerate(ingress.rules)}

    queries = [q for r in rule_queries.values() for q in r]
    queries.append(ingress_query)

    # ingress is the owner of the ingress-ruleset
    # the rule-set contains all the ingress-rules
    queries += [f"(owner: $ingress, entry: {rule_name}) isa ingress-ruleset;" for rule_name in rule_queries.keys()]
    # rule_queries = [q for r in ingress.rules for q in to_typeql(r, ingress.name)]
    return [f"insert {' '.join(queries)}"]


@dispatch
def get_insert_query(rule: model.NetworkPolicyRule, var_name: str | None = None) -> QueryType:
    if var_name is None:
        var_name = to_kebab_case(type(rule).__name__)
    peer_var = f"{var_name}-peer"
    port_var = f"{var_name}-port"

    tql = to_typeql(rule, var_name=var_name, peer=peer_var, target_port=port_var)

    if rule.peers is None:
        peer_tqls = []
    elif len(rule.peers) == 1:
        peer_tqls = [to_typeql(rule.peers[0], var_name=peer_var)]
    else:
        peer_tqls = [to_typeql(p, var_name=f"{peer_var}_{i}") for i, p in enumerate(rule.peers)]

    if rule.ports is None:
        port_tqls = []
    elif len(rule.ports) == 1:
        port_tqls = [to_typeql(rule.ports[0], var_name=port_var)]
    else:
        port_tqls = [to_typeql(p, var_name=f"{port_var}_{i}") for i, p in enumerate(rule.ports)]
    # port_tqls = [to_typeql(p, var_name=f"{port_var}_{i}") for i, p in enumerate(rule.ports)] if rule.ports else []

    return [tql] + peer_tqls + port_tqls


@dispatch
def get_insert_query(network_policy: model.NetworkPolicy) -> QueryType:
    net_pol_query = to_typeql(network_policy)

    rule_queries = []
    rules = (network_policy.ingress_rules or []) + (network_policy.egress_rules or [])
    rule_queries = {f"$rule_{i}": get_insert_query(r, f"rule_{i}") for i, r in enumerate(rules)}
    # rule_queries = {f"$rule_{i}": to_typeql(r, f"rule_{i}") for i, r in enumerate(ingress.rules)}

    queries = [q for r in rule_queries.values() for q in r]
    queries.append(net_pol_query)

    # ingress is the owner of the ingress-ruleset
    # the rule-set contains all the ingress-rules
    queries += [
        f"(owner: $network-policy, entry: {rule_name}) isa network-policy-ruleset;" for rule_name in rule_queries.keys()
    ]
    # rule_queries = [q for r in ingress.rules for q in to_typeql(r, ingress.name)]
    return [f"insert {' '.join(queries)}"]


# @dispatch  # type: ignore
# def to_typeql(volume: k8s.Volume) -> QueryType:
#     if isinstance(volume.source, str):
#         src_insert = f'$vs isa tmp-volume-source; $vs "{volume.source}"; '  # not all volume sources are supported yet!
#     elif isinstance(volume.source, k8s.OtherVolumeSource):
#         src_insert = f'$vs isa tmp-volume-source; $vs "{volume.source.name} [{volume.source.type}]"; '  # not all volume sources are supported yet!
#     else:
#         src_insert = to_typeql(volume.source)
#     return f"{src_insert} " f'$v_{volume.name} isa volume, has name "{volume.name}", has $vs;'


# @dispatch # type: ignore
# def to_typeql(source: k8s.SecretVolumeSource) -> QueryType:
#     query = (
#         "$vs isa secret-volume-source; "
#         f'$vs "secret_vol_src_{source.secret_name}";'
#         f'$vs has secret-name "{source.secret_name}"'
#     )
#     if source.default_mode is not None:
#         query += f', has default-mode "{source.default_mode}"'

#     if source.is_optional is not None:
#         query += f", has secret-is-optional {str(source.is_optional).lower()}"

#     return query + ";"


# @dispatch  # type: ignore
# def to_typeql(source: k8s.ProjectedVolumeSource) -> QueryType:
#     src_name = str(source.sources[0])[:10] 
#     query = (
#         "$vs isa projected-volume-source; "
#         f'$vs "proj_vol_src_{src_name}";'
#         # f'$vs "secret_vol_src_{source.secret_name}";'
#         # f'$vs has secret-name "{source.secret_name}", '
#         # f'has secret-mode "{source.secret_mode}", '
#         # f'has secret-is-optional {str(source.is_optional).lower()};'
#     )
#     if source.default_mode is not None:
#         query += f'$vs has default-mode "{source.default_mode}"'
#     query += "; "

#     (
#         owned_var_names,
#         proj_insert_queries,
#     ) = zip(*[get_insert_query(src) for src in source.sources])
#     query += " ".join(proj_insert_queries)
#     query += " ".join([f" $vs has {v};" for v in owned_var_names])
#     return query


# @dispatch   # type: ignore
# def get_insert_query(proj: k8s.OtherProjection) -> Tuple[str, str]:
#     var = f"$vp_{round(random.random() * 10000)}"
#     # return f'$vp_{tid} isa tmp-volume-projection; $vp_{tid} "{self.value}";'
#     return var, f'{var} isa tmp-volume-projection; {var} "{proj.value}";'


# @dispatch   # type: ignore
# def get_insert_query(proj: k8s.SecretProjection) -> Tuple[str, str]:
#     spid = f"$sp_{proj.secret_name}"
#     qry = (
#         f"{spid} isa secret-projection;" f'{spid} "{proj.secret_name}";' f'{spid} has secret-name "{proj.secret_name}"'
#     )
#     if proj.is_optional is not None:
#         qry += f", has is-optional {str(proj.is_optional).lower()}"

#     for i in proj.items:
#         qry += f', has item "{i}"'

#     return spid, qry + "; "


# @dispatch   # type: ignore
# def get_insert_query(proj: k8s.ServiceAccountTokenProjection) -> Tuple[str, str]:
#     var = "$satp"
#     return var, (
#         f"{var} isa service-account-token-projection; "
#         f'{var} "satp"; '
#         f'{var} has audience "{proj.audience}", '
#         f"has expiration-seconds {proj.expiration_seconds}, "
#         f'has path "{proj.path}";'
#     )


# @dispatch   # type: ignore
# def get_insert_query(port: k8s.ContainerPort) -> Tuple[str, str]:
#     pid = f"$p_{port.container_port}"
#     val = port.name or str(port.container_port)
#     lines = [f'{pid} "{val}" isa port, has number {port.container_port}']
#     if port.name:
#         lines.append(f'has name "{port.name}"')
#     # , has name "{port.name}", has number {port.container_port};'
#     return pid, ", ".join(lines) + ";"


# @dispatch   # type: ignore
# def get_insert_query(env_var: k8s.EnvVar) -> Tuple[str, str]:
#     var = f"$ev-{env_var.name}"
#     val_query = ""

#     query = f'{var} "{env_var.name}" isa env-var'
#     if env_var.value_from is not None:
#         val_var, val_query = get_insert_query(env_var.value_from)
#         if val_var is not None:
#             query += f", has secret-key-ref {val_var}"
#     else:
#         query += f', has var-value "{env_var.value}"'

#     return var, f"{val_query} {query};"


# @dispatch   # type: ignore
# def get_insert_query(src: k8s.EnvVarSource) -> Tuple[str, str]:
#     if src.secret_key_ref is not None:
#         return get_insert_query(src.secret_key_ref)
#     else:
#         logger.warning(f"no reference found in value_from")
#     return "", ""


# @dispatch   # type: ignore
# def get_insert_query(src: k8s.SecretEnvSource) -> Tuple[str, str]:
#     var = f"$sr-{src.name}"
#     query = f'{var} "{src.name}" isa secret-env-source'
#     if src.is_optional is not None:
#         query += f", has is-optional {bool(src.is_optional)}"
#     return var, query + "; "


# @dispatch   # type: ignore
# def get_insert_query(src: k8s.ConfigMapEnvSource) -> Tuple[str, str]:
#     var = f"$cm-{src.name}"
#     query = f'{var} "{src.name}" isa configmap-env-source'
#     if src.is_optional is not None:
#         query += f", has is-optional {bool(src.is_optional)}"
#     raise NotImplemented("ConfigMapEnvSource is not yet supported")
#     return var, query + "; "


@dispatch  # type: ignore
def get_insert_query(sel: k8s.SecretKeySelector) -> Tuple[str, str]:
    name = sel.secret_name
    var = f"$sk-ref-{name}"
    query = f'{var} "{name}" isa secret-key-ref, has secret-name "{name}", has secret-key "{sel.key}";'
    return var, query


# @dispatch   # type: ignore
# def get_insert_query(src: k8s.EnvFromSource) -> Tuple[str, str]:
#     src_name = src.get_source_name()
#     var = f"$ef_{src_name}"

#     ref_insert = None
#     query = f'{var} "{src_name}" isa env-from-source'
#     if src.prefix is not None:
#         query += f', has prefix "{src.prefix}"'
#     if src.secret_ref is not None:
#         ref_var, ref_insert = get_insert_query(src.secret_ref)
#         query += f", has secret-env-source {ref_var}"  # $sr-{src.secret_ref.name}'
#     elif src.config_map_ref is not None:
#         ref_var, ref_insert = get_insert_query(src.config_map_ref)
#         query += f", has configmap-env-source {ref_var}"
#     else:
#         logger.error(f"No valid EnvSource found in EnvFromSource attribute '{src_name}'")

#     return var, f"{ref_insert} {query}; "


# @dispatch   # type: ignore
# def to_typeql(mount: k8s.VolumeMount) -> str:
#     var = f"$vol-mount-{mount.name}"
#     tql = (
#         f"{var} (user: $c, volume: $v) isa volume-mount, "
#         f'has name "{mount.name}", '
#         f'has mount-path "{mount.mount_path}"'
#     )
#     if mount.sub_path is not None:
#         tql += f', has sub-path "{mount.sub_path}"'
#     if mount.sub_path_expr is not None:
#         tql += f', has sub-path-expr "{mount.sub_path_expr}"'
#     return tql


@dispatch  # type: ignore
def get_insert_query(mount: k8s.VolumeMount, container: k8s.Container) -> Tuple[str, str]:
    builder = TqlBuilder(mount)
    mount_tql = builder.as_tql()

    var = get_var_from_tql(mount_tql)
    match_qry = (
        f'match $container isa container, has container-name "{container.name}"; '
        f'$volume isa volume, has name "{mount.name}"; '
    )

    return var, match_qry + "insert " + mount_tql


@dispatch  # type: ignore
def get_insert_query(contains: model.Contains) -> QueryType:
    if type(contains.container) == str:
        # if only the name is given, then a regex must be part of the match statement
        contains = contains.model_copy(deep=True)
        # replace the workload pattern with an actual reference to a workload object
        # ensure original object is immutable
        contains.container = model.Pod(
            name=model.SpecialField(regex=contains.container),
            namespace=model.SpecialField(is_variable=True),
        )

    container_tql = TqlBuilder(contains.container).as_tql()
    # in case the container has other children, pick only the main container and ignore the rest

    thing_tql = to_typeql(contains.thing)
    match_part = f"match {' '.join([container_tql, thing_tql])}"

    contains_tql = TqlBuilder(contains).as_tql()
    return [f"{match_part} insert {contains_tql}"]


