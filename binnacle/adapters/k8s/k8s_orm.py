from enum import auto
from typing import Any

import kubernetes.client as k8s
from loguru import logger
from plum import dispatch
from strenum import StrEnum

import binnacle.model as model


def _parse_base(obj: Any):
    owner_refs = [parse_owner_reference(r) for r in obj.metadata.owner_references or []]

    labels = obj.metadata.labels
    if labels is not None:
        labels = {k: model.Label(key=k, data=v) for k, v in labels.items()}
    else:
        labels = {}
    data = {
        "name": obj.metadata.name,
        # "api_version": obj.api_version,
        "ns": obj.metadata.namespace,
        "annotations": obj.metadata.annotations,
        "labels": labels,
        "id": obj.metadata.uid,
        "owner_references": owner_refs,
    }
    return data


def parse_local_object_reference(ref: k8s.V1LocalObjectReference) -> model.ObjectReference:
    return model.ObjectReference()


def parse_owner_reference(ref: k8s.V1OwnerReference) -> model.OwnerReference:
    return model.OwnerReference(name=ref.name, kind=ref.kind, uid=ref.uid)


def parse_daemon_endpoints(endpoints: k8s.V1NodeDaemonEndpoints) -> dict[str, model.DaemonEndpoint]:
    eps = {}
    if hasattr(endpoints, "kubelet_endpoint"):
        eps["kubelet"] = model.KubeletEndpoint(port=endpoints.kubelet_endpoint.port)
    return eps


class NodeAddressType(StrEnum):
    Hostname = auto()
    InternalIP = auto()
    ExternalIP = auto()
    InternalDNS = auto()
    ExternalDNS = auto()


@dispatch
def parse_k8s_object(obj: k8s.V1Node) -> model.ClusterNode:
    base = _parse_base(obj)

    node_addresses = {}
    for a in obj.status.addresses:
        address_type = NodeAddressType(a.type)
        node_addresses[address_type] = (
            model.IpAddress(ip=a.address)
            if address_type in (NodeAddressType.InternalIP, NodeAddressType.ExternalIP)
            else a.address
        )

    # daemon_endpoints = parse_daemon_endpoints(obj.status.daemon_endpoints)

    return model.ClusterNode(
        **base,
        pod_cidr=model.PodCidr(cidr=obj.spec.pod_cidr) if obj.spec.pod_cidr else None,
        kernel_version=obj.status.node_info.kernel_version,
        kube_proxy_version=obj.status.node_info.kube_proxy_version,
        kubelet_version=obj.status.node_info.kubelet_version,
        os=obj.status.node_info.operating_system,
        os_image=obj.status.node_info.os_image,
        internal_ip=node_addresses.get(NodeAddressType.InternalIP, None),
        internal_dns=node_addresses.get(NodeAddressType.InternalDNS, None),
        external_ip=node_addresses.get(NodeAddressType.ExternalIP, None),
        external_dns=node_addresses.get(NodeAddressType.ExternalDNS, None),
        hostname=node_addresses.get(NodeAddressType.Hostname, None),
    )


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1Namespace) -> model.Namespace:
    """Convert a Namespace K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    base = _parse_base(obj)
    return model.Namespace(**dict(base))


def parse_secret_key_selector(selector: k8s.V1SecretKeySelector) -> model.SecretKeySelector:
    """Convert a K8s secret key selector into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    return model.SecretKeySelector(secret_name=selector.name, secret_key=selector.key, is_optional=selector.optional)


def parse_env_var_source(source: k8s.V1EnvVarSource) -> model.EnvVarSource:
    """Convert a K8s EnvVarSource into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    if source.secret_key_ref is not None:
        secret_key_ref = parse_secret_key_selector(source.secret_key_ref)
    else:
        secret_key_ref = None
        logger.info("ConfigMapKeyRef, FieldRef and ResourceFieldRef are not yet supported by EnvVarSource!")

    return model.EnvVarSource(
        secret_key_ref=secret_key_ref,
    )


def parse_env_var(env_var: k8s.V1EnvVar) -> model.EnvVar:
    """Convert a K8s EnvVar into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    value_from = parse_env_var_source(env_var.value_from) if env_var.value_from is not None else None

    var_value = (
        None if env_var.value is None else env_var.value.replace('"', "'").encode("unicode_escape").decode("utf-8")
    )
    return model.EnvVar(name=env_var.name, var_value=var_value, value_from=value_from)


def parse_volume_mount(mount: k8s.V1VolumeMount) -> model.VolumeMount:
    """Convert a K8s volume Mount into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    return model.VolumeMount(
        name=mount.name,
        mount_path=mount.mount_path,
        is_read_only=mount.read_only,
        sub_path=mount.sub_path,
        sub_path_expr=mount.sub_path_expr,
    )


def parse_config_map_env_source(env_source: k8s.V1ConfigMapEnvSource) -> model.ConfigMapEnvSource:
    """Convert a K8s ConfigMap EnvSource into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    return model.ConfigMapEnvSource(name=env_source.name, is_optional=env_source.optional)


def parse_secret_env_source(env_source: k8s.V1SecretEnvSource) -> model.SecretEnvSource:
    """Convert a K8s Secret EnvSource into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    return model.SecretEnvSource(name=env_source.name, is_optional=env_source.optional)


def parse_env_from_source(env_from_source: k8s.V1EnvFromSource) -> model.EnvFromSource:
    """Convert a K8s EnvFromSource into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    # self.secret_ref = env_from_source.secret_ref
    # TODO support ConfigMapref
    # config_map_ref = (
    #     None if env_from_source.config_map_ref is None else parse_config_map_env_source(env_from_source.config_map_ref)
    # )
    config_map_ref = None
    secret_ref = None if env_from_source.secret_ref is None else parse_secret_env_source(env_from_source.secret_ref)
    if config_map_ref is None and secret_ref is None:
        logger.warning("Parsing EnvFromSource but it has no configmap or secret ref source!")
    return model.EnvFromSource(prefix=env_from_source.prefix, config_map_ref=config_map_ref, secret_ref=secret_ref)


def parse_container(container: k8s.V1Container) -> model.Container:
    """Convert a K8s Container into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    ports = [parse_container_port(p, owner_name=container.name) for p in container.ports or []]

    env_vars = None if container.env is None else [parse_env_var(e) for e in container.env]
    env_from_sources = None if container.env_from is None else [parse_env_from_source(e) for e in container.env_from]
    volume_mounts = [parse_volume_mount(vm) for vm in container.volume_mounts or []]

    command = None if container.command is None else f"[{', '.join(container.command)}]"
    args = None if container.args is None else f"[{', '.join(container.args)}]"

    return model.Container(
        name=container.name,
        image_name=container.image,
        image_pull_policy=container.image_pull_policy,
        ports=ports,
        command=command,
        args=args,
        volume_mounts=volume_mounts,
        env_vars=env_vars,
        env_from_sources=env_from_sources,
    )


def parse_container_port(port: k8s.V1ContainerPort, owner_name: str) -> model.ContainerPort:
    """Convert a K8s ContainerPort into internal domain model

    :param obj: the object that will be converted
    :param owner_name: the name of the owner to make the ContainerPort unique per container type
    :return: the converted domain counterpart
    """
    value = port.name or str(port.container_port)
    id = f"{owner_name}_{value}"

    # use an explicit ID to differentiate the port to avoid conflation with ports with the same name/number of different cotnainers
    return model.ContainerPort(
        id=id,
        number=port.container_port,
        name=port.name,
        protocol=port.protocol,
        host_ip=port.host_ip,
        host_port=port.host_port,
    )


def parse_secret_volume_source(source: k8s.V1SecretVolumeSource) -> model.SecretVolumeSource:
    """Convert a K8s SecretVolumeSource into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    return model.SecretVolumeSource(
        secret_name=source.secret_name,
        default_mode=source.default_mode,
        items=source.items,
        is_optional=source.optional,
    )


def parse_secret_projection(projection: k8s.V1SecretProjection) -> model.SecretProjection:
    """Convert a K8s SecretProjection into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    return model.SecretProjection(
        secret_name=projection.name,
        items=[f"key='{i.key}'; mode={i.mode}; path='{i.path}'" for i in projection.items or []],
        is_optional=projection.optional,
    )


def parse_service_account_token_projection(
    projection: k8s.V1ServiceAccountTokenProjection,
) -> model.ServiceAccountTokenProjection:
    """Convert a K8s SA Token Projection into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    return model.ServiceAccountTokenProjection(
        audience=projection.audience,
        expiration_seconds=projection.expiration_seconds,
        path=projection.path,
    )


def _parse_volume_projections(sources: list[k8s.V1VolumeProjection]) -> list:
    """Convert a K8s Volume Projection into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    projections = []
    for src in sources:
        if src.service_account_token is not None:
            p = parse_service_account_token_projection(src.service_account_token)
        elif src.secret is not None:
            p = parse_secret_projection(src.secret)
        elif src.config_map is not None:
            p = model.OtherProjection(value="ConfigMapProjection dummy")
        elif src.downward_api is not None:
            p = model.OtherProjection(value="DownwardApi dummy")
            logger.warning("The parsing of downward api projection is currently not supported ")
        else:
            p = None
            logger.error("No valid source found in the volume projection!")

        if p is not None:
            projections.append(p)

    return projections


def parse_projected_volume_source(source: k8s.V1ProjectedVolumeSource) -> model.ProjectedVolumeSource:
    """Convert a Namespace K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """

    srcs = _parse_volume_projections(source.sources)
    return model.ProjectedVolumeSource(sources=srcs, default_mode=source.default_mode)


def parse_volume(volume: k8s.V1Volume) -> model.Volume:
    """Convert a K8s Volume into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    host_path = None
    source = None
    if volume.secret is not None:
        source = parse_secret_volume_source(volume.secret)
    elif volume.projected is not None:
        source = parse_projected_volume_source(volume.projected)
    elif volume.host_path is not None:
        host_path = model.HostPath(path=volume.host_path.path, type=volume.host_path.type)
    else:
        logger.warning(f"Could not parse the source for volume '{volume.name}'")
        vol_src_types = [k for k, src_type in volume.openapi_types.items() if src_type.endswith("VolumeSource")]
        # volume sources are mutually exclusive, but one must be set;
        # an StopIteration exception indicates a bigger flaw
        tmp_type = next(t for t in vol_src_types if getattr(volume, t) is not None)
        source = model.OtherVolumeSource(name=volume.name, type=f"{tmp_type} (unsupported)")

    return model.Volume(name=volume.name, source=source, host_path=host_path)


def parse_pod_security_context(sec_ctx: k8s.V1PodSecurityContext) -> model.PodSecurityContext:
    """Convert a K8s PodSecurityContext into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    logger.warning(f"Parsing of pod security context is not yet implemented!")
    return model.PodSecurityContext()


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1Pod) -> model.Pod:
    """Convert a Pod K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    print(f"parsing pod: {obj}")
    base = _parse_base(obj)

    sec_ctx = None if obj.spec.security_context is None else parse_pod_security_context(obj.spec.security_context)
    containers = [parse_container(c) for c in obj.spec.containers or []]

    return model.Pod(
        **dict(base),
        containers=containers,
        automount_service_account_token=obj.spec.automount_service_account_token,
        volumes=[parse_volume(v) for v in obj.spec.volumes or []],
        service_account_name=obj.spec.service_account,
        security_context=sec_ctx,
        host_network=obj.spec.host_network,
        node_name=obj.spec.node_name,
        pod_ip=model.IpAddress(ip=obj.status.pod_ip) if obj.status.pod_ip else None,
        host_ip=model.IpAddress(ip=obj.status.host_ip) if obj.status.host_ip else None,
        phase=obj.status.phase,
        # image_pull_secrets=[parse_local_object_reference(s) for s in obj.spec.image_pull_secrets] if obj,
    )


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1Deployment) -> model.Deployment:
    """Convert a Deployment K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    return model.Deployment(
        **dict(_parse_base(obj)),
        replicas=int(obj.spec.replicas),
        selector=obj.spec.selector.match_labels,
    )


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1ReplicaSet) -> model.ReplicaSet:
    """Convert a ReplicaSet K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    return model.ReplicaSet(
        **dict(_parse_base(obj)),
        replicas=int(obj.spec.replicas),
        selector=obj.spec.selector.match_labels,
    )


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1StatefulSet) -> model.StatefulSet:
    """Convert a StatefulSet K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    return model.StatefulSet(
        **dict(_parse_base(obj)),
        replicas=int(obj.spec.replicas),
        selector=obj.spec.selector.match_labels,
        service_name=obj.spec.service_name,
    )


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1DaemonSet) -> model.DaemonSet:
    """Convert a DaemonSet K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    return model.DaemonSet(
        **dict(_parse_base(obj)),
        selector=obj.spec.selector.match_labels,
    )


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1Service) -> model.Service:
    """Convert a Service K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    ports = [parse_service_port(p, owner_name=obj.metadata.name) for p in obj.spec.ports or []]

    return model.Service(
        **dict(_parse_base(obj)),
        type=obj.spec.type,
        cluster_ip=obj.spec.cluster_ip,
        ports=ports,
        selector=obj.spec.selector,
        # self.external_ips = [ip for ip in res.spec.external_i_ps]
    )


def parse_service_port(port: k8s.V1ServicePort, owner_name: str | None = None) -> model.ServicePort:
    """Convert a K8s Service into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    id = None
    if owner_name is not None:
        value = port.name or str(port.port)
        id = f"{owner_name}_{value}"
    return model.ServicePort(
        id=id,
        number=port.port,
        name=port.name,
        protocol=port.protocol,
        app_protocol=port.app_protocol,
        node_port=port.node_port,
        target_port=str(port.target_port),  # can be port name or port number, cast it to string to support TypeDb
    )


def _parse_ingress_rule(rule: k8s.V1IngressRule) -> list[model.IngressRule]:
    """Convert a K8s Ingress rule into internal domain model

    :param obj: the object that will be converted
    :return: a list of rules for every path to backend mapping
    """
    rules = []
    # currently, K8s only has http paths, so no need to differentiate at this point
    for path, backend in [_parse_ingress_path(p) for p in rule.http.paths]:
        rules.append(model.IngressRule(path=path, backend=backend, host=rule.host))
    return rules


def _parse_ingress_path(ingress_path: k8s.V1HTTPIngressPath) -> tuple[model.IngressPath, model.IngressBackend]:
    """Convert a K8s IngressPath into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """

    backend = _parse_ingress_backend(backend=ingress_path.backend)

    # HttpIngressPath is currently the only path type supported by Kubernetes, so use it as default
    path = model.HttpIngressPath(path=ingress_path.path, path_type=ingress_path.path_type)
    return path, backend


def _parse_ingress_backend(backend: k8s.V1IngressBackend) -> model.IngressBackend:
    if hasattr(backend, "service"):
        backend_port = backend.service.port
        port = model.ServiceBackendPort(number=backend_port.number, name=backend_port.name)
        backend = model.IngressServiceBackend(name=backend.service.name, port=port)
    else:
        ref = parse_local_object_reference(ref=backend.resource)
        backend = model.IngressResourceBackend(reference=ref)
    return backend


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1Ingress) -> model.Ingress:
    """Convert a Ingress K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    rules = []
    # a sing rule in K8s maps multiple paths to backends,
    # the model flattens this to a single IngressRule per mapping, so multiple objects are returned
    for r in obj.spec.rules:
        rules += _parse_ingress_rule(r)
    # rules = [_parse_ingress_rule(r) for r in obj.spec.rules]

    # ruleset = model.IngressRuleset(entries=rules)
    default_backend = None if obj.spec.default_backend is None else _parse_ingress_backend(obj.spec.default_backend)
    ingress = model.Ingress(**dict(_parse_base(obj)), rules=rules, default_backend=default_backend)
    # ruleset.owner = ingress
    return ingress


def parse_network_policy_port(port: k8s.V1NetworkPolicyPort) -> model.NetworkPolicyPort:
    # split union of port_number/port_name into dedicated fields depending on type
    port_info = {"port": port.port} if isinstance(port.port, int) else {"port_name": port.port}
    return model.NetworkPolicyPort(**port_info, protocol=port.protocol, end_port=port.end_port)


def parse_label_selector(
    selector: k8s.V1LabelSelector, default: Any | None = None, selector_type: str | None = None
) -> model.LabelSelector | None:
    if selector is None:
        return None

    match selector_type:
        case "pod":
            ctor = model.PodSelector
        case "namespace":
            ctor = model.NamespaceSelector
        case _:
            ctor = model.LabelSelector

    if selector.match_labels is not None:
        return ctor(entries=selector.match_labels)

    # depending on the context of the label selector, the default behaviour varies. e.g.:
    # - Service: when none or empty, it's assumed to manage EPs externally
    # - NetworkPolicy: if any selector is empty (but present) it selects everything in scope
    if default is not None:
        return default

    logger.warning(f"Not parsing LabelSelector properly: {selector}")
    return ctor()


def parse_network_policy_peer(peer: k8s.V1NetworkPolicyPeer) -> model.NetworkPolicyPeer:
    ip_block = None
    if peer.ip_block is not None:
        exceptions = [model.Cidr(cidr=e) for e in peer.ip_block._except or []]
        ip_block = model.IpBlock(cidr=model.Cidr(cidr=peer.ip_block.cidr), exceptions=exceptions)

    return model.NetworkPolicyPeer(
        pod_selector=parse_label_selector(peer.pod_selector, selector_type="pod"),
        namespace_selector=parse_label_selector(peer.namespace_selector, selector_type="namespace"),
        ip_block=ip_block,
    )


@dispatch
def parse_network_policy_rule(rule: k8s.V1NetworkPolicyIngressRule) -> model.NetworkPolicyIngressRule:
    ports = [parse_network_policy_port(p) for p in rule.ports or []] if rule.ports else None
    sources = [parse_network_policy_peer(p) for p in rule._from] if rule._from else None
    return model.NetworkPolicyIngressRule(ports=ports, peers=sources)


@dispatch
def parse_network_policy_rule(rule: k8s.V1NetworkPolicyEgressRule) -> model.NetworkPolicyEgressRule:
    ports = [parse_network_policy_port(p) for p in rule.ports] if rule.ports else None
    destinations = [parse_network_policy_peer(p) for p in rule._to] if rule._to else None
    return model.NetworkPolicyEgressRule(ports=ports, peers=destinations)


@dispatch
def parse_k8s_object(obj: k8s.V1NetworkPolicy) -> model.NetworkPolicy:
    ingress_rules = [parse_network_policy_rule(r) for r in obj.spec.ingress] if obj.spec.ingress else None
    egress_rules = [parse_network_policy_rule(r) for r in obj.spec.egress] if obj.spec.egress else None

    net_pol = model.NetworkPolicy(
        **dict(_parse_base(obj)),
        pod_selector=parse_label_selector(
            obj.spec.pod_selector,
            default=model.PodSelector(select_all=True),
            selector_type="pod",
        ),
        ingress_rules=ingress_rules,
        egress_rules=egress_rules,
        policy_types=obj.spec.policy_types,
    )
    return net_pol


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1ServiceAccount) -> model.ServiceAccount:
    """Convert a Serviceaccount K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    secrets = [model.ObjectReference(name=s.name) for s in obj.secrets] if obj.secrets is not None else []

    return model.ServiceAccount(
        **dict(_parse_base(obj)), automount_service_account_token=obj.automount_service_account_token, secrets=secrets
    )


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1Secret) -> model.Secret:
    """Convert a Secret K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    secret_type = obj.type

    if secret_type == "kubernetes.io/service-account-token":
        sa_name = obj.metadata.annotations["kubernetes.io/service-account.name"]
    else:
        sa_name = None

    return model.Secret(**dict(_parse_base(obj)), secret_type=obj.type, data=obj.data, sa_name=sa_name)


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1Role) -> model.Role:
    """Convert a Role K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    rules = [
        model.RbacRule(api_groups=r.api_groups, verbs=r.verbs, resources=r.resources, resource_names=r.resource_names)
        for r in obj.rules
    ]

    return model.Role(**dict(_parse_base(obj), rules=rules))


@dispatch  # type: ignore
def parse_k8s_object(obj: k8s.V1RoleBinding) -> model.RoleBinding:
    """Convert a RoleBinding K8s object into internal domain model

    :param obj: the object that will be converted
    :return: the converted domain counterpart
    """
    subjects = [
        model.RbacSubject(kind=s.kind, name=s.name, api_group=s.api_group, ns=s.namespace) for s in obj.subjects
    ]
    role_ref = model.RoleRef(kind=obj.role_ref.kind, name=obj.role_ref.name, api_group=obj.role_ref.api_group)

    return model.RoleBinding(**dict(_parse_base(obj), subjects=subjects, role_ref=role_ref))
