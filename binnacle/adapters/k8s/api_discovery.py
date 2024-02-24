import os
from functools import partial
from typing import Any, Generator, List, Optional, Union

import urllib3
from kubernetes import client
from loguru import logger

from binnacle.adapters.k8s.cluster_management import load_kube_config
from binnacle.model import Ingress
from binnacle.model.k8s_object import (
    ClusterNode,
    DaemonSet,
    Deployment,
    Namespace,
    Pod,
    ReplicaSet,
    Role,
    RoleBinding,
    Secret,
    Service,
    ServiceAccount,
    StatefulSet,
)
from binnacle.model.networking import NetworkPolicy

from .k8s_orm import parse_k8s_object


def check_authentication() -> bool:
    """Basic check if it's possible to authenticate against the Kubernetes cluster

    :return: True if authentication is possible, False otherwise
    """
    api = client.AuthenticationApi()
    try:
        api.get_api_group()
        return True
    except client.ApiException as exc:
        msg = _parse_api_exception(exc)
        raise RuntimeError(
            f"Failed to authorize with the cluster: {msg}"
            + os.sep
            + "Please ensure the provided token and certificate are valid"
        )
    except urllib3.exceptions.MaxRetryError as exc:
        logger.warning(f"Authorization check failed because no connection could be established")
    return False


def _parse_api_exception(exception: client.ApiException) -> str:
    return f"{exception.status} {exception.reason}"


def get_k8s_version() -> str | None:
    v1 = client.VersionApi()
    try:
        version = v1.get_code()
        return version.git_version
    except client.ApiException as exc:
        return None


def get_nodes() -> ClusterNode:
    v1 = client.CoreV1Api()
    ret = v1.list_node()
    return [parse_k8s_object(n) for n in ret.items]


def get_namespaces() -> List[Namespace]:
    v1 = client.CoreV1Api()
    ret = v1.list_namespace()
    ns = [parse_k8s_object(r) for r in ret.items]
    return ns


def get_namespace(name: str) -> Namespace:
    v1 = client.CoreV1Api()
    ret = v1.read_namespace(name)
    return parse_k8s_object(ret)


def get_pods(namespace: Optional[str] = None) -> List[Pod]:
    v1 = client.CoreV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_pod(namespace)
    else:
        ret = v1.list_pod_for_all_namespaces(watch=False)

    pods = [parse_k8s_object(r) for r in ret.items]
    return pods


def get_deployments(namespace: Optional[str] = None) -> List[Deployment]:
    v1 = client.AppsV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_deployment(namespace)
    else:
        ret = v1.list_deployment_for_all_namespaces(watch=False)

    deployments = [parse_k8s_object(r) for r in ret.items]
    return deployments


def get_replica_sets(namespace: Optional[str] = None) -> List[ReplicaSet]:
    v1 = client.AppsV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_replica_set(namespace)
    else:
        ret = v1.list_replica_set_for_all_namespaces(watch=False)

    replica_sets = [parse_k8s_object(r) for r in ret.items]
    return replica_sets


def get_stateful_sets(namespace: Optional[str] = None) -> List[StatefulSet]:
    v1 = client.AppsV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_stateful_set(namespace)
    else:
        ret = v1.list_stateful_set_for_all_namespaces(watch=False)

    stateful_sets = [parse_k8s_object(r) for r in ret.items]
    return stateful_sets


def get_daemon_sets(namespace: Optional[str] = None) -> List[DaemonSet]:
    v1 = client.AppsV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_daemon_set(namespace)
    else:
        ret = v1.list_daemon_set_for_all_namespaces(watch=False)

    daemon_sets = [parse_k8s_object(r) for r in ret.items]
    return daemon_sets


def get_services(namespace: Optional[str] = None) -> List[Service]:
    v1 = client.CoreV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_service(namespace)
    else:
        ret = v1.list_service_for_all_namespaces(watch=False)

    services = [parse_k8s_object(r) for r in ret.items]
    return services


def get_ingresses(namespace: Optional[str] = None) -> List[Ingress]:
    v1 = client.NetworkingV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_ingress(namespace)
    else:
        ret = v1.list_ingress_for_all_namespaces(watch=False)

    ingresses = [parse_k8s_object(r) for r in ret.items]
    return ingresses


def get_network_policies(namespace: Optional[str] = None) -> List[NetworkPolicy]:
    v1 = client.NetworkingV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_network_policy(namespace)
    else:
        ret = v1.list_network_policy_for_all_namespaces(watch=False)

    network_policies = [parse_k8s_object(r) for r in ret.items]
    return network_policies


def get_service_accounts(namespace: Optional[str] = None) -> List[ServiceAccount]:
    v1 = client.CoreV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_service_account(namespace)
    else:
        ret = v1.list_service_account_for_all_namespaces(watch=False)

    service_accounts = [parse_k8s_object(r) for r in ret.items]
    return service_accounts


def get_role_bindings(namespace: Optional[str] = None) -> List[RoleBinding]:
    v1 = client.RbacAuthorizationV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_role_binding(namespace)
    else:
        ret = v1.list_role_binding_for_all_namespaces(watch=False)

    role_bindings = [parse_k8s_object(r) for r in ret.items]
    return role_bindings


def get_roles(namespace: Optional[str] = None) -> List[Role]:
    v1 = client.RbacAuthorizationV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_role(namespace)
    else:
        ret = v1.list_role_for_all_namespaces(watch=False)

    roles = [parse_k8s_object(r) for r in ret.items]
    return roles


def get_secrets(namespace: Optional[str] = None) -> List[Secret]:
    v1 = client.CoreV1Api()
    if namespace is not None:
        ret = v1.list_namespaced_secret(namespace)
    else:
        ret = v1.list_secret_for_all_namespaces(watch=False)

    secret = [parse_k8s_object(r) for r in ret.items]
    return secret



def load_cluster_objects(
    config_path: str,
    context: str,
    namespaces: Optional[Union[str, List[str]]] = None,
    include_infrastructure: bool = False,
) -> Generator[Any, None, None]:
    load_kube_config(config_path=config_path, used_context=context)
    resource_getter_fns = []

    fns = [
        get_network_policies,
        get_pods,
        get_deployments,
        # get_replica_sets,  # this level of detail is not needed for any use-case atm
        # get_stateful_sets,
        # get_daemon_sets,
        get_services,
        get_ingresses,
        # get_service_accounts,
        # get_secrets,
        # get_roles,
        # get_role_bindings,
    ]

    if include_infrastructure:
        resource_getter_fns.append(get_nodes)

    if namespaces is None or len(namespaces) == 0:  # no specific namespace implies all namespaces are used
        resource_getter_fns.append(get_namespaces)
        namespaces = [None]  #  None means that resource from all namespaces will be loaded
    elif isinstance(namespaces, str):
        namespaces = [namespaces]

    # prefill namespace resource retrieval functions for all namespaces
    for ns in namespaces:
        if ns is not None:
            yield get_namespace(ns)
        resource_getter_fns += [partial(fn, ns) for fn in fns]
        # for fn in fns:
        #     logger.debug(f"Loading {fn.__name__}")
        #     yield from (r for r in fn(ns))

    try:
        for fn in resource_getter_fns:
            try:
                for r in fn():
                    yield r
            except Exception as exc:
                raise RuntimeError(f"Error while loading {fn}: ", exc)
        # yield from (r for fn in resource_getter_fns for r in fn())
    except urllib3.exceptions.RequestError as exc:
        raise RuntimeError("Unable to connect to the Kubernetes cluster: " + str(exc))
    except Exception as exc:
        # transform it into a generic runtime error
        raise RuntimeError("Error while loading the resources: ", exc)
