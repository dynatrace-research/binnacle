from loguru import logger

from binnacle.adapters.k8s.api_discovery import get_namespaces
from binnacle.adapters.k8s.cluster_management import (
    get_context_information,
    load_kube_config,
    load_or_create_kubeconfig,
    save_kubeconfig,
)
from binnacle.model.cluster import KubeConfigEntry


def get_cluster_contexts(config_path: str | None) -> list[str]:
    config = load_or_create_kubeconfig(file_path=config_path)
    return [ctx.name for ctx in config.contexts]


def get_default_context_name() -> str | None:
    """Retrieve the name of the Kubernetes contex from the active kubectl context.
    #TODO: this does not make sense?: In case of complex context name (e.g., AWS) the name is the last part after the '/'.

    :return: name of targeted context or None, if no active context is set.
    """
    ctx = get_context_information()
    if ctx is None:
        return None
    ctx_name = ctx["name"]
    # if "/" in ctx_name:
    #     _, ctx_name = ctx_name.rsplit("/", maxsplit=1)
    return ctx_name


def add_cluster(entry: KubeConfigEntry, config_path: str) -> None:
    """Add a new cluster in the kubeconfig file at the designated location.

    :param entry: the new entry to add
    :param config_path: the path to the kubeconfig file
    """
    config = load_or_create_kubeconfig(file_path=config_path)
    config.add_or_update_entry(entry)

    # write updated version
    save_kubeconfig(config)


def remove_context(context_name: str, config_path: str) -> bool:
    """Remove an entry from the kubeconfig at the given location

    :param context_name: the name of the entry to remove
    :param config_path: the path to the kubeconfig file
    :return: True if the entry was deleted, False otherwise
    """
    config = load_or_create_kubeconfig(file_path=config_path)
    if config.has_entry(context_name):
        config.remove_entry(context_name)
        save_kubeconfig(config)
        return True
    return False


def get_namespaces_in_cluster(cluster: str, config_path: str) -> list[str]:
    load_kube_config(config_path=config_path, used_context=cluster)
    ns = get_namespaces()
    return ns
