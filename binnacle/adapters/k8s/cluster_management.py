from pathlib import Path

import yaml
from kubernetes import config
from loguru import logger

from binnacle.model.cluster import KubeConfig
from binnacle.settings import get_settings


def get_context_information(config_path: str | None = None) -> dict | None:
    """Get general information about the target context which will be interacted with

    :return: a dictionary containing any relevant of the active context
    :rtype: dict
    """
    try:
        contexts, active_context = config.list_kube_config_contexts(config_file=config_path)
        return active_context
    except config.ConfigException:
        logger.warning(f"No valid `current_context` is set in kubeconfig at '{config_path}'")
        return None


def get_default_namespace_from_context() -> str:
    ctx_info = get_context_information()
    return ctx_info["context"]["namespace"]


def load_kube_config(config_path: str | None = None, used_context: str | None = None) -> str | None:
    active_context = used_context
    if config_path is None:
        settings = get_settings()
        config_path = settings.kubeconfig_path
    try:
        if used_context is None:
            active_context_map = get_context_information(config_path=config_path)
            active_context = active_context_map["name"]
        logger.info(f"Activating kubeconfig context: {active_context}")
        config.load_kube_config(config_file=config_path, context=used_context)
    except config.ConfigException as exc:
        logger.warning(f"Unable to activate kubeconfig {config_path}: {str(exc)}")

    return active_context


def load_or_create_kubeconfig(file_path: str) -> KubeConfig:
    """Load or create a kubecconfig file from the specified location.
    If no such file exists an object will be created in-memory.

    :param file_path: the path of the kubeconfig file
    :return: an instance of the loaded kubeconfig file
    """
    path = Path(file_path).expanduser()

    if path.exists():
        with open(path, "r") as f:
            data = yaml.safe_load(f)
            config = KubeConfig.model_validate(data)
            config.path = file_path
            return config
    else:
        logger.info(f"No kubeconfig found at '{path}'. Loading new config!")
        return KubeConfig(path=str(path))


def save_kubeconfig(config: KubeConfig, path: Path | None = None) -> None:
    """Save the given kubeconfig at the specified location.
    if no location is specified, then the config-internal path will be used.

    :param config: the kubeconfig file, that will be saved
    :param path: the destination path to save the config file, defaults to None
    :raises FileNotFoundError: no path to save the config to is specified
    """
    if path is None:
        if config.path is None:
            raise FileNotFoundError("No path specified for the kubeconfig")
        path = Path(config.path)

    # ensure parents exist as well
    path = path.expanduser()
    path.parent.mkdir(exist_ok=True, parents=True)
    with open(path, "w") as f:
        content = config.model_dump(
            exclude_none=True,
            by_alias=True,  # use the correct field names specified as alias
        )
        yaml.dump(content, f)
