import multiprocessing as mp
from typing import Callable

from loguru import logger

from binnacle import model
from binnacle.adapters.knowledge_base import AbstractKnowledgeBase
from binnacle.adapters.typedb.typedb_knowledge_graph import reset_database
from binnacle.services.unit_of_work import (
    AbstractDatabaseUnitOfWork,
    KubernetesUnitOfWork,
)


def populate(k8s_uow: KubernetesUnitOfWork, db_uow: AbstractDatabaseUnitOfWork, db_name: str) -> None:
    """Populate the knowledge base with the data from the currently active Kubernetes cluster

    :param k8s_uow: the unit of work to load objects from a Kubernetes cluster
    :param db_uow: the unit of work for knowledge base operations
    :param db_name: the name of the used database instance
    :raises RuntimeError: if either Kubernetes cluster or the knowledge base are not available
    """
    if not k8s_uow.is_ready():
        raise RuntimeError(f"Can NOT connect to Kubernetes cluster '{k8s_uow.cluster}'")
    try:
        if db_name in db_uow.kb.get_databases():
            logger.info(f'"{db_name}" already exists - resetting it!')
        db_uow.create_database(db_name)

        k8s_loader = k8s_uow.get_object_loader(k8s_uow.cluster)
        load_environment_into_knowledge_base(k8s_loader, db_uow.kb)
    except Exception as exc:
        raise RuntimeError(exc)


def get_projects(uow: AbstractDatabaseUnitOfWork) -> list[str]:
    try:
        projects = uow.get_databases()
    except Exception as exc:
        raise RuntimeError(exc)
    return projects


def delete_project(uow: AbstractDatabaseUnitOfWork, name: str) -> bool:
    try:
        uow.delete_database(name)
        return True
    except Exception as exc:
        return False


def reset_knowledge_base(db_host: str, db_name: str) -> None:
    reset_database(db_host, db_name)


def load_k8s_cluster_objects(environment_reader: Callable, queue: mp.Queue, *args):
    logger.info("starting k8s loader")
    cnt = 0
    print(args)
    try:
        for cnt, r in enumerate(environment_reader(*args)):
            queue.put(r)
    except ValueError as exc:
        logger.error(exc)
    except RuntimeError as exc:
        logger.error(exc)
        queue.put(exc)  # stop the ETL process

    queue.put(None)
    logger.info(f"loaded {cnt} objects from kubernetes")


def load_environment_into_knowledge_base(
    environment_reader: Callable,
    kb: AbstractKnowledgeBase,
):
    queue = mp.Queue()

    producer_proc = mp.Process(target=load_k8s_cluster_objects, args=(environment_reader, queue))
    producer_proc.start()

    internet = model.Internet()
    queue.put(internet)

    # perform the TypeDB tasks on main process because TypeDBclient internal objects can't be pickled properly for Windows
    kb.insert_via_stream(queue)

    queue.close()
