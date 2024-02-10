from abc import ABC, abstractmethod
from multiprocessing import Queue
from typing import Any

from binnacle.model.primitives import DomainObject


class AbstractKnowledgeBase(ABC):
    def __init__(self, url: str) -> None:
        self.ready = True

    @abstractmethod
    def get_databases(self):
        raise NotImplementedError

    @abstractmethod
    def create_database(self, name: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def delete_database(self, name: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def insert_via_stream(self, queue: Queue):
        raise NotImplementedError

    @abstractmethod
    def query(self, query: str, *arg, **kwargs) -> list[DomainObject]:
        raise NotImplementedError

    @abstractmethod
    def insert(self, queries: str, *args, **kwargs) -> list[Any]:
        raise NotImplementedError

    @abstractmethod
    def delete(self, queries: list[str], *args, **kwargs) -> None:
        raise NotImplementedError
