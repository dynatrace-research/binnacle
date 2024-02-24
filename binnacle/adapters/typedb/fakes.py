from typing import Any
from unittest.mock import MagicMock

from pyparsing import Iterable

from binnacle.adapters.knowledge_base import AbstractKnowledgeBase
from binnacle.adapters.typedb.object_to_typeql import get_insert_query
from binnacle.model.primitives import DomainObject, Relation, Thing
from binnacle.services.unit_of_work import AbstractDatabaseUnitOfWork


class FakeDBUnitOfWork(AbstractDatabaseUnitOfWork):
    def __init__(self, db_name: str | None = "default") -> None:
        self.kb = FakeKnowledgeBase(db_name=db_name)
        self.queries = []

    def __enter__(self, *args):
        self.session = self.kb.start_session()
        return self

    def __exit__(self, *args):
        self.session = None

    def get_databases(self):
        return self.kb.get_databases()

    def create_database(self, name: str):
        self.kb.create_database(name)

    def delete_database(self, name: str):
        self.kb.delete_database(name)

    def temp(self, object: Thing | Relation) -> Thing | Relation:
        self.kb.insert([object])
        return object

    def get(self, *objects: Iterable, **kwargs) -> list[Thing | Relation]:
        return []

    def query(self, queries: DomainObject | list[DomainObject], **kwargs) -> list[DomainObject]:
        return []

    def query_str(self, query: str, **kwargs) -> list[DomainObject]:
        return []


class FakeKnowledgeBase(AbstractKnowledgeBase):
    def __init__(self, db_name: str = "fake-db", *args) -> None:
        self.db_name = db_name
        self.queries = []
        self.inserted_objects = []
        self.session = None
        self.dbs = ["default", "fake-db"]

    def get_databases(self):
        return self.dbs

    def create_database(self, name: str):
        if name not in self.dbs:
            self.dbs.append(name)

    def delete_database(self, name: str) -> None:
        self.dbs = [db for db in self.dbs if db != name]

    def __enter__(self):
        self.start_session()

    def __exit__(self, *args, **kwargs):
        self.session = None

    def start_session(self):
        if self.db_name not in self.dbs:
            raise ValueError(f"The database with the name '{self.db_name}' does not exist!")
        self.session = FakeSession()
        return self.session

    def insert_via_stream(self, *args, **kwargs):
        pass

    def query(self, *args, **kwargs) -> tuple[list, list]:
        return [], []

    def insert(self, objects: list[str], *args, **kwargs) -> list[Any]:
        self.inserted_objects += objects
        self.queries = [q for obj in objects for q in get_insert_query(obj)]
        return self.queries

    def delete(self, objects: list[Thing | Relation], *args, **kwargs) -> None:
        for obj in objects:
            self.inserted_objects.remove(obj)


class FakeQuery:
    def __init__(self):
        self.insert = MagicMock()
        self.match = MagicMock()
        self.delete = MagicMock()


class FakeTransaction:
    def __init__(self) -> None:
        self._query = None

    @property
    def query(self) -> FakeQuery:
        self._query = FakeQuery()
        return self._query

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self

    def get_query(self) -> FakeQuery | None:
        """Extra function to retrieve the faked children

        :return: return the faked transaction if avialable
        """
        return self._query


class FakeSession:
    def __init__(self) -> None:
        self.tx = None

    def transaction(self, *args, **kwargs) -> FakeTransaction:
        self.tx = FakeTransaction()
        return self.tx

    def __enter__(self):
        return self  # super().__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self  # super().__exit__(exc_type, exc_val, exc_tb)

    def get_query(self) -> FakeQuery | None:
        """Extra function to retrieve the faked children

        :return: return the faked transaction if avialable
        """
        if self.tx is not None:
            return self.tx.get_query()
        return None
