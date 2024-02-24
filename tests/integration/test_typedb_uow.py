import pytest

from binnacle import model
from binnacle.adapters.typedb.typedb_knowledge_graph import TypeDbKnowledgeGraph
from binnacle.services.unit_of_work import TypeDbUnitOfWork


@pytest.fixture(scope="session")
def setup_db():
    db_name = "integration-test"
    db = TypeDbKnowledgeGraph(db_name, url="0.0.0.0:1729")
    db.create_database(db_name)
    yield db

    db.delete_database(db_name)


class TestObjectInsertion:
    def test_adding_new_pod(self, setup_db):
        uow = TypeDbUnitOfWork(kb=setup_db)

        container = model.Container(name="test-container", image_name="busybox")
        pod = model.Pod(name="test-pod", namespace="default", containers=[container])
        with uow:
            uow.insert(pod)

            res = uow.get(model.Pod)
            assert len(res) == 1
