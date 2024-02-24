from binnacle import model
from binnacle.adapters.typedb.fakes import FakeKnowledgeBase
from binnacle.services.unit_of_work import TypeDbUnitOfWork


class TestTemporaryFactsInImpactAssessment:
    def test_temporary_facts_can_be_added(self):
        kb = FakeKnowledgeBase("fake-db")
        with TypeDbUnitOfWork(db_name="db", kb=kb) as uow:
            uow.temp(model.Pod(name="a-pod", namespace="default"))
            assert len(uow._staged_objects) == 1

    def test_temporary_facts_are_only_added_when_retrieving_other_data(self):
        kb = FakeKnowledgeBase("fake-db")
        with TypeDbUnitOfWork(db_name="db", kb=kb) as uow:
            uow.temp(model.Pod(name="a-pod", namespace="default"))
            assert len(uow._staged_objects) == 1
            assert len(kb.inserted_objects) == 0

            uow.get(model.Pod)
            assert len(kb.inserted_objects) == 1

    def test_temporary_facts_are_gone_after_uow(self):
        kb = FakeKnowledgeBase("fake-db")
        with TypeDbUnitOfWork(db_name="db", kb=kb) as uow:
            uow.temp(model.Pod(name="a-pod", namespace="default"))
            uow.get(model.Pod)
            assert len(uow.temporary_objects) == 1
            assert len(uow.kb.inserted_objects) == 1
        assert len(kb.inserted_objects) == 0
