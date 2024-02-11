import pytest
from _pytest.logging import LogCaptureFixture
from loguru import logger

from binnacle import model
from binnacle.adapters.typedb.fakes import FakeSession
from binnacle.adapters.typedb.object_to_typeql import TqlBuilder, to_typeql
from binnacle.adapters.typedb.typedb_knowledge_graph import (
    TypeDbKnowledgeGraph,
    _find_object_definition,
    convert_objects,
    flatten_and_deduplicate_elements,
    resolve_relations,
    transform_insert_to_delete_queries,
)
from binnacle.adapters.typedb.typedb_to_object import Ref, RelationData
from binnacle.model.primitives import Thing


# add fix to allow loguru to be compatible with pytests `caplog``
@pytest.fixture
def caplog(caplog: LogCaptureFixture):
    handler_id = logger.add(caplog.handler, format="{message}")
    yield caplog
    logger.remove(handler_id)


class TestConvertTypedbResultToDomainObject:
    def test_unmapped_entity_yield_generic_thing(self):
        entities = {"id": {"kind": "unknown"}}

        res_entities = convert_objects((entities, {}))
        assert len(res_entities) == 1
        assert isinstance(res_entities[0], Thing)

    def test_unknown_types_are_logged_as_warning(self, caplog):
        type_str = "an-unknown-type"
        entities = {"id": {"kind": type_str}}

        convert_objects((entities, {}))
        assert "WARNING" in caplog.text
        assert type_str in caplog.text

    class TestRelationResolving:
        def test_reference_to_existing_entities(self):
            pod = model.Pod(name="pod")
            container = model.Container(name="image", image_name="busbyx")
            dependencies = {"container": pod, "thing": container}

            id = "rel-id"
            ctor = model.Contains
            refs = [
                Ref(
                    relationship=(role),
                    target=e.id,
                )
                for (role, e) in dependencies.items()
            ]
            attrs = {}
            rel_data = RelationData(id=id, ctor=ctor, attributes=attrs, refs=refs)
            objects = resolve_relations(entities=list(dependencies.values()), relation_data=[rel_data])

            assert len(objects) == len(dependencies) + 1  # one additional relation is in the results
            *_, relation = objects
            assert isinstance(relation, ctor)
            # ensure roles have been correctly assingned to the referred entities
            assert relation.thing == container
            assert relation.container == pod

        def test_references_to_other_relations(self):
            src_rel_data = RelationData(id="my-src-relation", ctor=model.Relation, attributes={}, refs={})
            target_rel_data = RelationData(id="my-target-relation", ctor=model.Relation, attributes={}, refs={})
            ref_data = RelationData(
                id="my-reference",
                ctor=model.Reference,
                attributes={"label": "dummy-reference"},
                refs=[
                    Ref(relationship="referrer", target=src_rel_data.id),
                    Ref(relationship="object", target=target_rel_data.id),
                ],
            )
            # place reference first, so cover more difficult use-case where not all players are yet resolved
            relation_data = [ref_data, src_rel_data, target_rel_data]

            objects = resolve_relations(entities=[], relation_data=relation_data)
            assert len(objects) == len(relation_data)

        def test_unresolved_references_are_ignored(self):
            pod = model.Pod(name="pod")

            ctor = model.Contains
            refs = [Ref(relationship="container", target=pod.id), Ref(relationship="thing", target="does-not-exist")]
            rel_data = RelationData(id="rel-id", ctor=ctor, attributes={}, refs=refs)
            _, relation = resolve_relations(entities=[pod], relation_data=[rel_data])
            assert isinstance(relation, ctor)
            # ensure roles have been correctly assingned to the referred entities
            assert relation.thing == None  # this was not resolved


class TestElementDeduplication:
    def test_duplicate_entities_are_merged(self):
        id = "123"
        a1, a2 = "attr1", "attr2"
        entities = [{id: {"kind": "pod", a1: False}}, {id: {"kind": "pod", a2: True}}]

        num_entities = len(entities)
        input = zip(entities, [{}] * num_entities, [[]] * num_entities)
        res_entities, _ = flatten_and_deduplicate_elements(input)
        assert len(res_entities) == 1
        assert id in res_entities
        e = res_entities[id]
        # both attributes should be on that element
        assert a1 in e and a2 in e

    def test_deduplication_flattens_entities(self):
        entities = [{"1": {"kind": "pod"}}, {"2": {"kind": "pod"}}, {"3": {"kind": "pod"}}, {"4": {"kind": "pod"}}]
        num_entities = len(entities)
        input = zip(entities, [{}] * num_entities, [[]] * num_entities)
        res_entities, _ = flatten_and_deduplicate_elements(input)
        assert len(res_entities) == 4

class TestTransformaInsertQueriesToDeleteQueries:
    def test_find_object_definition_in_insert(self):
        entity = "service-accout"
        var = "$service-account"
        query = f"insert {var} isa {entity};"
        res = _find_object_definition(query)

        assert res == f"{var} isa {entity}"

    def test_no_object_definition_yields_none(self):
        res = _find_object_definition("insert this query has not valid 'isa' sentence;")
        assert res is None

    def test_attributes_are_ignored(self):
        entity = "pod"
        var = "$sa"
        res = _find_object_definition(f"insert {var} isa {entity}, has attr 'something', has other 'value';")
        assert res == f"{var} isa {entity}"

