from binnacle import model
from binnacle.adapters.knowledge_base import AbstractKnowledgeBase
from binnacle.adapters.typedb.typedb_knowledge_graph import TypeDbKnowledgeGraph


def query_knowledge_base(
    query: str, kb: AbstractKnowledgeBase | None = None, **kwargs
) -> tuple[model.Thing, model.Relation]:
    """Run the given query against the TypeDB instance and return any matched entities and relations

    :param query: the query that will be run against the TypeDB instance
    :return: a tuple with a list of entities and a list of relations between them
    """
    if kb is None:
        kb = TypeDbKnowledgeGraph(**kwargs)
    entities, relations = kb.query(query)

    return entities, relations
