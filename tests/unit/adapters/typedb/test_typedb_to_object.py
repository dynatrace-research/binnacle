from binnacle.adapters.typedb.typedb_to_object import (
    map_attributes,
    map_entity_to_domain_object,
)
from binnacle.model.k8s_object import K8sObject


def test_mapping_returns_domain_object():
    res = map_entity_to_domain_object({"kind": "pod", "name": "a-name", "ns": "default"})
    assert isinstance(res, K8sObject)


class TestAttributeMapping:
    def test_no_attribute_yields_empty_dict(self):
        attr = map_attributes([])
        assert attr == {}

    def test_single_attributes_is_plain_entry(self):
        key, value = "a-key", "a-value"
        attr = map_attributes([(key, value)])
        assert attr == {key: value}

    def test_multiple_same_attributes_are_combined_to_list(self):
        key = "attr"
        values = ["val-1", "val-2", "val-3"]

        attrs = map_attributes([(key, v) for v in values])

        # there is only one entry with a list of the values
        assert len(attrs) == 1
        assert len(attrs[key]) == len(values)
        assert set(values) == set(attrs[key])
