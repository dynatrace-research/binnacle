from binnacle import model
from binnacle.model import utils


class TestKindToResourceTypeMapping:
    def test_kind_is_converted_resource_type_format(self):
        kinds = ["Pod", "Secret", "Configmap", "Endpointslice", "Crontab", "Deployment", "Job", "Node"]
        for kind in kinds:
            expected_res_type = kind.lower() + "s"
            res = utils.map_kind_to_resource_type(kind)
            assert res == expected_res_type

    def test_irregular_resource_types(self):
        irregular_kinds = {
            "Ingress": "ingresses",
            "IngressClass": "ingressclasses",
            "NetworkPolicy": "networkpolicies",
            "RuntimeClass": "runtimeclasses",
            "PriorityClass": "priorityclasses",
            "CsiStorageCapacity": "csistoragecapacities",
            "StorageClass": "storageclasses",
        }

        for kind, expected in irregular_kinds.items():
            res = utils.map_kind_to_resource_type(kind)
            assert res == expected


class TestObjectConsolidation:
    def test_merge_two_identical_objects(self):
        id = "an-id"
        o1 = model.Thing(id=id)
        o2 = model.Thing(id=id)
        res = utils.consolidate_objects([o1, o2])
        assert len(res) == 1
        assert res[0] == o1

    def test_merge_two_objects_with_same_id_but_complementary_info(self):
        id = "an-id"
        name = "exploit name"
        ns = "default"
        sa_name = "a-service-account"
        automount_sa = True

        o1 = model.Pod(id=id, name=name, namespace=ns, automount_service_account_token=automount_sa)
        o2 = model.Pod(id=id, name=name, namespace=ns, service_account_name=sa_name)
        res, *other = utils.consolidate_objects([o1, o2])

        assert len(other) == 0

        assert res.id == id
        assert res.service_account_name == sa_name
        assert res.automount_service_account_token == automount_sa

    def test_merge_lists_of_identical_objects(self):
        targets1 = {"a": "target1"}
        targets2 = {"b": "target2", "c": "target3"}
        id = "an-id"
        rel1 = model.Relation(id=id, relates=targets1)
        rel2 = model.Relation(id=id, relates=targets2)

        res, *other = utils.consolidate_objects([rel1, rel2])
        assert len(other) == 0

        assert len(res.relates) == len(targets1) + len(targets2)

    class TestConsolidateSimilarObjects:
        def test_merge_two_objects_with_different_ids_but_same_data(self):
            name = "exploit name"
            ns = "default"
            sa_name = "a-service-account"

            o1 = model.Pod(name=name, namespace=ns, service_account_name=sa_name)
            o2 = model.Pod(name=name, namespace=ns, service_account_name=sa_name)
            res, *other = utils.consolidate_objects([o1, o2], merge_similar_objects=True)

            assert len(other) == 0

            assert res.name == name
            assert res.namespace == ns
            assert res.service_account_name == sa_name
