from ipaddress import ip_address
from typing import Annotated

import pytest
from pydantic import BaseModel

from binnacle import model
from binnacle.adapters.typedb.object_to_typeql import to_typeql
from binnacle.adapters.typedb.tql_builder import (
    TqlBuilder,
    _get_variables_from_relations,
    is_primitive,
)
from binnacle.model.k8s_object import Pod
from binnacle.model.primitives import RelationPart
from binnacle.utils import to_kebab_case


class TestTqlBuilder:
    def test_pod_to_tql(self):
        pod_name = "pod"
        ns = "ns"
        pod = Pod(name=pod_name, namespace=ns)
        builder = TqlBuilder(pod)
        tql = builder.as_tql()

        assert "$pod isa pod" in tql
        assert f'has name "{pod_name}"' in tql
        assert 'has kind "Pod"' in tql
        assert f'has ns "{ns}"' in tql

    def test_multiple_labels_are_possible(self):
        key1 = "label-1"
        key2 = "label-2"
        labels = {
            key1: model.Label(key=key1, data="a value"),
            key2: model.Label(key=key2, data=True),
        }
        obj = model.K8sObject(name="a-object", labels=labels)
        tql = TqlBuilder(obj).as_tql()

        # values of labels is not relevant for this, just the number of labels
        for i, _ in enumerate(labels.keys()):
            assert f"has label $label_{i}" in tql

    def test_returned_tql_ends_with_semicolon(self):
        obj = model.K8sObject(name="a-object")
        tql = TqlBuilder(obj).as_tql()

        assert tql.endswith(";")

    def test_custom_variable_name(self):
        obj = model.K8sObject(name="a-object")
        var_name = "my-custom-var"
        tql = TqlBuilder(obj).as_tql(var_name=var_name)
        assert f"${var_name} isa" in tql

    def test_complex_attribute_with_custom_name(self):
        env_var = model.EnvVar(name="my-var", var_value="var-value")
        container = model.Container(name="my-container", image_name="image", env_vars=[env_var])
        # obj = model.K8sObject(name="a-object", part_of=ms)
        # ms_var = "ms_0"
        custom_attr_name = "special-env-var"
        tql = TqlBuilder(container).set_variables(env_var=custom_attr_name).as_tql()
        assert f"has env-var ${custom_attr_name}" in tql
        assert f"${custom_attr_name} isa env-var" in tql

    def test_complex_attribute_with_custom_name_is_not_part_of_relation(self):
        ms = model.MicroService(name="my-microservice")
        obj = model.K8sObject(name="a-object", part_of=ms)
        ms_var = "ms_0"
        tql = TqlBuilder(obj).set_variables(part_of=ms_var).as_tql()
        assert f": ${ms_var})" not in tql

    def test_relation_players_are_automatically_determined(self):
        can = "exploit"
        adversary = model.Adversary(name="Mallory")
        exploit = model.Exploit(name="Log4Shell", cve="123")
        ability = model.Ability(actor=adversary, target=exploit, can=can)

        relations = [
            ("ability:actor", adversary),
            ("ability:target", exploit),
        ]
        tql = to_typeql(ability)
        # rel_definitions = TqlBuilder._get_variables_from_relations(relations, obj_type="ability")

        expected_rel_definitions = [(r.split(":")[1], str(obj).lower()) for r, obj in relations]
        for role, var in expected_rel_definitions:
            assert f"{role}: ${var}" in tql

    def test_relation_variables_extraction(self):
        relations = [
            ("ability:actor", model.Adversary(name="Mallory")),
            ("ability:target", model.Exploit(name="Log4Shell", cve="123")),
        ]
        rel_definitions = _get_variables_from_relations(relations)

        expected_rel_definitions = [(r.split(":")[1], str(obj).lower()) for r, obj in relations]
        for player, var in expected_rel_definitions:
            assert rel_definitions.get(player, None) == [var]


class TestMappingOfClassToQuery:
    def test_get_basic_thing(self):
        tql = TqlBuilder(model.Thing).as_tql()
        assert "$thing isa thing;" in tql

    def test_object_with_required_field(self):
        tql = TqlBuilder(model.Pod).as_tql()
        assert tql == "$pod isa pod, has name $name, has ns $ns;"

    def test_class_with_attributes_matches_all(self):
        tql = TqlBuilder(model.Capability).as_tql()
        assert tql.startswith("$capability (environment: $environment, requires: $requires) isa capability")
        assert "has resource-type $resource-type;" in tql

    def test_class_without_attributes(self):
        tql = TqlBuilder(model.Adversary).as_tql()
        assert tql == "$adversary isa adversary;"

    def test_basic_relation(self):
        tql = TqlBuilder(model.Relation).as_tql()
        assert tql.startswith("$relation isa relation;")

    @pytest.mark.parametrize(
        "relation",
        [
            model.Implication,
            model.Ability,
            model.RunInWorkload,
        ],
    )
    def test_relation_with_required_references(self, relation):
        tql = TqlBuilder(relation).as_tql()
        required_fields = model.get_required_fields(relation)

        # part of the relation definition '(...)' in the query
        for field in required_fields:
            assert f"{field}: ${field}" in tql

    def test_relation_with_recursive_required_fields(self):
        tql = TqlBuilder(model.CanReach).as_tql()

        assert f"$can-reach (source: $source, destination: $destination) isa can-reach" in tql
        assert f"$source has name $source-name" in tql
        assert f"$destination has name $destination-name" in tql

    def test_required_union_type_field_take_only_insersection_of_required_field(self):
        class TmpBase(BaseModel):
            name: str

        class A(TmpBase):
            a_specific: str

        class B(TmpBase):
            b_specific: str | None = None

        class Both(BaseModel):
            attr: Annotated[A | B, RelationPart.Source]

        tql = TqlBuilder(Both).as_tql()

        main_tql, attr_tql, *rest = [t.strip() for t in tql.split(";") if len(t) > 0]
        assert main_tql == "$both (attr: $attr) isa both"
        assert attr_tql.strip() == "$attr has name $attr-name"
        assert len(rest) == 0  # no left over after last ';'

    @pytest.mark.parametrize("action", [model.DenialOfService, model.ExploitVulnerability, model.DeployPod])
    def test_action_with_required_references(self, action):
        tql = TqlBuilder(action).as_tql()
        required_fields = model.get_required_fields(action)

        # part of the relation definition '(...)' in the query
        for field in required_fields:
            assert f"{field}: ${field}" in tql

    @pytest.mark.parametrize(
        "capability", [model.CanRead, model.CanWrite, model.CanExecute, model.CanCreate, model.Capability]
    )
    def test_capability_relates_requires_and_environment(self, capability):
        tql = TqlBuilder(capability).as_tql()
        meta_infos = model.get_meta_infos(capability)
        # TODO: maybe generalize "get_required_fields" function?
        required_fields = [
            name
            for name, field in capability.model_fields.items()
            if meta_infos[name].get(model.FieldConfig.Required, False) and not is_primitive(field)
        ]

        # part of the relation definition '(...)' in the query
        for field in required_fields:
            assert f"{field}: ${field}" in tql

    def test_mandatory_attributes_of_referenced_objects_are_appended(self):
        tql = TqlBuilder(model.VolumeMount).as_tql()

        main_tql, constaints_tql = tql.split(";", 1)
        assert main_tql.startswith("$volume-mount (user: $user, volume: $volume) isa volume-mount")
        assert "$volume has name $volume-name" in constaints_tql

    def test_add_subtypes_to_query(self):
        class DummyAdversary(model.Adversary):
            name: str = "dummy"

        tql = TqlBuilder(model.Adversary).as_tql(include_subtypes=True)

        dummy_type_name = to_kebab_case(DummyAdversary.__name__)
        assert f"${dummy_type_name} isa {dummy_type_name};" in tql


def test_ip_addr_conversion():
    class Dummy(model.DomainObject):
        ip: model.IpAddress

    ip = ip_address(address="127.0.0.1")
    tmp = Dummy(ip=model.IpAddress(ip=ip))
    tql = TqlBuilder(tmp).as_tql()
    assert f"has ip $ip" in tql
    assert "$ip isa ip" in tql
    assert f"has ip-value {int(ip)}" in tql
    assert f'$ip "{str(ip)}"' in tql


class TestCidrConvers:
    def test_basic_cidr_conversion(self):
        ip_addr = "192.168.0.1/24"
        cidr = model.Cidr(cidr=ip_addr)
        tql = TqlBuilder(cidr).as_tql()
        assert "$cidr isa cidr" in tql

    def test_cidr_string_is_the_value(self):
        class Dummy(model.DomainObject):
            cidr: model.Cidr

        ip_addr = "192.168.0.1/24"
        cidr = Dummy(cidr=model.Cidr(cidr=ip_addr))
        tql = TqlBuilder(cidr).as_tql()
        assert f'$cidr "{ip_addr}"' in tql

    def test_cidr_specify_ip_range_as_long(self):
        ip_addr = "192.168.0.1/24"
        cidr = model.Cidr(cidr=ip_addr)
        tql = TqlBuilder(cidr).as_tql()

        assert cidr.min_ip_value is not None
        assert f"has min-ip-value {cidr.min_ip_value}" in tql
        assert cidr.max_ip_value is not None
        assert f"has max-ip-value {cidr.max_ip_value}" in tql
