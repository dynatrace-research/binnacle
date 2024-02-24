import ipaddress

import pytest
from pydantic import ValidationError

from binnacle import model


class TestEnvVarSourceFieldsAreMutuallyExclusive:
    def test_only_set_value_is_valid(self):
        value = "a value"
        m = model.EnvVar(name="a-name", var_value=value)

        assert m.var_value == value
        assert m.value_from is None

    def test_only_set_valuefrom_is_valid(self):
        var_src = model.EnvVarSource(config_map_key_ref="anything")
        m = model.EnvVar(name="a-name", value_from=var_src)

        assert m.var_value is None
        assert m.value_from == var_src

    def test_setting_both_is_invalid(self):
        value = "a value"
        var_src = model.EnvVarSource(config_map_key_ref="anything")

        with pytest.raises(ValidationError):
            model.EnvVar(name="a-name", var_value=value, value_from=var_src)


class TestK8sObject:
    def test_kind_is_mapped_to_resource_type_format(self):
        ns = "default"
        objects = [
            model.Pod(name="", namespace=ns),
            model.Deployment(name="", namespace=ns),
            model.Namespace(name=ns),
            model.Service(name="", namespace=ns),
            model.Role(name="", namespace=ns),
            model.RoleBinding(name="", namespace=ns),
        ]
        for obj in objects:
            expected_res_type = obj.kind.lower() + "s"
            assert obj.resource_type == expected_res_type

    def test_irregular_kinds_are_mapped_to_resource_type_format(self):
        ns = "default"
        objects = [
            (model.Ingress(name="", namespace=ns, rules=[]), "ingresses"),
            # "ingressesclasses": "IngressClass",
            # "networkpolicies": "NetworkPolicy",
            # "runtimeclasses": "RuntimeClass",
            # "priorityclasses": "PriorityClass",
            # "csistoragecapacities": "CsiStorageCapacity",
            # "storageclasses": "StorageClass",
        ]
        for obj, expected in objects:
            assert obj.resource_type == expected


class TestCidr:
    def test_infer_min_max_ip_from_cidr_notation(self):
        cidr = model.Cidr(cidr="192.168.0.1/24")
        assert cidr.min_ip_value == int(ipaddress.IPv4Address("192.168.0.0"))
        assert cidr.max_ip_value == int(ipaddress.IPv4Address("192.168.0.255"))

    def test_all_zeros_cidr_encompasses_all_ips(self):
        cidr = model.Cidr(cidr="0.0.0.0/0")
        assert cidr.min_ip_value == int(ipaddress.IPv4Address("0.0.0.0"))
        assert cidr.max_ip_value == int(ipaddress.IPv4Address("255.255.255.255"))
