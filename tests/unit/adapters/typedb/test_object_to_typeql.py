import pytest

from binnacle import model
from binnacle.adapters.typedb.object_to_typeql import (
    TqlBuilder,
    get_insert_query,
    get_var_from_tql,
    to_typeql,
)
from binnacle.model.k8s_object import Container, Pod
from binnacle.utils import to_kebab_case


class TestSpecialFieldMapping:
    def test_can_be_variable_without_value(self):
        field = model.SpecialField(is_variable=True)
        attr = "attr"
        builder = TqlBuilder()
        tql, _ = builder._format_attribute(attr, field)
        assert tql == f"has {attr} ${attr}"

    def test_can_be_regex_pattern(self):
        pattern = ".*"
        field = model.SpecialField(regex=pattern)
        attr = "attr"
        builder = TqlBuilder()
        tql, _ = builder._format_attribute(attr, field)
        assert tql == f"has {attr} ${attr}"

    def test_regex_is_explicit_contraint(self):
        pattern = ".*"
        field = model.SpecialField(regex=pattern)
        attr = "attr"
        builder = TqlBuilder()
        _, constraint = builder._format_attribute(attr, field)
        assert constraint == f'${attr} like "{pattern}"'

    def test_regex_takes_precedence_if_its_also_a_variable(self):
        pattern = ".*"
        field = model.SpecialField(is_variable=True, regex=pattern)
        attr = "attr"
        builder = TqlBuilder()
        tql, constraint = builder._format_attribute(attr, field)
        assert tql == f"has {attr} ${attr}"
        assert constraint == f'${attr} like "{pattern}"'


class TestNamespacedObjectMapping:
    def test_namespace_can_be_special_field(self):
        obj = model.NamespacedObject(name="a-object", namespace=model.SpecialField(is_variable=True), kind="unknown")
        tql = to_typeql(obj)
        assert "has ns $ns" in tql


class TestPodMapping:
    def test_minimal_pod(self):
        pod_name = "pod"
        ns = "ns"
        pod = Pod(name=pod_name, namespace=ns)
        tql = TqlBuilder(pod).as_tql()

        assert "$pod isa pod" in tql
        assert f'has name "{pod_name}"' in tql
        assert 'has kind "Pod"' in tql
        assert f'has ns "{ns}"' in tql

    def test_with_regex_name_adds_constraint_at_the_end(self):
        pod_name = "*pod*"
        pod = Pod(name=model.SpecialField(regex=pod_name), namespace="default")
        tql = TqlBuilder(pod).as_tql()

        assert f'$name like "{pod_name}"' in tql

    def test_pod_with_service_account(self):
        pod_name = "pod"
        ns = "ns"
        sa_name = "a-service-account"
        pod = Pod(name=pod_name, namespace=ns, automount_service_account_token=True, service_account_name=sa_name)
        tql = TqlBuilder(pod).as_tql()

        assert f'has service-account-name "{sa_name}"' in tql
        assert "has automount-service-account-token true" in tql

    def test_pod_with_image_pull_secrets(self):
        secrets = [model.ObjectReference(name=n) for n in ["secret-1", "secret-2"]]
        pod = Pod(name="a-pod", namespace="default", image_pull_secrets=secrets)
        tql = TqlBuilder(pod).as_tql()

        for secret in secrets:
            assert f'has secret "{secret.name}"' in tql

    def test_container_is_not_part_of_typeql_conversion(self):
        container_name = "my-container"
        c = Container(name=container_name, image_name="my-image")
        pod = Pod(name="pod", namespace="ns", containers=[c])
        tql = TqlBuilder(pod).as_tql()

        # only referenc to container is in tql
        assert "isa container" not in tql
        assert "(" not in tql

    def test_provided_commands_are_escaped(self):
        command = 'sh -cecho "test"'
        c = Container(name="a-container", image_name="my-image", command=command)
        tql = tql = TqlBuilder(c).as_tql()
        expected_cmd = "".join((c.replace('"', '\\"') for c in command))
        assert f'has command "{expected_cmd}"' in tql

    def test_provided_args_are_escaped(self):
        args = 'sh -c echo "test"'
        c = Container(name="a-container", image_name="my-image", command="/bin/sh -c", args=args)
        tql = tql = TqlBuilder(c).as_tql()
        expected_args = "".join((a.replace('"', '\\"') for a in args))
        assert f'has args "{expected_args}"' in tql

    def test_pod_with_container_has_additional_contains_and_container_insert_query(self):
        c = model.Container(name="container", image_name="my-image")
        pod = model.Pod(name="pod", namespace="ns", containers=[c])
        queries = get_insert_query(pod)
        assert len(queries) == 1

        pod_insert, container_insert, contains_insert = [q + ";" for q in queries[0].split("; ")]

        expected_pod_tql = TqlBuilder(pod).as_tql()
        assert expected_pod_tql in pod_insert

        container_var = f"container_{c.name}"
        expected_container_tql = to_typeql(c, container=container_var)
        assert expected_container_tql in container_insert

        contains = model.Contains(container=pod, thing=c)
        expected_contains_tql = to_typeql(contains, var_name=f"contains_{c.name}", thing=container_var)
        assert expected_contains_tql in contains_insert

    def test_pod_with_multiple_containers(self):
        container_names = ["container_1", "container_2"]
        containers = [model.Container(name=cname, image_name="my-image") for cname in container_names]
        pod = model.Pod(
            name="pod",
            namespace="ns",
            containers=containers,
        )

        queries = get_insert_query(pod)
        queries = [q + ";" for q in queries[0].split("; ")]
        # per container insert actual container and the 'contains' relation
        assert len(queries) == len(containers) * 2 + 1

    def test_pod_with_multiple_containers_uses_unique_variable_names(self):
        container_names = ["foo", "bar"]
        containers = [model.Container(name=cname, image_name="my-image") for cname in container_names]
        pod = model.Pod(
            name="pod",
            namespace="ns",
            containers=containers,
        )

        queries = get_insert_query(pod)
        queries = queries[0].split("; ")
        # per container insert actual container and the 'contains' relation
        for container_name in container_names:
            container_var = f"$container_{container_name}"
            contains_query = [
                tql for tql in queries if f"$contains_{container_name} (" in tql and f"thing: {container_var}" in tql
            ]
            assert len(contains_query) == 1
            container_query = [tql for tql in queries if f"{container_var} isa container" in tql]
            assert len(container_query) == 1

    def test_pod_with_volume_references(self):
        vol_name = "root-fs"
        pod = Pod(name="pod", namespace="ns", volumes=[model.Volume(name=vol_name)])
        tql = TqlBuilder(pod).as_tql()

        assert f'has volume-name "{vol_name}"' in tql


class TestContainerMapping:
    def test_minimal_container_to_typeql(self):
        name = "my-container"
        img_name = "my-image"
        c = model.Container(name=name, image_name=img_name)
        tql = TqlBuilder(c).as_tql()

        assert f'$container isa container, has container-name "{name}", has image-name "{img_name}"' in tql

    def test_container_ports_are_attributes(self):
        port_name = "web-port"
        port_number = 80
        port = model.ContainerPort(number=port_number, name=port_name)
        c = model.Container(name="my-container", image_name="my-image", ports=[port])
        tql = TqlBuilder(c).as_tql()
        assert "has port" in tql
        assert port_name in tql

    def test_variables_prefixed_with_container_variable_name(self):
        cname = "my-container"
        port_number = 8080
        port = model.ContainerPort(number=port_number)
        env_var_name = "my-env"
        env_var = model.EnvVar(name=env_var_name)
        container = model.Container(name=cname, image_name="my-image", ports=[port], env_vars=[env_var])

        tql = TqlBuilder(container).as_tql(var_name=cname, prefix_fields=True)
        assert f"{cname}_container-port_" in tql
        assert f"{cname}_env-var_" in tql

    def test_env_from_sources_are_attributes(self):
        secret_name = "my-secret"
        env_from_src = model.EnvFromSource(secret_ref=model.SecretEnvSource(name=secret_name))
        c = model.Container(name="my-container", image_name="my-image", env_from_sources=[env_from_src])

        tql = TqlBuilder(c).as_tql()
        assert "has env-from-source" in tql

    def test_environment_variables_are_attributes(self):
        ev_name = "ENV_VAR_NAME"
        ev_value = "ENV_VAR_VALUE"
        env_vars = [model.EnvVar(name=ev_name, var_value=ev_value)]
        c = model.Container(name="my-container", image_name="my-image", env_vars=env_vars)

        tql = TqlBuilder(c).as_tql()
        assert "has env-var" in tql

    class TestEnvValueFromSecretKeyRef:
        def test_environment_variable_value_from_source(self):
            env_var = "ENV_VAR_NAME"
            secret_name = "my-secret"
            key = "password"
            secret_ref = model.SecretKeySelector(secret_name=secret_name, secret_key=key)
            var_value_src = model.EnvVarSource(secret_key_ref=secret_ref)
            env_vars = [model.EnvVar(name=env_var, value_from=var_value_src)]
            c = model.Container(name="my-container", image_name="my-image", env_vars=env_vars)

            tql = TqlBuilder(c).as_tql()
            assert "has env-var" in tql

    def test_insert_container_with_env_from_source(self):
        secret_name = "my-secret"
        pfx = "my-pfx"
        env_from_src = model.EnvFromSource(secret_ref=model.SecretEnvSource(name=secret_name), prefix=pfx)
        c = model.Container(name="my-container", image_name="my-image",
            # env_vars=[model.EnvVar(name="test",var_value="test_value")],
                             env_from_sources=[env_from_src])

        tql = to_typeql(c)

        assert f'$sr-my-secret "{secret_name}" isa secret-env-source' in tql
        assert (
            f'$ef_my-secret "{secret_name}" isa env-from-source, has prefix "{pfx}", has secret-env-source $sr-my-secret'
            in tql
        )
        assert f"has env-from-source $ef_my-secret" in tql

    def test_container_with_volume_mount_has_its_name_as_attribute(self):
        vol_mount_name = "my-vol-mount"
        vol_mount = model.VolumeMount(name=vol_mount_name, mount_path="/opt/data")
        container_name = "my-container"
        c = model.Container(name=container_name, image_name="my-image", volume_mounts=[vol_mount])
        tql = to_typeql(c)

        assert f'has volume-mount-name "{vol_mount_name}"' in tql

    def test_container_with_volume_mounts_has_multiple_insert_queries(self):
        vol_mount = model.VolumeMount(name="my-vol-mount", mount_path="/opt/data")
        container_name = "my-container"
        c = model.Container(name=container_name, image_name="my-image", volume_mounts=[vol_mount])
        queries = get_insert_query(c)
        assert len(queries) == 2

        container_insert, vol_mount_insert = queries
        assert container_insert == f"insert {to_typeql(c)}"

        # vol_mount_insert is a relation, so it must also refer the container name in its insert query
        assert container_name in vol_mount_insert

    def test_volume_mount_insert_query_is_a_relation(self):
        vol_mount = model.VolumeMount(name="my-vol-mount", mount_path="/opt/data")
        container_name = "my-container"
        c = model.Container(name=container_name, image_name="my-image", volume_mounts=[vol_mount])
        _, query = get_insert_query(vol_mount, c)

        match_part, insert_part = query.split("insert")
        vol_var = container_var = ""
        for m in match_part.split(";"):
            if "isa container" in m:
                container_var = get_var_from_tql(m)
            elif "isa volume" in m:
                vol_var = get_var_from_tql(m)

        assert "isa volume-mount" in insert_part
        assert f"user: ${container_var}" in insert_part
        assert f"volume: ${vol_var}" in insert_part


class TestDeploymentMapping:
    def test_basic_deployment(self):
        name = "a-deployment"
        replicas = 2
        ns = "default"
        depl = model.Deployment(name=name, namespace=ns, replicas=replicas, selector={})
        tql = to_typeql(depl)

        assert f'has name "{name}"' in tql
        assert "$deployment isa deployment" in tql
        assert f"has replicas {replicas}" in tql

    def test_deployment_with_selector(self):
        name = "a-deployment"
        selector = {"app-name": "my-app", "part-of": "binnacle"}
        depl = model.Deployment(name=name, namespace="default", replicas=1, selector=selector)
        tql = to_typeql(depl)

        for k, v in selector.items():
            assert f'has selector "{k}:{v}"' in tql

    def test_pods_are_inserted_independently(self):
        ns = "default"
        pods = [model.Pod(name="pod-1", namespace=ns), model.Pod(name="pod-2", namespace=ns)]
        name = "a-deployment"
        depl = model.Deployment(name=name, namespace=ns, replicas=1, selector={}, pods=pods)
        tql = to_typeql(depl)

        assert "has pod" not in tql
        for p in pods:
            assert p.name not in tql


class TestServiceMapping:
    def test_basic_service(self):
        name = "a-service"
        ns = "default"
        service = model.Service(name=name, namespace=ns, ports=[], selector={})
        tql = to_typeql(service)
        assert "$service isa service" in tql
        assert f'has name "{name}"' in tql
        assert "has cluster-ip" not in tql

    def test_service_type_defaults_to_cluster_ip(self):
        service = model.Service(name="a-service", namespace="default", ports=[], selector={})
        tql = to_typeql(service)
        assert 'has service-type "ClusterIP"' in tql

    def test_service_with_service_type(self):
        service_type = model.ServiceType.NodePort
        service = model.Service(name="a-service", namespace="default", ports=[], selector={}, type=service_type)
        tql = to_typeql(service)
        assert f'has service-type "{service_type}"' in tql

    def test_service_with_selector(self):
        selector = {"app-name": "my-app", "part-of": "binnacle"}
        service = model.Service(name="a-service", namespace="default", selector=selector, ports=[])
        tql = to_typeql(service)

        for k, v in selector.items():
            assert f'has selector "{k}:{v}"' in tql

    class TestServicePortMapping:
        def test_service_with_ports(self):
            ports = [model.ServicePort(number=nr) for nr in [80, 443]]
            service = model.Service(name="a-service", namespace="default", ports=ports, selector={})
            tql = to_typeql(service)
            for p in ports:
                assert f"isa service-port, has port-number {p.number}" in tql

        def test_service_with_port_names(self):
            ports = [model.ServicePort(number=nr, name=name) for nr, name in [(80, "http"), (443, "https")]]
            service = model.Service(name="a-service", namespace="default", ports=ports, selector={})
            tql = to_typeql(service)
            for p in ports:
                assert f'has port-name "{p.name}"' in tql

        def test_service_port_target_port_can_be_int(self):
            port_nr = 80
            svc_port = model.ServicePort(number=80, target_port=port_nr)
            tql = to_typeql(svc_port)
            assert f"target_port isa target-port, has port-number {port_nr}" in tql

        def test_service_port_target_port_can_be_str(self):
            port_name = "http"
            svc_port = model.ServicePort(number=80, target_port=port_name)
            tql = to_typeql(svc_port)
            assert f'target_port isa target-port, has port-name "{port_name}"' in tql

        def test_service_port_target_port_can_be_actual_port(self):
            port_nr = 80
            port_name = "http"
            target_port = model.TargetPort(number=port_nr, name=port_name)
            svc_port = model.ServicePort(number=443, target_port=target_port)
            tql = to_typeql(svc_port)
            assert f"target_port isa target-port" in tql
            assert f'has port-name "{port_name}"' in tql
            assert f"has port-number {port_nr}" in tql

        def test_target_port_is_port_attribute(self):
            ports = [model.ServicePort(number=nr, target_port=nr) for nr in [80, 443]]
            service = model.Service(name="a-service", namespace="default", ports=ports, selector={})
            tql = to_typeql(service)
            for p in ports:
                assert f'_target_port "{p.target_port.value}"' in tql


class TestIngressMapping:
    def test_basic_ingress(self):
        name = "my-ingress"
        ns = "my-namespace"
        ingress = model.Ingress(name=name, namespace=ns)

        tql = to_typeql(ingress)

        assert tql.startswith("$ingress isa ingress")
        assert f'has name "{name}"' in tql
        assert f'has  "{ns}"'

    @pytest.mark.parametrize("field,value", [("name", "http"), ("number", 8080)])
    def test_service_backend_port(self, field, value):
        port = model.ServiceBackendPort(**{field: value})
        tql = TqlBuilder(port).as_tql()

        type = "service-backend-port"
        assert tql.startswith(f"${type} isa {type}")

        exp_value = f'"{value}"' if isinstance(value, str) else value
        # the field names are prefixed with 'port-'
        assert f"has port-{field} {exp_value}" in tql

    def test_ingress_service_backend(self):
        service_name = "my-service"
        backend = model.IngressServiceBackend(name=service_name, port=model.ServiceBackendPort(name="port-name"))

        tql = TqlBuilder(backend).as_tql()
        type = "ingress-service-backend"
        assert tql.startswith(f"${type} isa {type}")
        assert f'has backend-type "Service"' in tql
        assert f'has name "{service_name}"' in tql
        assert f"has service-backend-port $port" in tql

    def test_ingress_resource_backend(self):
        ref_name = "a-ref"
        ref = model.ObjectReference(name=ref_name)
        backend = model.IngressResourceBackend(reference=ref)

        tql = TqlBuilder(backend).as_tql()
        type = "ingress-resource-backend"
        assert tql.startswith(f"${type} isa {type}")
        assert f'has backend-type "Resource"' in tql
        assert f'has reference "{ref_name}"' in tql

    def test_ingress_path_owns_backend_with_service(self):
        service_name = "my-service"
        backend = model.IngressServiceBackend(name=service_name, port=model.ServiceBackendPort(name="port-name"))

        tql = TqlBuilder(backend).as_tql()
        type = "ingress-service-backend"
        assert tql.startswith(f"${type} isa {type}")
        assert f'has backend-type "Service"' in tql
        assert f'has name "{service_name}"' in tql
        assert f"has service-backend-port $port" in tql

    def test_insert_ingress_with_single_rule_adds_ruleset_relation(self):
        host = "my.host"
        ingress_path = model.HttpIngressPath(path="/", path_type=model.IngressPathType.Prefix)
        backend = model.IngressResourceBackend(reference=model.ObjectReference(name="a-ref"))
        rules = [model.IngressRule(host=host, path=ingress_path, backend=backend)]

        ingress = model.Ingress(name="my-ingress", namespace="default", rules=rules)
        tql = get_insert_query(ingress)
        assert len(tql) == 1
        tql = tql[0]

        for i, rule in enumerate(rules):
            var_name = f"$rule_{i}"
            assert f"isa ingress-rule" in tql
            assert f"(owner: $ingress, entry: {var_name}) isa ingress-ruleset" in tql

    class TestIngressPathMapping:
        def test_ingress_path_(self):
            path = "/my-path"
            path_type = model.IngressPathType.Prefix
            ingress_path = model.HttpIngressPath(path=path, path_type=path_type)
            tql = to_typeql(ingress_path)
            type = "http-ingress-path"
            assert tql.startswith(f"${type} isa {type}")
            assert f'has path "{path}"' in tql
            assert f'has ingress-path-type "{path_type}"'

    class TestIngressBackendMapping:
        def test_service_backend_port_with_port_number(self):
            number = 8080
            port = model.ServiceBackendPort(number=number)
            tql = to_typeql(port)
            type = "service-backend-port"
            assert tql.startswith(f"${type} isa {type}")
            assert f"has port-number {number}" in tql

        def test_service_backend_port_with_port_name(self):
            name = "http-port"
            port = model.ServiceBackendPort(name=name)
            tql = to_typeql(port)
            type = "service-backend-port"
            assert tql.startswith(f"${type} isa {type}")
            assert f'has port-name "{name}"' in tql

        def test_basic_service_backend(self):
            svc_name = "a-service"
            port = model.ServiceBackendPort(number=8080)
            backend = model.IngressServiceBackend(name=svc_name, port=port)
            tql = to_typeql(backend)
            type = "ingress-service-backend"
            assert tql.startswith(f"${type} isa {type}")
            assert 'has backend-type "Service"' in tql
            assert f'has name "{svc_name}"' in tql
            assert f"has service-backend-port $port" in tql

    class TestIngressRuleMapping:
        def test_ingress_rule_isa_relatinship(self):
            path = model.HttpIngressPath(path="/")
            backend = model.IngressServiceBackend(name="my-service", port=model.ServiceBackendPort(number=8080))
            host = "binnacle.com"

            rule = model.IngressRule(host=host, path=path, backend=backend)
            tql = to_typeql(rule)
            type = "ingress-rule"
            assert tql.startswith(f"${type} (path: $http-ingress-path, backend: $ingress-service-backend) isa {type}")

            assert f'has host "{host}"' in tql

        def test_insert_ingress_rule_also_inserts_path_and_backend(self):
            path = model.HttpIngressPath(path="/")
            backend = model.IngressServiceBackend(name="my-service", port=model.ServiceBackendPort(number=8080))
            host = "binnacle.com"

            rule = model.IngressRule(host=host, path=path, backend=backend)
            rule_name = "my-rule"
            tql = get_insert_query(rule, rule_name)
            assert len(tql) == 3
            rule_tql, path_tql, backend_tql = tql

            path_var = get_var_from_tql(path_tql)
            backend_var = get_var_from_tql(backend_tql)

            type = "ingress-rule"
            assert rule_tql.startswith(f"${rule_name} (path: ${path_var}, backend: ${backend_var}) isa {type}")
            assert f'has host "{host}"' in rule_tql

            assert path_tql.startswith(f"${path_var} isa http-ingress-path")
            assert backend_tql.startswith(f"${backend_var} isa ingress-service-backend")


class TestServiceAccountMapping:
    def test_basic_service_account(self):
        name = "my-sa"
        ns = "default"
        sa = model.ServiceAccount(name=name, namespace=ns)
        tql = to_typeql(sa)

        assert f'has name "{name}"' in tql
        assert "isa service-account" in tql

    def test_automount_sa_token_is_optional(self):
        sa_without = model.ServiceAccount(name="my-sa", namespace="default")
        tql = to_typeql(sa_without)
        assert f"has automount-service-account-token" not in tql

        sa_with = model.ServiceAccount(name="my-sa", namespace="default", automount_service_account_token=True)
        tql = to_typeql(sa_with)
        assert f"has automount-service-account-token true" in tql

    def test_service_account_can_has_multiple_secrets(self):
        secrets = [model.ObjectReference(name="secret-1"), model.ObjectReference(name="secret-2")]
        sa = model.ServiceAccount(name="my-sa", namespace="default", secrets=secrets)
        tql = to_typeql(sa)

        for s in secrets:
            assert f'has secret-name "{s.name}"' in tql


class TestSecretMapping:
    def test_basic_secret(self):
        name = "my-secret"
        secret = model.Secret(name=name, namespace="default")
        tql = to_typeql(secret)

        assert f'has name "{name}"' in tql
        assert "isa secret" in tql

    def test_secret_type_defaults_to_opaque(self):
        secret = model.Secret(name="my-secret", namespace="default")
        tql = to_typeql(secret)

        assert f'has secret-type "{str(model.SecretType.Opaque)}"' in tql

    def test_sa_name_is_optional(self):
        secret_without = model.Secret(name="my-sa", namespace="default")
        tql = to_typeql(secret_without)
        assert f"has service-account-name" not in tql

        sa_name = "my-sa"
        secret_with = model.Secret(name="my-sa", namespace="default", sa_name=sa_name)
        tql = to_typeql(secret_with)
        assert f'has service-account-name "{sa_name}"' in tql

    def test_data_is_not_mapped(self):
        data = {"secret-entry": "top-secret!"}
        secret = model.Secret(name="my-sa", namespace="default", data=data)
        tql = to_typeql(secret)
        for k, v in data.items():
            assert k not in tql
            assert v not in tql


class TestRbacMapping:
    class TestRole:
        def test_basic_role(self):
            name = "a-role"
            ns = "default"
            role = model.Role(name=name, namespace=ns)
            tql = to_typeql(role)

            assert "isa role" in tql
            assert f'has name "{name}"' in tql
            assert f'has ns "{ns}"' in tql

        def test_rules_are_not_attributes(self):
            rules = [
                model.RbacRule(api_groups=[""], verbs=["create"], resources=["pods/exec"], resource_names=None),
            ]
            role = model.Role(name="a-role", namespace="default", rules=rules)
            tql = to_typeql(role)

            assert f"has rbac-rule" not in tql
            assert f"has rule" not in tql

        def test_relation_to_rule_is_added_for_insert(self):
            rules = [
                model.RbacRule(
                    api_groups=[""], verbs=["create", "list", "get"], resources=["pods"], resource_names=None
                ),
                model.RbacRule(api_groups=[""], verbs=["create"], resources=["pods/exec"], resource_names=None),
            ]
            role = model.Role(name="a-role", namespace="default", rules=rules)
            [tql] = get_insert_query(role)

            rule_names = [get_var_from_tql(s) for s in tql.split(";") if "isa rbac-rule" in s]
            for rule_name in rule_names:
                assert f"(owner: $role, entry: ${rule_name}) isa ruleset" in tql

    class TestBindingEntity:
        def test_basic_role_ref(self):
            name = "a-role"
            role_ref = model.RoleRef(name=name, api_group="rbac.authorization.k8s.io")
            tql = to_typeql(role_ref)

            # NOTE: here the kind is not the model type, but the 'kind' field it refers to!
            assert f"isa {role_ref.kind.lower()}" in tql
            assert f'has name "{name}"' in tql

        def test_basic_role_ref_may_point_to_clusterrole(self):
            name = "a-role"
            kind = "ClusterRole"
            role_ref = model.RoleRef(name=name, kind=kind, api_group="rbac.authorization.k8s.io")
            tql = to_typeql(role_ref)

            # NOTE: here the kind is not the model type, but the 'kind' field it refers to!
            expected_type = to_kebab_case(kind)
            assert f"isa {expected_type}" in tql
            assert f'has name "{name}"' in tql

        def test_basic_rbac_subject(self):
            name = "a-subject"
            kind = "user"
            subject = model.RbacSubject(name=name, kind=kind, api_group="rbac.authorization.k8s.io")
            tql = to_typeql(subject)

            # NOTE: here the kind is not the model type, but the 'kind' field it refers to!
            assert f"isa {kind.lower()}" in tql
            assert f'has name "{name}"' in tql

        @pytest.mark.parametrize("kind", ["service-account", "user", "group"])
        def test_rbac_subject_may_be_of_kind(self, kind: str):
            subject = model.RbacSubject(name="a-subject", kind=kind, api_group="rbac.authorization.k8s.io")
            tql = to_typeql(subject)

            # NOTE: here the kind is not the model type, but the 'kind' field it refers to!
            assert f"isa {kind}" in tql

        def test_rbac_subjects_is_namespaced(self):
            ns = "my-namespace"
            subject = model.RbacSubject(
                name="a-subject", kind="service-account", ns=ns, api_group="rbac.authorization.k8s.io"
            )
            tql = to_typeql(subject)
            assert f'has ns "{ns}"' in tql

        @pytest.mark.parametrize("kind", ["user", "group"])
        def test_rbac_subjects_user_or_group_must_not_have_namespace(self, kind: str):
            subject = model.RbacSubject(
                name="a-subject", kind=kind, ns="invalid-ns", api_group="rbac.authorization.k8s.io"
            )
            tql = to_typeql(subject)
            assert f"has ns" not in tql

    class TestRbacRule:
        def test_basic_rbac_rule(self):
            resources = ["pods"]
            verbs = ["create", "list", "get"]
            api_groups = ["apps"]
            res_names = ["admin", "edit", "view"]
            rule = model.RbacRule(api_groups=api_groups, verbs=verbs, resources=resources, resource_names=res_names)

            var_name = "my-rbac-rule"

            tql = to_typeql(rule, var_name=var_name)
            assert f"${var_name} isa rbac-rule" in tql

            for res in resources:
                assert f'has resource-type "{res}"' in tql

            for v in verbs:
                assert f'has verb "{v}"' in tql

            for group in api_groups:
                assert f'has api-group "{group}"' in tql

            for res_name in res_names:
                assert f'has resource-name "{res_name}"' in tql

        def test_empty_string_is_valid_apigroup(self):
            api_groups = [""]
            rule = model.RbacRule(api_groups=api_groups, verbs=[], resources=[])
            tql = to_typeql(rule)

            assert f'has api-group ""' in tql

        def test_wildcard_is_valid_for_verb_and_resource(self):
            verbs = ["*"]
            resources = ["*"]
            rule = model.RbacRule(api_groups=[], verbs=verbs, resources=resources)
            tql = to_typeql(rule)

            assert f'has verb "*"' in tql
            assert f'has resource-type "*"' in tql

        def test_resource_names_are_optional(self):
            rule = model.RbacRule(api_groups=[], verbs=[], resources=[])
            tql = to_typeql(rule)

            assert "has resource-name" not in tql


class TestNetworkPolicyMapping:
    def test_basic_network_policy_with_no_policy_types(self):
        name = "my-network-policy"
        pod_selector = model.PodSelector(entries={"app-name": "my-app", "part-of": "binnacle"})
        netpol = model.NetworkPolicy(name=name, pod_selector=pod_selector)
        tql = to_typeql(netpol)
        assert tql.startswith("$network-policy isa network-policy")

        for sel in pod_selector.items():
            assert f'has pod-selector "{sel}"' in tql

    def test_insert_policy_with_rules_has_a_ruleset(self):
        peer = model.NetworkPolicyPeer(pod_selector=model.PodSelector(select_all=True))
        port_number = 8080
        port = model.NetworkPolicyPort(port=port_number)
        ingress_rule = model.NetworkPolicyIngressRule(peers=[peer], ports=[port])
        net_pol = model.NetworkPolicy(
            name="my-netpol", pod_selector=model.PodSelector(select_all=True), ingress_rules=[ingress_rule]
        )

        [tql] = get_insert_query(net_pol)
        assert "owner: $network-policy" in tql
        assert "isa network-policy-ruleset" in tql

    @pytest.mark.parametrize("policy_types", [["Ingress"], ["Egress"], ["Ingress", "Egress"], []])
    def test_network_policy_types(self, policy_types: list[str]):
        netpol = model.NetworkPolicy(
            name="my-policy-type", pod_selector=model.PodSelector(select_all=True), policy_types=policy_types
        )
        tql = to_typeql(netpol)

        for pol_type in policy_types:
            assert f'has policy-type "{pol_type}"' in tql

    def test_empty_pod_selector_is_mapped_to_asterisk(self):
        # TODO: find a way to influence behaviour of label selector from 'outside', i.e it's default behavior
        netpol = model.NetworkPolicy(name="my-policy-type", pod_selector=model.PodSelector(select_all=True))
        tql = to_typeql(netpol)

        assert f"has pod-selector" in tql
        assert f'pod-selector "*"' in tql

    class TestNetworkPolicyRuleMapping:
        def test_network_policy_rule_is_a_relation(self):
            peer = model.NetworkPolicyPeer(pod_selector=model.PodSelector(select_all=True))
            rule = model.NetworkPolicyIngressRule(peers=[peer])

            tql = to_typeql(rule)
            expected_type = to_kebab_case(type(rule).__name__)
            assert f"${expected_type} (peer: $network-policy-peer) isa {expected_type}" in tql

        def test_insert_network_policy_ingress_rule(self):
            peer = model.NetworkPolicyPeer(pod_selector=model.PodSelector(select_all=True))
            rule = model.NetworkPolicyIngressRule(peers=[peer])

            tqls = get_insert_query(rule)
            assert len(tqls) == 2
            rule_tql, peer_tql = tqls
            expected_type = to_kebab_case(type(rule).__name__)
            assert f"${expected_type} (peer: ${expected_type}-peer) isa {expected_type}" in rule_tql

        def test_insert_ingress_rule_peer_var_must_match_with_its_relation_var(self):
            port_number = 8080
            port = model.NetworkPolicyPort(port=port_number)
            peer = model.NetworkPolicyPeer(pod_selector=model.PodSelector(select_all=True))
            rule = model.NetworkPolicyIngressRule(peers=[peer], ports=[port])

            tqls = get_insert_query(rule)
            assert len(tqls) == 3
            rule_tql, peer_tql, port_tql = tqls
            expected_type = to_kebab_case(type(rule).__name__)

            expected_peer_var = f"${expected_type}-peer"  # no sfx, because it's just 1 entry
            peer_type = to_kebab_case(type(peer).__name__)
            assert f"{expected_peer_var} isa {peer_type}" in peer_tql

            port_var = f"${expected_type}-port"
            port_type = "network-policy-port"

            assert f"target-port: {port_var}" in rule_tql
            assert f"{port_var} isa {port_type}" in port_tql
            assert f"has port-number {port_number}" in port_tql

        def test_insert_rule_with_custom_variable_name(self):
            rule_var = "my-rule"
            port = model.NetworkPolicyPort(port=80)
            peer = model.NetworkPolicyPeer(pod_selector=model.PodSelector(select_all=True))
            rule = model.NetworkPolicyIngressRule(peers=[peer], ports=[port])

            tqls = get_insert_query(rule, var_name=rule_var)
            assert len(tqls) == 3
            rule_tql, peer_tql, port_tql = tqls

            expected_peer_var = f"${rule_var}-peer"  # no sfx, because it's just 1 entry
            peer_type = to_kebab_case(type(peer).__name__)
            assert f"{expected_peer_var} isa {peer_type}" in peer_tql

            port_var = f"${rule_var}-port"
            port_type = "network-policy-port"

            assert f"target-port: {port_var}" in rule_tql
            assert f"{port_var} isa {port_type}" in port_tql

        def test_insert_network_policy_rule_with_multiple_peers(self):
            peers = [model.NetworkPolicyPeer(pod_selector={"part-of": f"app-{i}"}) for i in range(2)]
            rule = model.NetworkPolicyIngressRule(peers=peers)

            tqls = get_insert_query(rule)
            assert len(tqls) == 1 + len(peers)
            rule_tql, *peer_tqls = tqls
            expected_type = to_kebab_case(type(rule).__name__)
            for i, (peer, peer_tql) in enumerate(zip(peers, peer_tqls)):
                peer_type = to_kebab_case(type(peer).__name__)
                peer_var = f"${expected_type}-peer_{i}"
                assert f"peer: {peer_var}" in rule_tql
                assert f"{peer_var} isa {peer_type}" in peer_tql

        def test_insert_network_policy_rule_with_multiple_ip_blocks(self):
            peers = [model.NetworkPolicyPeer(ip_block=model.IpBlock(cidr=model.Cidr(cidr=ip))) for ip in ["10.0.1.0/22", "10.0.2.0/22"]]
            rule = model.NetworkPolicyIngressRule(peers=peers)

            tqls = get_insert_query(rule)
            assert len(tqls) == 1 + len(peers)
            rule_tql, *peer_tqls = tqls
            expected_type = to_kebab_case(type(rule).__name__)
            for i, (peer, peer_tql) in enumerate(zip(peers, peer_tqls)):
                peer_type = to_kebab_case(type(peer).__name__)
                peer_var = f"${expected_type}-peer_{i}"
                assert f"peer: {peer_var}" in rule_tql
                assert f"{peer_var} isa {peer_type}" in peer_tql

    class TestNetworkPolicyPeer:
        def test_network_policy_peer_with_pod_selector(self):
            pod_selector = model.PodSelector(entries={"app-name": "my-app", "part-of": "binnacle"})
            peer = model.NetworkPolicyPeer(pod_selector=pod_selector)

            tql = to_typeql(peer)

            assert "isa network-policy" in tql

            for sel in pod_selector.items():
                assert f'has pod-selector "{sel}"' in tql

        def test_insert_network_policy_peer_with_pod_selector(self):
            pod_selector = model.PodSelector(entries={"app-name": "my-app", "part-of": "binnacle"})
            peer = model.NetworkPolicyPeer(pod_selector=pod_selector)

            [tql] = get_insert_query(peer)
            assert tql == "insert " + to_typeql(peer)

        def test_insert_network_policy_peer_with_ip_block(self):
            cidr = "0.0.0.0/0"
            ip_block = model.IpBlock(cidr=model.Cidr(cidr=cidr))
            peer = model.NetworkPolicyPeer(ip_block=ip_block)

            [tql] = get_insert_query(peer)
            assert tql == "insert " + to_typeql(peer)
            # assert "has ip-block $ip_block" in tql
            assert f'$ip_block_cidr "{cidr}"' in tql


