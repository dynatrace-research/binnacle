from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from textwrap import dedent

import pytest
from fastapi.testclient import TestClient

from binnacle.adapters.typedb.fakes import FakeDBUnitOfWork, FakeKnowledgeBase
from binnacle.api.main import app
from binnacle.api.routes import get_db_uow, get_k8s_uow, get_kb
from binnacle.model import cluster as cluster_model
from binnacle.model.api import NewProjectRequest
from binnacle.model.graph import Graph
from binnacle.services.unit_of_work import AbstractUnitOfWork
from binnacle.settings import Settings, get_settings

CURR_CTX = "existing-context"


class FakeK8sUnitOfWork(AbstractUnitOfWork):
    def __init__(self, config_path: str, *args):
        self.config_path = config_path
        self.active_cluster = None
        self.cluster = None
        self.namespaces: list[str] | None = None

    def is_ready(self) -> bool:
        return True

    def add_scope(self, cluster: str, namespaces: list[str], infra: bool = False) -> None:
        self.cluster = cluster
        self.namespaces = namespaces

    def get_object_loader(self, cluster: str):
        return lambda: []

    def use_cluster(self, cluster: str) -> None:
        self.active_cluster = cluster


def gen_fake_kubeconfig(path: Path) -> str:
    content = dedent(
        f"""\
                apiVersion: v1
                current-context: {CURR_CTX}
                kind: Config
                clusters:
                - cluster:
                    certificate-authority-data: data==
                    server: https://kind-control-plane:6443
                  name: {CURR_CTX} 
                contexts:
                - context:
                    cluster: {CURR_CTX}
                    user: {CURR_CTX}
                  name: {CURR_CTX}
                users:
                - name: {CURR_CTX}
                  user:
                    client-certificate-data: data==
                    client-key-data: data==
            """
    )

    path.write_text(content)
    return content


def override_get_settings(tmp_dir) -> Settings:
    fake_config_path = tmp_dir / "fake-config"
    gen_fake_kubeconfig(fake_config_path)

    return Settings(
        db_name="fake",
        db_host="127.0.0.1",
        kubeconfig_path=str(fake_config_path),
    )


def override_get_kb():
    return FakeKnowledgeBase()


def override_get_db_uow(
    project: str | None = None,
):
    return FakeDBUnitOfWork(db_name=project)


def override_get_k8s_uow(tmp_dir):
    fake_config_path = tmp_dir / "fake-config"
    return FakeK8sUnitOfWork(fake_config_path)


client = TestClient(app)


# note: fixture decorator must be last, otherwise it didn't work properly
@contextmanager
@pytest.fixture(scope="function")
def override_dependency(tmp_path, **overrides):
    app.dependency_overrides[get_settings] = lru_cache(lambda: override_get_settings(tmp_path))
    # cache the function, so it returns the same instance for the same unit test
    app.dependency_overrides[get_kb] = lru_cache(override_get_kb)
    app.dependency_overrides[get_db_uow] = lru_cache(override_get_db_uow)
    app.dependency_overrides[get_k8s_uow] = lru_cache(lambda: override_get_k8s_uow(tmp_path))
    yield app.dependency_overrides
    # reset overrides
    app.dependency_overrides = {}


class TestClusterManagementApi:
    def test_list_clusters(self, override_dependency):
        res = client.get("/clusters")
        assert res.status_code == 200
        assert res.json() == [CURR_CTX]

    def test_add_new_cluster(self, override_dependency):
        api_ep = "/clusters"

        known_clusters = client.get(api_ep).json()
        num_clusters = len(known_clusters)

        name = "my-cluster"
        cluster = cluster_model.ClusterEntry(server="http://localhost:1234", ca_data="data==")
        user = cluster_model.UserEntry(key_data="key==", cert_data="cert==")
        entry = cluster_model.KubeConfigEntry(name=name, cluster=cluster, user=user)

        res = client.post(api_ep, json=entry.model_dump(exclude_none=True))
        assert res.status_code == 201

        known_clusters_res = client.get(api_ep)
        assert known_clusters_res.status_code == 200
        known_clusters = known_clusters_res.json()

        assert len(known_clusters) == num_clusters + 1
        assert known_clusters[-1] == name

    def test_add_cluster_with_same_name_updates_it(self, override_dependency):
        api_ep = "/clusters"

        known_clusters = client.get(api_ep).json()
        num_clusters = len(known_clusters)

        name = known_clusters[0]
        server = "http://localhost:1234"
        user_key = "key=="
        cluster = cluster_model.ClusterEntry(server=server, ca_data="data==")
        user = cluster_model.UserEntry(key_data=user_key, cert_data="cert==")
        entry = cluster_model.KubeConfigEntry(name=name, cluster=cluster, user=user)

        res = client.post(api_ep, json=entry.model_dump(exclude_none=True))
        assert res.status_code == 201

        known_clusters_res = client.get(api_ep)
        assert known_clusters_res.status_code == 200
        known_clusters = known_clusters_res.json()

        assert len(known_clusters) == num_clusters  # no new entry was added
        assert known_clusters[-1] == name

    def test_remove_cluster(self, override_dependency):
        res = client.delete(f"/clusters/{CURR_CTX}")
        assert res.status_code == 204
        known_clusters = client.get("/clusters").json()
        assert len(known_clusters) == 0

    def test_removing_non_existant_cluster_yields_error(self, override_dependency):
        res = client.delete(f"/clusters/nonexistant")
        assert res.status_code == 404


class TestProjectManagementApi:
    def test_create_new_project(self, override_dependency):
        res = client.get("/clusters")
        assert res.status_code == 200
        available_clusters = res.json()

        assert len(available_clusters) > 0

        ctx = available_clusters[0]
        proj_name = "my-new-project"
        request = NewProjectRequest(name=proj_name, cluster=ctx)

        projects = client.get("/projects").json()
        prev_num_projects = len(projects)

        res = client.put("/projects", json=request.dict(exclude_none=True))
        assert res.status_code == 201

        projects = client.get("/projects").json()
        assert len(projects) == prev_num_projects + 1
        assert projects[-1] == proj_name

    def test_list_projects(self, override_dependency):
        uow = override_dependency[get_db_uow]()
        num_dbs_by_default = len(uow.kb.dbs)
        res = client.get("/projects")
        assert len(res.json()) == num_dbs_by_default

    def test_delete_project(self, override_dependency):
        uow = override_dependency[get_db_uow]()
        num_dbs_by_default = len(uow.kb.dbs)
        api_ep = "/projects"
        projects = client.get(api_ep).json()
        assert len(projects) == num_dbs_by_default

        res = client.delete(f"{api_ep}/{projects[0]}")
        assert res.status_code == 204
        projects = client.get(api_ep).json()
        assert len(projects) == num_dbs_by_default - 1


# class TestTopologyRequest:
#     def test_valid_project_yields_graph_as_json(self, override_dependency):
#         projects = client.get("/projects").json()
#         api_ep = f"topology/{projects[0]}"
#         res = client.get(api_ep)
#         assert res.status_code == 200
#         topology = res.json()

#         # returned object is a graph
#         g = Graph(**topology)
#         assert g.nodes == []
#         assert g.edges == []

#     def test_invalid_project_yields_404(self, override_dependency):
#         api_ep = f"topology/non-existing-project"
#         res = client.get(api_ep)
#         assert res.status_code == 404
