from textwrap import dedent

import pytest
from _pytest.logging import LogCaptureFixture
from loguru import logger

from binnacle.adapters.k8s import cluster_management as mgmt
from binnacle.model.cluster import ClusterEntry, KubeConfig, KubeConfigEntry, UserEntry


# add fix to allow loguru to be compatible with pytests `caplog``
@pytest.fixture
def caplog(caplog: LogCaptureFixture):
    handler_id = logger.add(caplog.handler, format="{message}")
    yield caplog
    logger.remove(handler_id)


class TestKubeConfigManagement:
    class TestKubeConfigIO:
        def test_load_config_from_non_existing_path_creates_new_one(self, tmp_path):
            path = str(tmp_path / "config")
            cfg = mgmt.load_or_create_kubeconfig(path)
            assert cfg is not None
            assert len(cfg.clusters) == 0
            assert len(cfg.users) == 0
            assert len(cfg.contexts) == 0

        def test_creating_new_config_when_loading_is_logged(self, tmp_path, caplog):
            path = str(tmp_path / "config-that-does-not-exist.yaml")
            mgmt.load_or_create_kubeconfig(path)
            assert "Loading new config" in caplog.text

        def test_load_existing_config(self, tmp_path):
            curr_ctx = "existing-context"
            content = dedent(
                f"""\
                apiVersion: v1
                current-context: {curr_ctx}
                kind: Config
                clusters:
                - cluster:
                    certificate-authority-data: data==
                    server: https://kind-control-plane:6443
                  name: {curr_ctx} 
                contexts:
                - context:
                    cluster: {curr_ctx}
                    user: {curr_ctx}
                  name: {curr_ctx}
                users:
                - name: {curr_ctx}
                  user:
                    client-certificate-data: data==
                    client-key-data: data==
            """
            )
            path = tmp_path / "config"
            path.write_text(content)

            cfg = mgmt.load_or_create_kubeconfig(str(path))
            assert cfg.current_context == curr_ctx
            assert len(cfg.clusters) == 1
            assert len(cfg.contexts) == 1
            assert len(cfg.users) == 1

        def test_write_kubeconfig_yaml(self, tmp_path):
            target_path = tmp_path / "config.yaml"
            config = KubeConfig()

            server = "arn:xyz"
            ca_data = "arstars===="
            cluster_name = "my-cluster"
            cluster = ClusterEntry(name=cluster_name, ca_data=ca_data, server=server)

            cert_data = "certdata=="
            key_data = "keydata=="
            user_name = "bob"
            user = UserEntry(name=user_name, key_data=key_data, cert_data=cert_data)

            entry_name = "my-entry"
            entry = KubeConfigEntry(name=entry_name, cluster=cluster, user=user)
            config.add_or_update_entry(entry)

            mgmt.save_kubeconfig(config, target_path)

            # the file was actually written
            assert len(list(tmp_path.iterdir())) == 1
            content = target_path.read_text()

            # metadata
            assert "apiVersion: v1" in content
            assert "kind: Config" in content

            # cluster
            assert f"name: {cluster_name}" in content
            assert f"certificate-authority-data: {ca_data}" in content
            assert f"server: {server}" in content

            # user
            assert f"name: {user_name}" in content
            assert f"client-certificate-data: {cert_data}" in content
            assert f"client-key-data: {key_data}" in content

            # context
            assert f"cluster: {cluster_name}" in content
            assert f"user: {user_name}" in content

        def test_create_config_in_nonexisting_folder(self, tmp_path):
            target_path = tmp_path / "new-folder/config.yaml"
            config = KubeConfig()

            server = "arn:xyz"
            ca_data = "arstars===="
            cluster = ClusterEntry(ca_data=ca_data, server=server)

            cert_data = "certdata=="
            key_data = "keydata=="
            user = UserEntry(key_data=key_data, cert_data=cert_data)

            entry_name = "my-cluster"
            entry = KubeConfigEntry(name=entry_name, cluster=cluster, user=user)
            config.add_or_update_entry(entry)

            # containing folder is also new
            assert not target_path.parent.exists()
            mgmt.save_kubeconfig(config, target_path)
            assert target_path.exists()

    class TestEntryManagement:
        def test_add_new_entry_to_kubeconfig(self):
            cfg = KubeConfig()

            name = "my-cluster"
            cluster = ClusterEntry(ca_data="na", server="arn:xyz")
            user = UserEntry(key_data="test", cert_data="pem")
            entry = KubeConfigEntry(name=name, cluster=cluster, user=user)

            num_clusters, num_users, num_contexts = len(cfg.clusters), len(cfg.users), len(cfg.contexts)
            cfg.add_or_update_entry(entry)

            # entries have been added to the other fields accordingly
            assert len(cfg.clusters) == num_clusters + 1
            assert len(cfg.users) == num_users + 1
            assert len(cfg.contexts) == num_contexts + 1

        def test_add_entry_user_and_cluster_name_default_to_context_name(self):
            cfg = KubeConfig()

            name = "my-context"
            cluster = ClusterEntry(name=name, ca_data="na", server="arn:xyz")
            user = UserEntry(name=name, key_data="test", cert_data="pem")
            entry = KubeConfigEntry(name=name, cluster=cluster, user=user)

            cfg.add_or_update_entry(entry)

            assert cfg.contexts[-1].name == name
            assert cfg.clusters[-1].name == name
            assert cfg.users[-1].name == name

        def test_add_entry_with_different_user_and_cluster_name(self):
            cfg = KubeConfig()

            cluster_name = "my-cluster"
            cluster = ClusterEntry(name=cluster_name, ca_data="na", server="arn:xyz")
            user_name = "bob"
            user = UserEntry(name=user_name, key_data="test", cert_data="pem")
            context_name = "my-context"
            entry = KubeConfigEntry(name=context_name, cluster=cluster, user=user)

            cfg.add_or_update_entry(entry)

            assert cfg.contexts[-1].name == context_name
            assert cfg.clusters[-1].name == cluster_name
            assert cfg.users[-1].name == user_name

        def test_remove_existing_entry_from_kubeconfig(self):
            cfg = KubeConfig()

            name = "my-cluster"
            cluster = ClusterEntry(ca_data="na", server="arn:xyz")
            user = UserEntry(key_data="test", cert_data="pem")
            entry = KubeConfigEntry(name=name, cluster=cluster, user=user)
            cfg.add_or_update_entry(entry)
            assert len(cfg.contexts) == 1  # just ensure adding actually worked

            cfg.remove_entry(name)

            # entries have been removed from the other fields accordingly
            assert len(cfg.clusters) == 0
            assert len(cfg.users) == 0
            assert len(cfg.contexts) == 0

        def test_remove_existing_entry_with_different_user_and_cluster_name(self):
            cfg = KubeConfig()

            cluster = ClusterEntry(name="my-cluster", ca_data="na", server="arn:xyz")
            user = UserEntry(name="bob", key_data="test", cert_data="pem")
            context_name = "my-cluster"
            entry = KubeConfigEntry(name=context_name, cluster=cluster, user=user)
            cfg.add_or_update_entry(entry)
            assert len(cfg.contexts) == 1  # just ensure adding actually worked

            cfg.remove_entry(context_name)

            # entries have been removed from the other fields accordingly
            assert len(cfg.clusters) == 0
            assert len(cfg.users) == 0
            assert len(cfg.contexts) == 0

        def test_removing_entry_which_is_current_context_resets_the_context(self):
            cfg = KubeConfig()

            name = "my-cluster"
            cluster = ClusterEntry(ca_data="na", server="arn:xyz")
            user = UserEntry(key_data="test", cert_data="pem")
            entry = KubeConfigEntry(name=name, cluster=cluster, user=user)
            cfg.add_or_update_entry(entry)
            cfg.switch_context(name)
            assert cfg.current_context == name  # just ensure adding actually worked

            cfg.remove_entry(name)
            assert cfg.current_context == ""

        def test_removing_non_existing_entry_has_no_side_effect(self):
            cfg = KubeConfig()

            cfg.remove_entry("i-do-not-exist")
            assert len(cfg.clusters) == 0
            assert len(cfg.users) == 0
            assert len(cfg.contexts) == 0

        def test_switching_context_updates_current_context(self):
            cfg = KubeConfig()

            cfg.remove_entry("i-do-not-exist")
            name = "my-cluster"
            cluster = ClusterEntry(ca_data="na", server="arn:xyz")
            user = UserEntry(key_data="test", cert_data="pem")
            entry = KubeConfigEntry(name=name, cluster=cluster, user=user)
            cfg.add_or_update_entry(entry)
            cfg.switch_context(name)
            assert cfg.current_context == name

        def test_setting_non_existing_context_raises_error(self):
            cfg = KubeConfig()

            with pytest.raises(ValueError):
                cfg.switch_context("i-do-not-exist")
