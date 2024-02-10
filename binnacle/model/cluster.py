from loguru import logger
from pydantic import BaseModel, ConfigDict, Field


class KubeConfigBaseModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class User(KubeConfigBaseModel):
    name: str | None = None  # defaults to context name
    cert_data: str | None = None
    key_data: str | None = None


class AuthInfo(KubeConfigBaseModel):
    key_data: str | None = Field(None, alias="client-key-data")
    # key_path: Path | None = Field(None, alias="client-key")  # mutually exclusive w/ the data
    cert_data: str | None = Field(None, alias="client-certificate-data")
    # cert_path: Path | None = Field(None, alias="client-certificate")  # mutually exclusive w/ the data

    token: str | None = None
    model_config = ConfigDict(populate_by_name=True)


class BasicAuthInfo(AuthInfo):
    username: str | None = None
    password: str | None = None


class TokenAuthInfo(AuthInfo):
    token: str


class ExecEnvVar(KubeConfigBaseModel):
    name: str
    value: str


class KubeConfigUser(KubeConfigBaseModel):
    name: str
    user: TokenAuthInfo | BasicAuthInfo | AuthInfo


class ClusterData(KubeConfigBaseModel):
    ca_data: str = Field(..., alias="certificate-authority-data")
    # ca_path: Path | None = Field(None, alias="certificate-authority")  # mutually exclusive w/ the data
    server: str
    model_config = ConfigDict(populate_by_name=True)


class KubeConfigCluster(KubeConfigBaseModel):
    name: str
    cluster: ClusterData


class ContextData(KubeConfigBaseModel):
    user: str
    cluster: str
    namespace: str | None = None


class KubeConfigContext(KubeConfigBaseModel):
    name: str
    context: ContextData


class ClusterEntry(ClusterData):
    name: str | None = None


class UserEntry(AuthInfo):
    name: str | None = None


class KubeConfigEntry(KubeConfigBaseModel):
    name: str  # name of the context
    cluster: ClusterEntry
    user: UserEntry


class KubeConfig(KubeConfigBaseModel):
    path: str | None = Field(None, exclude=True)  # not part of the file - only for internal management
    api_version: str = Field("v1", alias="apiVersion")
    kind: str = "Config"
    current_context: str = Field("", alias="current-context")
    preferences: dict = {}
    clusters: list[KubeConfigCluster] = []
    contexts: list[KubeConfigContext] = []
    users: list[KubeConfigUser] = []
    model_config = ConfigDict(populate_by_name=True)

    def add_or_update_entry(self, entry: KubeConfigEntry) -> None:
        """Add or update an entry to `users`, `contexts` and `clusters` lists in the config file.

        :param entry: the entry which will be added to the corresponding lists
        """
        if self.has_entry(entry.name):
            self.remove_entry(entry.name)

        cluster_name = entry.cluster.name or entry.name
        user_name = entry.user.name or entry.name
        # cast data to respective super-types to ensure
        self.clusters.append(KubeConfigCluster(name=cluster_name, cluster=ClusterData(**entry.cluster.dict())))
        self.users.append(KubeConfigUser(name=user_name, user=AuthInfo(**entry.user.dict())))

        self.contexts.append(
            KubeConfigContext(
                name=entry.name,
                context=ContextData(cluster=cluster_name, user=user_name),
            )
        )

    def has_entry(self, name: str) -> bool:
        """Check if an entry/context exists in the Kubeconfig

        :param name: the name of the entry
        :return: True if an entry with that name exists, False otherwise
        """
        return any(name == ctx.name for ctx in self.contexts)

    def remove_entry(self, name: str) -> None:
        """Remove an entry from the `users`, `contexts` and `clusters` lists in the config file.
        If entry does not exist, nothing happens.

        :param name: the name of the entry to remove
        """
        ctx = next((ctx for ctx in self.contexts if ctx.name == name), None)

        if ctx is None:
            logger.warning(f"Failed to delete kubeconfig entry '{name}': no entry found with that name!")
            return

        self.clusters = [c for c in self.clusters if c.name != ctx.context.cluster]
        self.users = [u for u in self.users if u.name != ctx.context.user]
        self.contexts = [ctx for ctx in self.contexts if ctx.name != name]

        if self.current_context == name:
            self.current_context = ""

    def switch_context(self, name: str) -> None:
        """Update the current_context to the specified name if it exists

        :param name: the name of the new current_context
        :raises ValueError: if no context with the given name exists
        """
        if not self.has_entry(name):
            raise ValueError(f"No context named '{name}' registered!")

        self.current_context = name
