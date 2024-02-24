from functools import lru_cache

from pydantic import ConfigDict, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = ConfigDict(populate_by_name=True)

    db_name: str | None = None
    db_host: str | None = "0.0.0.0"
    db_port: int = 1729

    reload_api: bool = False
    kubeconfig_path: str = Field("~/.kube/config", validation_alias="KUBECONFIG")

    @property
    def db_url(self):
        return f"{self.db_host}:{self.db_port}"


@lru_cache()
def get_settings():
    return Settings()
