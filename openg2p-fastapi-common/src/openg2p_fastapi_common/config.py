"""Module initializing configs"""
import os
from enum import Enum
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from . import __version__
from .context import config_registry


class WorkerType(Enum):
    local = "local"
    uvicorn = "uvicorn"
    gunicorn = "gunicorn"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="common_", env_file=".env", extra="allow"
    )

    host: str = "0.0.0.0"
    port: int = 8000

    no_of_workers: int = 1
    worker_id: int = -1
    worker_pid: int = -1
    worker_type: WorkerType = WorkerType.local
    docker_pod_id: str = ""
    docker_pod_name: str = ""

    logging_default_logger_name: str = "app"
    logging_level: str = "INFO"
    logging_file_name: Path | None = None

    openapi_title: str = "Common"
    openapi_description: str = """
    This is common library for FastAPI service. Override Settings properties to change this.

    ***********************************
    Further details goes here
    ***********************************
    """
    openapi_version: str = __version__
    openapi_contact_url: str = "https://www.openg2p.org/"
    openapi_contact_email: str = "info@openg2p.org"
    openapi_license_name: str = "Mozilla Public License 2.0"
    openapi_license_url: str = "https://www.mozilla.org/en-US/MPL/2.0/"
    openapi_root_path: str = ""
    openapi_common_api_prefix: str = ""

    # If empty will be constructed like this
    # f"{db_driver}://{db_username}:{db_password}@{db_hostname}:{db_port}/{db_dbname}"
    db_datasource: str = ""
    db_driver: str = "postgresql+asyncpg"
    db_username: str = ""
    db_password: str = ""
    db_hostname: str = "localhost"
    db_port: int = 5432
    db_dbname: str = ""
    db_logging: bool = False

    error_response_debug: bool = False

    @model_validator(mode="after")
    def validate_db_datasource(self) -> "Settings":
        if self.db_datasource:
            return self
        datasource = ""
        if self.db_driver:
            datasource += f"{self.db_driver}://"
        if self.db_username:
            datasource += f"{self.db_username}:{self.db_password}@"
        if self.db_hostname:
            datasource += self.db_hostname
        if self.db_port:
            datasource += f":{self.db_port}"
        if self.db_dbname:
            datasource += f"/{self.db_dbname}"

        self.db_datasource = datasource

        return self

    @model_validator(mode="after")
    def validate_worker_ids_and_pod_ids(self) -> "Settings":
        self.set_current_worker_id()
        self.set_current_docker_pod_id()
        return self

    @classmethod
    def get_config(cls, strict=True):
        result = None
        for config in config_registry.get():
            if strict:
                if cls is type(config):
                    result = config
                    break
            else:
                if isinstance(config, cls):
                    result = config
                    break
        if not result:
            result = cls()
            config_registry.get().append(result)
        return result

    def set_current_worker_id(self):
        if self.worker_type == WorkerType.local:
            return
        try:
            self.worker_pid = os.getpid()
            import subprocess

            pid_arr = sorted(
                [
                    int(a)
                    for a in str(
                        subprocess.check_output(
                            ["pgrep", "-f", self.worker_type.value]
                        ),
                        "UTF-8",
                    ).split("\n")
                    if a
                ]
            )
            self.worker_id = pid_arr.index(self.worker_pid) - 1
        except Exception:
            pass

    def set_current_docker_pod_id(self):
        self.docker_pod_id = str(self.docker_pod_name.split("-")[-1])
