"""Module initializing configs"""

import json
import os
import sys
from enum import Enum
from pathlib import Path
from typing import List

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from . import __version__
from .context import config_registry


class WorkerType(Enum):
    local = "local"
    uvicorn = "uvicorn"
    gunicorn = "gunicorn"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="common_", env_file=".env", extra="allow", env_nested_delimiter="__"
    )

    app_host: str = "0.0.0.0"
    app_port: int = 8000

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

    keymanager_api_base_url: str = ""
    keymanager_api_timeout: int = 10
    keymanager_api_domain: str = "AUTH"
    keymanager_ssl_verify: bool = False
    keymanager_auth_enabled: bool = True
    keymanager_auth_url: str = ""
    keymanager_auth_client_id: str = "openg2p"
    keymanager_auth_client_secret: str = ""
    keymanager_sign_app_id: str = "OPENG2P"
    keymanager_sign_ref_id: str = ""

    # JWS sign/verify backend selector — DISTINCT from the keymanager_* settings
    # above, which are left untouched.
    #   "keymanager" (default) -> KeymanagerCryptoHelper (remote Keymanager service).
    #   "local"                -> PyJWTCryptoHelper (in-process PyJWT; no Keymanager).
    crypto_backend: str = "keymanager"
    # --- "local" backend settings (ignored when crypto_backend="keymanager") ---
    # Outbound signing: a password-protected PKCS#12 (.p12) keystore holding this
    # service's own private key. Empty when the service only verifies.
    crypto_signing_key_path: str = ""
    crypto_signing_key_password: str = ""
    # Optional kid; blank -> the signing certificate's SHA-256 thumbprint is used.
    crypto_signing_key_kid: str = ""
    crypto_signing_algorithm: str = "RS256"
    # Comma-separated allowed JWS algorithms for verification. RS256 only
    # (asymmetric); "none" and HMAC (HS*) are always rejected regardless.
    crypto_allowed_algorithms: str = "RS256"
    # Seed-based partner onboarding: a JSON list of partner public certs upserted
    # into the partner_keys table at migrate-time. Each item:
    #   {"reference_id": "PARTNER_<MNEMONIC>", "public_key": "<PEM cert>",
    #    "kid": "<optional>", "algorithm": "RS256"}
    crypto_partner_certs: list[dict] = []

    cors_allow_origins: List[str] = []
    cors_allow_credentials: bool = True
    security_headers_enabled: bool = True

    @field_validator("cors_allow_origins", mode="before")
    def parse_cors_allow_origins(cls, v):
        """Support JSON-style list and comma-separated values in env."""
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @model_validator(mode="after")
    def validate_db_datasource(self) -> Self:
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
    def validate_worker_ids_and_pod_ids(self) -> Self:
        self.set_current_worker_id()
        self.set_current_docker_pod_id()
        return self

    @classmethod
    def get_config(cls, strict=True) -> Self:
        result = None
        cr = config_registry.get()
        if not cr:
            cr = []
            config_registry.set(cr)
        for config in cr:
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
            cr.append(result)
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
                        subprocess.check_output(["pgrep", "-f", self.worker_type.value]),
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
