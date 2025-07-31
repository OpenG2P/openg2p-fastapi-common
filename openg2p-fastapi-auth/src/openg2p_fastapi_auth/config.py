from openg2p_fastapi_common.config import Settings as BaseSettings
from pydantic import BaseModel
from pydantic_settings import SettingsConfigDict


class ApiAuthSettings(BaseModel):
    enabled: bool = False
    issuers: list[str] | None = None
    audiences: list[str] | None = None
    claim_name: str | None = None
    claim_values: list[str] | None = None
    id_token_verify_at_hash: bool | None = None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="common_", env_file=".env", extra="allow", env_nested_delimiter="__"
    )

    login_providers_table_name: str = "login_providers"

    auth_enabled: bool = True

    auth_default_issuers: list[str] = []
    auth_default_audiences: list[str] = []
    auth_default_jwks_urls: list[str] = []

    auth_cookie_max_age: int | None = None
    auth_cookie_set_expires: bool = False
    auth_cookie_path: str = "/"
    auth_cookie_httponly: bool = True
    auth_cookie_secure: bool = True

    auth_default_id_token_verify_at_hash: bool = True

    auth_api_get_profile: ApiAuthSettings = ApiAuthSettings(enabled=True)
