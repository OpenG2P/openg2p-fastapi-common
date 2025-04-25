from typing import List, Optional

from openg2p_fastapi_common.config import Settings as BaseSettings
from pydantic import BaseModel
from pydantic_settings import SettingsConfigDict


class ApiAuthSettings(BaseModel):
    enabled: bool = False
    issuers: Optional[List[str]] = None
    audiences: Optional[List[str]] = None
    claim_name: Optional[str] = None
    claim_values: Optional[List[str]] = None
    id_token_verify_at_hash: Optional[bool] = None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="common_", env_file=".env", extra="allow"
    )

    login_providers_table_name: str = "login_providers"

    auth_enabled: bool = True

    auth_default_issuers: List[str] = []
    auth_default_audiences: List[str] = []
    auth_default_jwks_urls: List[str] = []

    auth_cookie_max_age: Optional[int] = None
    auth_cookie_set_expires: bool = False
    auth_cookie_path: str = "/"
    auth_cookie_httponly: bool = True
    auth_cookie_secure: bool = True

    auth_default_id_token_verify_at_hash: bool = True

    auth_api_get_profile: ApiAuthSettings = ApiAuthSettings(enabled=True)
