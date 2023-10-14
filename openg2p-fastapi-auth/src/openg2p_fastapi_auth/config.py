from typing import List, Optional

from openg2p_fastapi_common.config import Settings
from pydantic import BaseModel
from pydantic_settings import SettingsConfigDict


class ApiAuthSettings(BaseModel):
    enabled: bool = False
    issuers: Optional[List[str]] = None
    audiences: Optional[List[str]] = None
    claim_name: Optional[str] = None
    claim_values: Optional[List[str]] = None


class Settings(Settings):
    model_config = SettingsConfigDict(
        env_prefix="common_", env_file=".env", extra="allow"
    )

    auth_enabled: bool = True

    auth_default_issuers: List[str] = []
    auth_default_audiences: List[str] = []
    auth_default_jwks_urls: List[str] = []

    auth_api_get_profile: ApiAuthSettings = ApiAuthSettings(enabled=True)
    auth_api_logout: ApiAuthSettings = ApiAuthSettings(enabled=True)
