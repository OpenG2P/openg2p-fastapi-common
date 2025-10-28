from datetime import datetime, timezone

from openg2p_fastapi_common.config import Settings as BaseSettings
from pydantic import BaseModel, model_validator
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

    login_providers_table_enabled: bool = True
    login_providers_table_name: str = "login_providers"
    login_providers_list: list[dict] = []
    login_providers_list_pkce_code_verifier: str | None = None

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

    @model_validator(mode="after")
    def validate_login_providers_list(self):
        if self.login_providers_list:
            code_verifier = self.login_providers_list_pkce_code_verifier
            self.login_providers_list.sort(key=lambda x: x.get("id"))

            from .models.login_provider import LoginProviderTypes

            for lp in self.login_providers_list:
                if "type" in lp:
                    lp["type"] = LoginProviderTypes[lp["type"]]

                lp_auth_params = lp.get("authorization_parameters")
                if code_verifier and lp_auth_params:
                    lp_auth_params["code_verifier"] = code_verifier
                if not lp.get("created_at"):
                    lp["created_at"] = datetime.now(timezone.utc).replace(tzinfo=None)

            if not self.auth_default_issuers:
                self.auth_default_issuers = [lp.get("iss") for lp in self.login_providers_list]
            if not self.auth_default_jwks_urls:
                self.auth_default_jwks_urls = [lp.get("jwks_url") for lp in self.login_providers_list]
        return self
