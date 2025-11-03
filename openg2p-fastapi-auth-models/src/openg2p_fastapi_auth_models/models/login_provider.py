import sys

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from typing import Any, Dict, Optional

from openg2p_fastapi_common.models import BaseORMModelWithTimes
from sqlalchemy import Boolean, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from ..context import auth_id_type_config_cache
from ..schemas import LoginProviderTypes


class LoginProvider(BaseORMModelWithTimes):
    __tablename__ = "login_providers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    body: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    image_icon_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    client_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    client_authentication_method: Mapped[str] = mapped_column(String)
    client_secret: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    client_private_key: Mapped[Optional[bytes]] = mapped_column(LargeBinary(), nullable=True)
    auth_endpoint: Mapped[str] = mapped_column(String)
    validation_endpoint: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    token_endpoint: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    jwks_uri: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    jwt_assertion_aud: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    scope: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    enable_pkce: Mapped[Optional[bool]] = mapped_column(Boolean(), nullable=True)
    code_verifier: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    date_format: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    token_map: Mapped[str] = mapped_column(String)
    extra_authorize_params: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    oauth_callback_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    g2p_id_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    @classmethod
    async def get_login_provider_from_iss(cls, iss: str) -> Self:
        # TODO: Modify the following to a direct database query
        # rather than getting all
        providers = await cls.get_all()
        for lp in providers:
            if lp.type == LoginProviderTypes.oauth2_auth_code:
                if iss in lp.authorization_parameters.get("token_endpoint", ""):
                    return lp
            else:
                raise NotImplementedError()
        return None

    @classmethod
    async def get_auth_id_type_config(cls, id: int = None, iss: str = None) -> Optional[Dict[str, Any]]:
        iss_id = id if id else iss
        if auth_id_type_config_cache.get() is None:
            auth_id_type_config_cache.set({})

        id_type_config: Optional[Dict[str, Any]] = auth_id_type_config_cache.get().get(iss_id, None)
        if not id_type_config:
            login_provider: Optional[LoginProvider] = None
            if id:
                login_provider = await cls.get_by_id(id)
            elif iss:
                login_provider = await cls.get_auth_provider_from_iss(iss)

            if login_provider and login_provider.g2p_id_type:
                id_type_config = {
                    "g2p_id_type": login_provider.g2p_id_type,
                    "token_map": login_provider.token_map,
                    "date_format": login_provider.date_format,
                    "login_provider_id": login_provider.id,
                }
                auth_id_type_config_cache.get()[iss_id] = id_type_config
        return id_type_config

    @classmethod
    def map_validation_response(cls, req: dict, mapping: str = None) -> Dict[str, Any]:
        res: Dict[str, Any] = {}
        mapping = mapping.strip() if mapping else ""
        if mapping:
            if mapping.endswith("*:*"):
                res = req
            for pair in mapping.split(" "):
                from_key, to_key = (k.strip() for k in pair.split(":", 1))
                res[to_key] = req.get(from_key, "")
        return res
