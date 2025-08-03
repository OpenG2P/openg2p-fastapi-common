import sys

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from openg2p_fastapi_common.models import BaseORMModelWithTimes
from sqlalchemy import JSON, String
from sqlalchemy import Enum as SaEnum
from sqlalchemy.orm import Mapped, mapped_column

from ...config import Settings
from ..login_provider import LoginProviderTypes

_config = Settings.get_config(strict=False)


class LoginProvider(BaseORMModelWithTimes):
    __enabled__ = _config.login_providers_table_enabled
    __tablename__ = _config.login_providers_table_name

    name: Mapped[str] = mapped_column(String())
    type: Mapped[LoginProviderTypes] = mapped_column(SaEnum(LoginProviderTypes))

    description: Mapped[str | None] = mapped_column(String())

    login_button_text: Mapped[str | None] = mapped_column(String())
    login_button_image_url: Mapped[str | None] = mapped_column(String())

    authorization_parameters: Mapped[dict | None] = mapped_column(JSON(), default={})

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
