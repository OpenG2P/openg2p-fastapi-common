# ruff: noqa: E402

"""Module initializing auth for APIs"""

import asyncio

from .config import Settings

_config = Settings.get_config(strict=False)

from openg2p_fastapi_common.app import Initializer as BaseInitializer

from .controllers.auth_controller import AuthController
from .controllers.oauth_controller import OAuthController
from .models.orm.login_provider import LoginProvider


class Initializer(BaseInitializer):
    def initialize(self, **kwargs):
        # Initialize all Services, Controllers, any utils here.
        AuthController().post_init()
        OAuthController().post_init()

    def migrate_database(self, args):
        super().migrate_database(args)

        async def migrate():
            await LoginProvider.create_migrate()

        asyncio.run(migrate())
