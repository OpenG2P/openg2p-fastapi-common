# ruff: noqa: E402

"""Module initializing auth for APIs"""

from .config import Settings

_config = Settings.get_config(strict=False)

from openg2p_fastapi_common.app import Initializer as BaseInitializer

from .controllers.auth_controller import AuthController
from .controllers.oauth_controller import OAuthController


class Initializer(BaseInitializer):
    def initialize(self, **kwargs):
        # Initialize all Services, Controllers, any utils here.
        AuthController().post_init()
        OAuthController().post_init()
