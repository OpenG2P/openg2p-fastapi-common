# ruff: noqa: E402

from .config import Settings

_config = Settings.get_config()

from openg2p_fastapi_common.app import Initializer as BaseInitializer


class Initializer(BaseInitializer):
    def initialize(self, **kwargs):
        super().initialize()

        # AuthFactory()
        # BeneficiaryEsignetAuth()
        # BeneficiaryKeycloakAuth()
        # StaffKeycloakAuth()
