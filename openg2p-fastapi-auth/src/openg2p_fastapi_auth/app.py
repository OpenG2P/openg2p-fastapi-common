# ruff: noqa: E402

from .config import Settings

_config = Settings.get_config()

from openg2p_fastapi_common.app import Initializer as BaseInitializer

from .auth.factory import AuthFactory
from .auth.implementations import (
    BeneficiaryEsignetAuth,
    BeneficiaryKeycloakAuth,
    StaffKeycloakAuth,
)


class Initializer(BaseInitializer):
    def initialize(self, **kwargs):
        super().initialize()
        
        # AuthFactory()
        # BeneficiaryEsignetAuth()
        # BeneficiaryKeycloakAuth()
        # StaffKeycloakAuth()
