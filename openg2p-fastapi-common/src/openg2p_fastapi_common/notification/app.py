# ruff: noqa: E402


from ..app import Initializer as BaseInitializer
from ..config import Settings
from .config import load_impl
from .factory import NotificationFactory

_config = Settings.get_config(strict=False)


class Initializer(BaseInitializer):
    def initialize(self, **kwargs):
        NotificationFactory()
        load_impl(_config.notification_impl)()
