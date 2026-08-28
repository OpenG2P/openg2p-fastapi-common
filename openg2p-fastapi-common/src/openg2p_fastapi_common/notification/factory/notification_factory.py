from ...service import BaseService
from ..interface.notification_interface import NotificationInterface


class NotificationFactory(BaseService):
    @staticmethod
    def get_notifier() -> NotificationInterface:
        # Whichever NotificationInterface impl the Initializer registered
        # (selected by Settings.impl).
        return NotificationInterface.get_component()
