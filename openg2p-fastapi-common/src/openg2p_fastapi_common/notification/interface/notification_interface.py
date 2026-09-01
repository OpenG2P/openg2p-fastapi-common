from typing import Any

from ...service import BaseService
from ..models import Recipient


class NotificationInterface(BaseService):
    def send_notification(
        self,
        notification_id: str,
        payload: Any,
        workflow_id: str,
        recipient: Recipient,
    ) -> None:
        """
        Send a notification using the given Novu workflow identifier.
        """
        pass
