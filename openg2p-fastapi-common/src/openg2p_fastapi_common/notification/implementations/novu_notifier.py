import logging
from typing import Any

import novu_py
from novu_py import Novu

from ...config import Settings
from ..interface.notification_interface import NotificationInterface
from ..models import (
    NotificationResponse,
    NotificationResponseStatus,
    Recipient,
)

_config = Settings.get_config(strict=False)
_logger = logging.getLogger("novu_notifier_impl")


class NovuNotifier(NotificationInterface):
    def send_notification(
        self,
        notification_id: str,
        payload: Any,
        workflow_id: str,
        recipient: Recipient,
    ) -> NotificationResponse:
        if not workflow_id:
            raise ValueError("workflow_id is required")

        with Novu(server_url=_config.novu_url, secret_key=_config.novu_api_key) as novu:
            _logger.info(
                f"Sending notification with ID {notification_id} to {recipient.recipient_email} via Novu"
            )
            _logger.info(f"Using workflow ID: {workflow_id}")
            novu_response = novu.trigger(
                trigger_event_request_dto=novu_py.TriggerEventRequestDto(
                    workflow_id=workflow_id,
                    payload=payload or {},
                    overrides=novu_py.Overrides(),
                    to=recipient.recipient_email or recipient.recipient_id,
                )
            )
            _logger.info(f"Novu response: {novu_response.result}")
            notification_response = NotificationResponse(
                notification_id=notification_id,
                response=str(novu_response.result),
                status=(
                    NotificationResponseStatus.SUCCESS
                    if novu_response.result.status.value == "processed"
                    else NotificationResponseStatus.FAILURE
                ),
            )
            return notification_response
