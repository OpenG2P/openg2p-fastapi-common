import enum
from typing import Optional

from pydantic import BaseModel


class NotificationResponseStatus(enum.Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class NotificationResponse(BaseModel):
    notification_id: str
    response: Optional[str] = None
    status: NotificationResponseStatus
