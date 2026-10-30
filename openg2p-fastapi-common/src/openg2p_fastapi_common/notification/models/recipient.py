from typing import Optional

from pydantic import BaseModel


class Recipient(BaseModel):
    recipient_id: str
    recipient_name: Optional[str] = None
    recipient_email: Optional[str] = None
    recipient_phone: Optional[str] = None
