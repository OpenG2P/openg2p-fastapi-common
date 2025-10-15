from datetime import datetime
import enum
from typing import Optional

from pydantic import BaseModel, ConfigDict


class UserType(enum.Enum):
    BENEFICIARY = "beneficiary"
    STAFF = "staff"
    AGENCY = "agency"

class UserProfile(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str | None = None
    sub: str | None = None
    iss: str | None = None
    exp: datetime | None = None
    picture: str | None = None
    profile: str | None = None
    email: str | None = None
    gender: str | None = None
    birthdate: str | None = None
    address: dict | None = None
    user_type: Optional[str] = None
