from datetime import datetime

from pydantic import BaseModel, ConfigDict


class BasicProfile(BaseModel):
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
