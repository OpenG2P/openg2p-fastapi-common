from datetime import datetime

from fastapi.security import HTTPAuthorizationCredentials
from pydantic import ConfigDict


class AuthCredentials(HTTPAuthorizationCredentials):
    model_config = ConfigDict(extra="allow")

    scheme: str = "bearer"
    credentials: str
    iss: str = None
    sub: str = None
    aud: str | list | None = None
    iat: datetime | None = None
    exp: datetime | None = None
