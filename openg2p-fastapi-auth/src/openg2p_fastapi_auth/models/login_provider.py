from enum import Enum

from pydantic import BaseModel


class LoginProviderTypes(Enum):
    oauth2_auth_code = "oauth2_auth_code"


class LoginProviderResponse(BaseModel):
    id: int
    name: str
    type: LoginProviderTypes
    displayName: str | dict
    displayIconUrl: str


class LoginProviderHttpResponse(BaseModel):
    loginProviders: list[LoginProviderResponse]
