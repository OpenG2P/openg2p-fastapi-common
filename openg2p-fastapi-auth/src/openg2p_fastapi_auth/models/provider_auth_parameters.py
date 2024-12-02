import base64
import enum
import hashlib
from typing import Dict, Optional, Union

from pydantic import BaseModel, model_validator


class OauthClientAssertionType(enum.Enum):
    private_key_jwt = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    client_secret = "client_secret"


class OauthProviderParameters(BaseModel):
    authorize_endpoint: str
    token_endpoint: str
    validate_endpoint: str
    jwks_endpoint: str

    client_id: str
    client_secret: Optional[str] = None
    client_assertion_type: OauthClientAssertionType = (
        OauthClientAssertionType.client_secret
    )
    client_assertion_jwk: Optional[Union[Dict, str, bytes]] = None
    client_assertion_jwt_aud: Optional[str] = None

    response_type: str = "code"
    redirect_uri: str
    scope: str = "openid profile email"
    enable_pkce: Optional[bool] = True
    code_verifier: str
    code_challenge: Optional[str] = None
    code_challenge_method: str = "S256"
    extra_authorize_parameters: dict = {}

    @model_validator(mode="after")
    def code_challenge_validator(self) -> "OauthProviderParameters":
        self.code_challenge = (
            base64.urlsafe_b64encode(
                hashlib.sha256(self.code_verifier.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode()
        )
        return self
