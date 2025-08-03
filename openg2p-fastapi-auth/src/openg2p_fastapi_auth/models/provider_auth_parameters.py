import enum

from pydantic import BaseModel, field_validator


class OauthClientAssertionType(enum.Enum):
    private_key_jwt = "private_key_jwt"
    """Private Key JWT - jwt will be created using private key available in
    OauthProviderParameters.client_assertion_jwk. The generated JWT will sent as client_assertion
    in the token call."""

    private_key_jwt_keymanager = "private_key_jwt_keymanager"
    """Private Key JWT with Keymanager - jwt will be created using keymanager. The generated JWT will sent as
    client_assertion in the token call."""

    private_key_jwt_legacy = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    """Private Key JWT Legacy - Same as `private_key_jwt`. Left of backward compat."""

    client_secret_basic = "client_secret_basic"
    """Client Secret - sent as basic auth for token call"""

    client_secret = "client_secret"
    """Client Secret - sent in body of token call"""


class OauthProviderParameters(BaseModel):
    authorize_endpoint: str
    token_endpoint: str
    validate_endpoint: str
    jwks_endpoint: str

    client_id: str
    client_secret: str | None = None
    client_assertion_type: OauthClientAssertionType = OauthClientAssertionType.client_secret
    client_assertion_jwk: dict | str | bytes | None = None
    client_assertion_jwt_aud: str | None = None
    client_assertion_jwk_keymanager: str | None = None

    response_type: str = "code"
    redirect_uri: str
    scope: str = "openid profile email"
    enable_pkce: bool = True
    code_verifier: str = ""
    code_challenge: str = ""
    code_challenge_method: str = "S256"
    extra_authorize_parameters: dict = {}

    @field_validator("enable_pkce", mode="before")
    @classmethod
    def validate_pkce(cl, val):
        if isinstance(val, bool) and val:
            return True
        elif isinstance(val, str) and val.lower() != "false":
            return True
        return False
