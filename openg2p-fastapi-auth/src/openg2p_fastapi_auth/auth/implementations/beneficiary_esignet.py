"""
Beneficiary authentication via Esignet/other OIDC.
"""

from fastapi import Request
from openg2p_fastapi_auth_models.schemas import AuthCredentials
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError

from ..interface import AuthInterface


class BeneficiaryEsignetAuth(AuthInterface):
    """Handles beneficiary authentication via Esignet/other OIDC."""

    async def authenticate(self, request: Request, auth_credentials: AuthCredentials) -> AuthCredentials:
        """
        Authenticate beneficiary user via Esignet/other OIDC.

        For Esignet beneficiaries:
        - Validates user_type = "beneficiary"
        - No role validation required
        """
        claims = auth_credentials.model_dump()

        # Validate user type
        user_type = claims.get("user_type") or claims.get("userType")
        if user_type != "beneficiary":
            raise ForbiddenError(message="Forbidden. Invalid userType.")

        # For Esignet/OIDC providers, only user_type validation is needed

        return auth_credentials
