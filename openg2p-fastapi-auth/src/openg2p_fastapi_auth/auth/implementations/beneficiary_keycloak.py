"""
Beneficiary authentication via Keycloak.
"""

from fastapi import Request
from openg2p_fastapi_auth_models.schemas import AuthCredentials
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError

from ..interface import AuthInterface


class BeneficiaryKeycloakAuth(AuthInterface):
    """Handles beneficiary authentication via Keycloak."""

    async def authenticate(self, request: Request, auth_credentials: AuthCredentials) -> AuthCredentials:
        """
        Authenticate beneficiary user via Keycloak.

        For Keycloak beneficiaries:
        - Validates user_type = "beneficiary"
        - No role validation required for beneficiaries
        """
        claims = auth_credentials.model_dump()

        # Validate user type
        user_type = claims.get("user_type") or claims.get("userType")
        if user_type != "beneficiary":
            raise ForbiddenError(message="Forbidden. Invalid userType.")

        # For beneficiaries, only user_type validation is needed
        # Additional beneficiary-specific validation can be added here if needed

        return auth_credentials
