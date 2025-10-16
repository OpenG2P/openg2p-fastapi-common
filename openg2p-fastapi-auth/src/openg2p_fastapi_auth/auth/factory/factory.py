"""
JWT Authentication Factory

Detects provider type and returns appropriate implementation.
Includes Generic Factory Dependency for FastAPI.
"""

from fastapi import Depends, Request
from openg2p_fastapi_auth_models.schemas import AuthCredentials

from ...dependencies import JwtBearerAuth
from ..implementations import (
    BeneficiaryEsignetAuth,
    StaffKeycloakAuth,
)


async def _authenticate_user(
    request: Request,
    auth_credentials: AuthCredentials,
) -> AuthCredentials:
    """
    Authenticate a user with the appropriate strategy.

    Args:
        request: FastAPI request object
        auth_credentials: Base JWT credentials after standard verification
        user_type: Required user type ("beneficiary" or "staff")

    Returns:
        AuthCredentials: Validated credentials
    """

    claims = auth_credentials.model_dump()
    user_type = claims.get("user_type") or claims.get("userType")

    if user_type == "beneficiary":
        strategy = BeneficiaryEsignetAuth()
    elif user_type == "staff":
        strategy = StaffKeycloakAuth()
    else:
        raise ValueError(f"No strategy found for user_type: {user_type}")

    return await strategy.authenticate(request, auth_credentials)


class AuthFactory:
    """
    Generic Factory-based dependency that accepts user type.

    This class provides a clean way to use the factory pattern directly
    in FastAPI dependencies with automatic provider detection.
    Extends BaseService for component registry integration.

    Usage:
        @app.get("/beneficiary/profile")
        async def get_profile(auth: AuthCredentials = Depends(AuthFactory())):
            return {"user_id": auth.sub}
    """

    async def __call__(
        self, request: Request, auth_credentials: AuthCredentials = Depends(JwtBearerAuth())
    ) -> AuthCredentials:
        """
        FastAPI dependency call method.

        Args:
            request: FastAPI request object
            auth_credentials: Base JWT credentials from JwtBearerAuth

        Returns:
            AuthCredentials: Validated credentials with provider-specific authentication applied
        """
        return await _authenticate_user(request, auth_credentials)
