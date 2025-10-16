"""
Base interface for JWT authentication strategies.
"""

from fastapi import Request
from openg2p_fastapi_auth_models.schemas import AuthCredentials

from ...dependencies import JwtBearerAuth


class AuthInterface(JwtBearerAuth):
    """Base interface for authentication strategies."""

    async def authenticate(self, request: Request, auth_credentials: AuthCredentials) -> AuthCredentials:
        """
        Authenticate user based on specific provider and user type.

        This method should be implemented by subclasses to provide
        provider-specific authentication logic.

        Args:
            request: FastAPI request object
            auth_credentials: Base JWT credentials after standard verification

        Returns:
            AuthCredentials: Validated credentials for the specific user type and provider

        Raises:
            ForbiddenError: If authentication fails due to insufficient permissions
        """
        # Default implementation - subclasses should override this
        return auth_credentials

    async def __call__(self, request: Request) -> AuthCredentials:
        """
        FastAPI dependency call method.
        First performs full JWT verification via JwtBearerAuth, then applies strategy-specific authentication.
        """
        # Get fully verified JWT credentials using JwtBearerAuth
        auth_credentials = await super().__call__(request)
        if not auth_credentials:
            return None

        # Apply strategy-specific authentication (provider-specific logic)
        return await self.authenticate(request, auth_credentials)
