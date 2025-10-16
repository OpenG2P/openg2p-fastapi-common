"""
Staff authentication via Keycloak.
"""

from fastapi import Request
from openg2p_fastapi_auth_models.schemas import AuthCredentials
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError

from ..interface import AuthInterface


class StaffKeycloakAuth(AuthInterface):
    """Handles staff authentication via Keycloak."""

    async def authenticate(self, request: Request, auth_credentials: AuthCredentials) -> AuthCredentials:
        """
        Authenticate staff user via Keycloak.

        For Keycloak staff:
        - Validates user_type = "staff"
        - Validates Keycloak roles (realm and client roles)
        """
        claims = auth_credentials.model_dump()

        # Validate user type
        user_type = claims.get("user_type") or claims.get("userType")
        if user_type != "staff":
            raise ForbiddenError(message="Forbidden. Invalid userType.")

        # Validate Keycloak roles
        realm_roles = set((claims.get("realm_access") or {}).get("roles") or [])
        client_roles = set(
            ((claims.get("resource_access") or {}).get("staff-portal") or {}).get("roles") or []
        )
        effective_roles = realm_roles | client_roles

        if "staff" not in effective_roles:
            raise ForbiddenError(message="Forbidden. Missing required role(s).")

        return auth_credentials
