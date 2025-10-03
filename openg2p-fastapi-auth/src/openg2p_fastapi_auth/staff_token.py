from fastapi import Request
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError

from .dependencies import JwtBearerAuth, UserTypeEnum
from .models.credentials import AuthCredentials


class StaffToken(JwtBearerAuth):
    def __init__(self):
        super().__init__()
        self.required_user_type = UserTypeEnum.STAFF.value  # TODO: Change to ENUM

    async def __call__(self, request: Request):
        # First, perform the standard JWT verification and route gating
        auth_credentials: AuthCredentials = await super().__call__(request)
        if not auth_credentials:
            return None
        claims = auth_credentials.model_dump()

        iss = claims.get("iss", "") or ""
        is_keycloak = bool(
            (claims.get("realm_access") or claims.get("resource_access")) or ("/realms/" in iss)
        )

        if is_keycloak:
            # Enforce userType + bene role on Keycloak
            if self.required_user_type and claims.get("userType") != self.required_user_type:
                raise ForbiddenError(message="Forbidden. Invalid userType.")
            realm_roles = set((claims.get("realm_access") or {}).get("roles") or [])
            client_roles = set(
                ((claims.get("resource_access") or {}).get("staff-portal") or {}).get("roles") or []
            )
            effective_roles = realm_roles | client_roles
            if UserTypeEnum.STAFF.value not in effective_roles:
                raise ForbiddenError(message="Forbidden. Missing required role(s).")
            return auth_credentials
        else:
            # Esignet or other OIDC providers: require only userType
            if self.required_user_type and claims.get("userType") != self.required_user_type:
                raise ForbiddenError(message="Forbidden. Invalid userType.")
            return auth_credentials
