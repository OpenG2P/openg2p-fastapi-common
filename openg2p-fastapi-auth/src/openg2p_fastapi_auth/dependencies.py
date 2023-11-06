from typing import Optional

import httpx
from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt
from openg2p_fastapi_common.errors.http_exceptions import (
    ForbiddenError,
    InternalServerError,
    UnauthorizedError,
)

from .config import Settings
from .context import jwks_cache
from .models.credentials import AuthCredentials

_config = Settings.get_config(strict=False)


class JwtBearerAuth(HTTPBearer):
    async def __call__(
        self, request: Request
    ) -> Optional[HTTPAuthorizationCredentials]:
        config_dict = _config.model_dump()
        if not config_dict.get("auth_enabled", None):
            return None

        api_call_name = str(request.scope["route"].name)

        api_auth_settings = config_dict.get("auth_api_" + api_call_name, {})

        if (not api_auth_settings) or (not api_auth_settings.get("enabled", None)):
            return None

        issuers_list = api_auth_settings.get("issuers", None) or config_dict.get(
            "auth_default_issuers", []
        )
        audiences_list = api_auth_settings.get("audiences", None) or config_dict.get(
            "auth_default_audiences", []
        )
        jwks_urls_list = api_auth_settings.get("jwks_urls", None) or config_dict.get(
            "auth_default_jwks_urls", []
        )

        jwt_token = request.headers.get("Authorization", None) or request.cookies.get(
            "X-Access-Token", None
        )
        jwt_id_token = request.cookies.get("X-ID-Token", None)
        if jwt_token:
            jwt_token = jwt_token.removeprefix("Bearer ")

        if not jwt_token:
            raise UnauthorizedError()

        try:
            unverified_payload = jwt.decode(
                jwt_token,
                None,
                options={
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_sub": False,
                },
            )
        except Exception as e:
            raise UnauthorizedError(
                message=f"Unauthorized. Jwt expired. {repr(e)}"
            ) from e
        iss = unverified_payload["iss"]
        aud = unverified_payload.get("aud", None)
        if iss not in issuers_list:
            raise UnauthorizedError(message="Unauthorized. Unknown Issuer.")

        if audiences_list:
            if (
                (not aud)
                or (
                    isinstance(aud, list)
                    and not (set(audiences_list).issubset(set(aud)))
                )
                or (isinstance(aud, str) and aud not in audiences_list)
            ):
                raise UnauthorizedError(message="Unauthorized. Unknown Audience.")

        jwks = jwks_cache.get().get(iss, None)

        if not jwks:
            try:
                jwks_list_index = list(issuers_list).index(iss)
                jwks_url = (
                    jwks_urls_list[jwks_list_index]
                    if jwks_list_index < len(jwks_urls_list)
                    else iss.rstrip("/") + "/.well-known/jwks.json"
                )

                res = httpx.get(jwks_url)
                res.raise_for_status()
                jwks = res.json()
                jwks_cache.get()[iss] = jwks
            except Exception as e:
                raise InternalServerError(
                    code="G2P-AUT-500",
                    message=f"Something went wrong while trying to fetch Jwks. {repr(e)}",
                ) from e

        try:
            jwt.decode(
                jwt_token,
                jwks,
                options={
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_sub": False,
                },
            )
        except Exception as e:
            raise UnauthorizedError(
                message=f"Unauthorized. Invalid Jwt. {repr(e)}"
            ) from e

        if jwt_id_token:
            try:
                res = jwt.decode(
                    jwt_id_token,
                    jwks,
                    access_token=jwt_token,
                    options={
                        "verify_aud": False,
                        "verify_iss": False,
                        "verify_sub": False,
                        "verify_at_hash": api_auth_settings.get(
                            "id_token_verify_at_hash",
                            config_dict.get("default_id_token_verify_at_hash", True),
                        ),
                    },
                )
                if res:
                    unverified_payload.update(res)
            except Exception as e:
                raise UnauthorizedError(
                    message=f"Unauthorized. Invalid Jwt ID Token. {repr(e)}"
                ) from e

        claim_to_check = config_dict.get("claim_name", None)
        claim_values = config_dict.get("claim_values", None)
        if claim_to_check:
            claims = unverified_payload.get(claim_to_check, None)
            if not claims:
                raise ForbiddenError(message="Forbidden. Claim(s) missing.")
            if isinstance(claims, str):
                if len(claim_values) != 1 or claim_values[0] != claims:
                    raise ForbiddenError(message="Forbidden. Claim doesn't match.")
            else:
                if all(x in claims for x in claim_values):
                    raise ForbiddenError(message="Forbidden. Claim(s) don't match.")

        unverified_payload["credentials"] = jwt_token

        return AuthCredentials.model_validate(unverified_payload)
