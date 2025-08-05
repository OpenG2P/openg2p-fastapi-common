import logging
from datetime import datetime, timedelta, timezone

import httpx
import orjson
from fastapi import Request
from fastapi.datastructures import QueryParams
from fastapi.responses import RedirectResponse
from jose import jwt
from openg2p_fastapi_common.controller import BaseController
from openg2p_fastapi_common.errors.http_exceptions import UnauthorizedError
from openg2p_fastapi_common.utils.crypto import KeymanagerCryptoHelper

from ..config import Settings
from ..models.orm.login_provider import LoginProvider, LoginProviderTypes
from ..models.provider_auth_parameters import (
    OauthClientAssertionType,
    OauthProviderParameters,
)
from .auth_controller import AuthController

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class OAuthController(BaseController):
    auth_controller: AuthController = AuthController.get_cached_component()
    keymanager_helper: KeymanagerCryptoHelper = KeymanagerCryptoHelper.get_cached_component()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.router.prefix += "/oauth2"
        self.router.tags += ["oauth"]

        self.router.add_api_route(
            "/callback",
            self.oauth_callback,
            methods=["GET"],
        )

    async def oauth_callback(self, request: Request):
        """
        Oauth2 Redirect Url. Auth Server will redirect to this URL after the Authentication is successful.

        Internal Errors:
        - Code: G2P-AUT-401. HTTP: 401. Message: Login Provider Id not received.
        """
        state = orjson.loads(request.query_params.get("state", "{}"))
        login_provider_id = state.get("p", None)
        if not login_provider_id:
            raise UnauthorizedError("G2P-AUT-401", "Login Provider Id not received")

        login_provider = await self.auth_controller.get_login_provider_db_by_id(login_provider_id)

        res = await self.oauth_get_tokens(login_provider, request.query_params)

        config_dict = _config.model_dump()
        access_token: str = res["access_token"]
        id_token: str = res["id_token"]
        expires_in = None
        if config_dict.get("auth_cookie_set_expires", False):
            expires_in = res.get("expires_in", None)
            if expires_in:
                expires_in = datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in)

        response = RedirectResponse(state.get("r", "/"))
        response.set_cookie(
            "X-Access-Token",
            access_token,
            max_age=config_dict.get("auth_cookie_max_age", None),
            expires=expires_in,
            path=config_dict.get("auth_cookie_path", "/"),
            httponly=config_dict.get("auth_cookie_httponly", True),
            secure=config_dict.get("auth_cookie_secure", True),
        )
        response.set_cookie(
            "X-ID-Token",
            id_token,
            max_age=config_dict.get("auth_cookie_max_age", None),
            expires=expires_in,
            path=config_dict.get("auth_cookie_path", "/"),
            httponly=config_dict.get("auth_cookie_httponly", True),
            secure=config_dict.get("auth_cookie_secure", True),
        )

        return response

    async def oauth_get_tokens(self, login_provider: LoginProvider, query_params: QueryParams, **kw):
        if login_provider.type == LoginProviderTypes.oauth2_auth_code:
            auth_parameters = OauthProviderParameters.model_validate(login_provider.authorization_parameters)
            token_request_data = {
                "client_id": auth_parameters.client_id,
                "grant_type": "authorization_code",
                "redirect_uri": auth_parameters.redirect_uri,
                "code": query_params.get("code"),
            }
            if auth_parameters.enable_pkce:
                token_request_data["code_verifier"] = auth_parameters.code_verifier

            token_auth = None
            if auth_parameters.client_assertion_type.name.startswith("private_key_jwt"):
                await self.oauth_update_client_assertion(auth_parameters, token_request_data, **kw)
            elif auth_parameters.client_assertion_type == OauthClientAssertionType.client_secret_basic:
                token_auth = (auth_parameters.client_id, auth_parameters.client_secret)
            elif auth_parameters.client_assertion_type == OauthClientAssertionType.client_secret:
                token_request_data["client_secret"] = auth_parameters.client_secret
            try:
                res = httpx.post(
                    auth_parameters.token_endpoint,
                    auth=token_auth,
                    data=orjson.loads(orjson.dumps(token_request_data)),
                )
                res.raise_for_status()
                res = res.json()
                return res
            except Exception as e:
                _logger.exception(
                    "Error while fetching token from token endpoint, %s",
                    auth_parameters.token_endpoint,
                )
                raise UnauthorizedError(message="Unauthorized. Failed to get token from Oauth Server") from e
        else:
            raise NotImplementedError()

    async def oauth_update_client_assertion(
        self, auth_parameters: OauthProviderParameters, token_request_data: dict, **kw
    ):
        if (
            auth_parameters.client_assertion_type == OauthClientAssertionType.private_key_jwt
            or auth_parameters.client_assertion_type == OauthClientAssertionType.private_key_jwt_legacy
        ):
            iat = datetime.now(tz=timezone.utc).replace(tzinfo=None)
            exp = iat + timedelta(hours=1)
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_assertion = jwt.encode(
                {
                    "iss": auth_parameters.client_id,
                    "sub": auth_parameters.client_id,
                    "aud": auth_parameters.client_assertion_jwt_aud or auth_parameters.token_endpoint,
                    "iat": int(iat.timestamp()),
                    "exp": int(exp.timestamp()),
                },
                auth_parameters.client_assertion_jwk,
                algorithm="RS256",
            )
        elif auth_parameters.client_assertion_type == OauthClientAssertionType.private_key_jwt_keymanager:
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_assertion = await self.oauth_generate_client_assertion_keymanager(auth_parameters, **kw)
        else:
            raise NotImplementedError()
        token_request_data.update(
            {"client_assertion_type": client_assertion_type, "client_assertion": client_assertion}
        )

    async def oauth_generate_client_assertion_keymanager(
        self, auth_parameters: OauthProviderParameters, **kw
    ):
        app_id_ref_id = auth_parameters.client_assertion_jwk_keymanager
        if ":" in app_id_ref_id:
            km_app_id = auth_parameters.client_assertion_jwk_keymanager.split(":")[0].strip()
            km_ref_id = auth_parameters.client_assertion_jwk_keymanager.split(":")[1].strip()
        else:
            km_app_id = app_id_ref_id
            km_ref_id = ""
        iat = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        exp = iat + timedelta(hours=1)
        return await self.keymanager_helper.create_jwt_token(
            {
                "iss": auth_parameters.client_id,
                "sub": auth_parameters.client_id,
                "aud": auth_parameters.client_assertion_jwt_aud or auth_parameters.token_endpoint,
                "iat": int(iat.timestamp()),
                "exp": int(exp.timestamp()),
            },
            km_app_id=km_app_id,
            km_ref_id=km_ref_id,
            **kw,
        )
