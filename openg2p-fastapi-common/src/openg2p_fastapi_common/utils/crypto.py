import base64
import logging
from datetime import datetime, timedelta, timezone

import httpx
import orjson

from ..config import Settings
from ..service import BaseService

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class CryptoHelper(BaseService):
    async def aclose(self):
        """Closes Crypto Helper"""

    async def verify_jwt(self, orig_jwt: str, payload=None, **kw) -> bool:
        """Verify the jwt given in the request, replies with boolean validity."""
        raise NotImplementedError()

    async def create_jwt_token(
        self,
        payload,
        include_payload=True,
        include_certificate=False,
        include_cert_hash=False,
        **kw,
    ) -> str:
        """Creates a JWT token for the given payload"""
        raise NotImplementedError()

    # TODO: more interfaces defined as per requirement


class KeymanagerCryptoHelper(CryptoHelper):
    def __init__(
        self,
        api_base_url=_config.keymanager_api_base_url,
        auth_enabled=_config.keymanager_auth_enabled,
        auth_url=_config.keymanager_auth_url,
        auth_client_id=_config.keymanager_auth_client_id,
        auth_client_secret=_config.keymanager_auth_client_secret,
        api_domain=_config.keymanager_api_domain,
        ssl_verify=_config.keymanager_ssl_verify,
        api_timeout=_config.keymanager_api_timeout,
        sign_app_id=_config.keymanager_sign_app_id,
        sign_ref_id=_config.keymanager_sign_ref_id,
        **kw,
    ):
        super().__init__(**kw)

        self.api_base_url = api_base_url
        self.auth_enabled = auth_enabled
        self.auth_url = auth_url
        self.auth_client_id = auth_client_id
        self.auth_client_secret = auth_client_secret

        self.api_domain = api_domain
        self.sign_app_id = sign_app_id
        self.sign_ref_id = sign_ref_id

        self.auth_token = ""
        self.auth_token_expiry: datetime | None = None

        self.http_client = httpx.AsyncClient(verify=ssl_verify, timeout=api_timeout)

    async def aclose(self):
        await self.http_client.aclose()

    async def verify_jwt(self, orig_jwt: str, payload=None, km_app_id=None, km_ref_id=None, **kw) -> bool:
        # If payload not None, perform payload validation also.
        if payload is None:
            actual_data = None
            final_jwt = orig_jwt
        else:
            try:
                part1, _, part3 = orig_jwt.split(".")
            except Exception as e:
                raise ValueError("Malformed detached JWT format. Expected format: part1..part3") from e

            actual_data = self.base64url_encode(self.treat_payload_types(payload))

            # Reconstruct full JWT
            final_jwt = f"{part1}.{actual_data}.{part3}"

        if km_app_id is None:
            km_app_id = await self.get_verify_app_id(orig_jwt, payload=payload, **kw)
        if km_ref_id is None:
            km_ref_id = await self.get_verify_ref_id(payload, **kw)

        # Send request to external service for verification
        cookies = {}
        if self.auth_enabled:
            cookies["Authorization"] = await self.get_auth_token()
        response = await self.http_client.post(
            f"{self.api_base_url}/jwtVerify",
            json={
                "id": "string",
                "version": "string",
                "requesttime": self.get_current_isotimestamp(),
                "metadata": {},
                "request": {
                    "jwtSignatureData": final_jwt,
                    "actualData": actual_data,
                    "applicationId": km_app_id,
                    "referenceId": km_ref_id,
                    "certificateData": "",
                    "validateTrust": False,
                    "domain": self.api_domain,
                },
            },
            cookies=cookies,
        )
        try:
            response.raise_for_status()
            return response.json()["response"]["signatureValid"]
        except Exception as e:
            _logger.error("Keymanager JWT Verify API response: %s", response.text)
            _logger.exception("KeymanagerHelper: Error validating JWT")
            raise e

    async def create_jwt_token(
        self,
        payload,
        include_payload=True,
        include_certificate=False,
        include_cert_hash=False,
        km_app_id=None,
        km_ref_id=None,
        **kw,
    ) -> str:
        if km_app_id is None:
            km_app_id = await self.get_sign_app_id(payload, **kw)
        if km_ref_id is None:
            km_ref_id = await self.get_sign_ref_id(payload, **kw)

        cookies = {}
        if self.auth_enabled:
            cookies["Authorization"] = await self.get_auth_token()
        response = await self.http_client.post(
            f"{self.api_base_url}/jwtSign",
            json={
                "id": "string",
                "version": "string",
                "requesttime": self.get_current_isotimestamp(),
                "metadata": {},
                "request": {
                    "dataToSign": self.base64url_encode(self.treat_payload_types(payload)),
                    "applicationId": km_app_id,
                    "referenceId": km_ref_id,
                    "includePayload": include_payload,
                    "includeCertificate": include_certificate,
                    "includeCertHash": include_cert_hash,
                },
            },
            cookies=cookies,
        )
        try:
            response.raise_for_status()
            return response.json()["response"]["jwtSignedData"]
        except Exception as e:
            _logger.error("Keymanager JWT Sign API response: %s", response.text)
            _logger.exception("KeymanagerHelper: Error creating JWT")
            raise e

    async def get_verify_app_id(self, orig_jwt: str, payload=None, **kw):
        return self.sign_app_id

    async def get_verify_ref_id(self, payload, **kw):
        return self.sign_ref_id

    async def get_sign_app_id(self, payload, **kw):
        return self.sign_app_id

    async def get_sign_ref_id(self, payload, **kw):
        return self.sign_ref_id

    async def get_auth_token(self) -> str:
        if (
            self.auth_token
            and self.auth_token_expiry
            and self.auth_token_expiry > datetime.now(tz=timezone.utc)
        ):
            return self.auth_token
        response = await self.http_client.post(
            self.auth_url,
            data={
                "client_id": self.auth_client_id,
                "client_secret": self.auth_client_secret,
                "grant_type": "client_credentials",
            },
        )
        response_data = response.json()
        expires_in = response_data.get("expires_in", 900)
        self.auth_token_expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in)
        self.auth_token = response_data["access_token"]
        return self.auth_token

    def treat_payload_types(self, payload) -> bytes:
        if isinstance(payload, dict):
            # Canonicalize JSON using separators and encode to base64url (same as JWT payload encoding)
            payload = orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)
        elif isinstance(payload, str):
            payload = payload.encode()
        return payload

    def base64url_encode(self, input: bytes) -> str:
        return base64.urlsafe_b64encode(input).decode().rstrip("=")

    def get_current_isotimestamp(self) -> str:
        return f"{datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat(timespec='milliseconds')}Z"
