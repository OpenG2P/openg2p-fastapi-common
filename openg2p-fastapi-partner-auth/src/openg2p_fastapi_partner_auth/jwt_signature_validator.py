import logging

import orjson
from fastapi import Request
from fastapi.security import HTTPBearer

from .config import Settings
from .jwt_validation_helper import JWTValidationHelper

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class JWTSignatureValidator(HTTPBearer):
    jwt_validate_helper: JWTValidationHelper = JWTValidationHelper.get_cached_component()

    async def __call__(self, request: Request) -> bool:
        # Get request body and decode to JSON
        request_body = await request.body()
        request_json = orjson.loads(request_body)

        # Get JWT from header
        jwt_signature_data = request.headers.get("Signature")
        if not jwt_signature_data:
            _logger.error("Signature Header is not present or empty.")
            return False

        return await self.jwt_validate_helper.verify_jwt(jwt_signature_data, request_json)
