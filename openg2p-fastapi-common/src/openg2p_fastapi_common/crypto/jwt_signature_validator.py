import logging

import orjson
from fastapi import Request

from openg2p_fastapi_common.config import Settings

from .jwt_validation_helper import JWTValidationHelper

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class JWTSignatureValidator:
    async def __call__(self, request: Request) -> bool:
        request_body = await request.body()
        request_json = orjson.loads(request_body)

        jwt_signature_data = request.headers.get("Signature")
        if not jwt_signature_data:
            _logger.error("Signature Header is not present or empty.")
            return False

        jwt_validate_helper = JWTValidationHelper.get_component()
        return await jwt_validate_helper.verify_jwt(jwt_signature_data, request_json)
