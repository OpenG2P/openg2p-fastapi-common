import logging

from openg2p_fastapi_common.service import BaseService
from openg2p_fastapi_common.utils.crypto import CryptoHelper

from .config import Settings

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class JWTValidationHelper(BaseService):
    crypto_helper: CryptoHelper = CryptoHelper.get_cached_component()

    async def verify_jwt(self, orig_jwt: str, payload: dict, **kw) -> bool:
        return await self.crypto_helper.verify_jwt(
            orig_jwt,
            payload=payload,
            km_app_id=_config.jwt_validate_keymanager_app_id,
            km_ref_id=self.get_partner_id_from_payload(payload),
            **kw,
        )

    def get_partner_id_from_payload(self, payload: dict, **kw) -> str:
        # TODO: Remove this legacy structure after all partners have migrated to use request_header
        header = payload.get("header")
        if header:
            value = header["sender_id"].replace("-", "_").upper()
            return f"PARTNER_{value}"
        req_header = payload.get("request_header")
        if req_header:
            value = req_header["sender_app_mnemonic"].replace("-", "_").upper()
            return f"PARTNER_{value}"
        return "PARTNER_UNKNOWN"
