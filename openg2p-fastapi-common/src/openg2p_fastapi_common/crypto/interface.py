from ..service import BaseService


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
