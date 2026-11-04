import base64
import json
import logging

import orjson
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, pkcs12
from cryptography.x509 import load_pem_x509_certificate
from jwt import PyJWS

from ..config import Settings
from .constants import DEFAULT_ALLOWED_ALGORITHMS, DEFAULT_SIGNING_ALGORITHM, is_forbidden_algorithm
from .interface import CryptoHelper
from .partner_key_store import PartnerKeyStore

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class PyJWTCryptoHelper(CryptoHelper):
    def __init__(
        self,
        *,
        partner_key_store=None,
        signing_key_path=None,
        signing_key_password=None,
        signing_key_kid=None,
        signing_algorithm=None,
        allowed_algorithms=None,
        name="",
        **kwargs,
    ):
        super().__init__(name=name)
        _ = kwargs
        if allowed_algorithms is None:
            allowed_algorithms = [
                a.strip() for a in (_config.crypto_allowed_algorithms or "").split(",") if a.strip()
            ] or list(DEFAULT_ALLOWED_ALGORITHMS)
        self.allowed_algorithms = tuple(allowed_algorithms)
        self._partner_key_store = partner_key_store if partner_key_store is not None else PartnerKeyStore()
        self._signing_key_path = (
            signing_key_path if signing_key_path is not None else (_config.crypto_signing_key_path or None)
        )
        self._signing_key_password = (
            signing_key_password
            if signing_key_password is not None
            else (_config.crypto_signing_key_password or None)
        )
        self._signing_key_kid = (
            signing_key_kid if signing_key_kid is not None else (_config.crypto_signing_key_kid or None)
        )
        self._signing_algorithm = (
            signing_algorithm or _config.crypto_signing_algorithm or DEFAULT_SIGNING_ALGORITHM
        )
        self._signing_key = None  # lazy-loaded cryptography private key
        self._signing_kid = None  # kid derived from the signing cert on load
        self._jws = PyJWS()

    async def aclose(self):
        """No remote client to close; kept for interface parity."""

    async def verify_jwt(self, orig_jwt, payload=None, km_app_id=None, km_ref_id=None, **kwargs) -> bool:
        if not orig_jwt:
            _logger.error("Empty JWS signature")
            return False
        try:
            part1, part2, part3 = orig_jwt.split(".")
        except ValueError:
            _logger.error("Malformed detached JWS; expected 'header..signature'")
            return False

        header = self._decode_header(part1)
        if header is None:
            return False
        alg = header.get("alg")
        if not self._is_algorithm_allowed(alg):
            _logger.error("Rejected JWS algorithm '%s' (not in allowed set %s)", alg, self.allowed_algorithms)
            return False

        if self._partner_key_store is None:
            _logger.error("Partner key store not configured; cannot verify signature")
            return False
        keys = await self._partner_key_store.get_keys(km_ref_id, wanted_kid=header.get("kid"))
        if not keys:
            _logger.error("No registered keys for partner '%s'", km_ref_id)
            return False

        candidates = self._candidate_keys(keys, header, alg)
        if not candidates:
            _logger.error("No registered key matches kid/alg for partner '%s'", km_ref_id)
            return False

        if payload is None:
            if not part2:
                _logger.error("Detached JWS supplied without a payload to verify against")
                return False
            verifiable = orig_jwt
        else:
            verifiable = f"{part1}.{self._b64u(self._canonical(payload))}.{part3}"

        for entry in candidates:
            try:
                key = self._load_public_key(entry["public_key_pem"])
                self._jws.decode(verifiable, key, algorithms=[alg])
            except Exception:
                continue
            _logger.info(
                "JWS signature verified for partner '%s' (alg=%s, kid=%s)", km_ref_id, alg, header.get("kid")
            )
            return True

        _logger.error("JWS signature verification failed for partner '%s'", km_ref_id)
        return False

    async def create_jwt_token(self, payload, include_payload=False, **kwargs) -> str:
        key = self._load_signing_key()
        alg = kwargs.get("algorithm") or self._signing_algorithm
        if not self._is_algorithm_allowed(alg):
            raise ValueError(f"Signing algorithm '{alg}' is not in the allowed set")
        headers = {}
        kid = self._signing_key_kid or self._signing_kid
        if kid:
            headers["kid"] = kid
        full = self._jws.encode(self._canonical(payload), key, algorithm=alg, headers=headers)
        part1, _part2, part3 = full.split(".")
        if include_payload:
            return full
        return f"{part1}..{part3}"

    def _load_signing_key(self):
        if self._signing_key is not None:
            return self._signing_key
        if not self._signing_key_path:
            raise ValueError("Signing key path not configured; cannot create JWS")
        with open(self._signing_key_path, "rb") as handle:
            data = handle.read()
        password = self._signing_key_password.encode() if self._signing_key_password else None
        private_key, cert, _extra = pkcs12.load_key_and_certificates(data, password)
        if private_key is None:
            raise ValueError("PKCS#12 keystore contains no private key")
        if cert is not None:
            # kid = the cert's SHA-256 thumbprint, so the verifier can correlate it.
            self._signing_kid = self._b64u(cert.fingerprint(hashes.SHA256()))
        self._signing_key = private_key
        return self._signing_key

    @staticmethod
    def _load_public_key(pem):
        pem_bytes = pem.encode() if isinstance(pem, str) else pem
        if b"BEGIN CERTIFICATE" in pem_bytes:
            return load_pem_x509_certificate(pem_bytes).public_key()
        return load_pem_public_key(pem_bytes)

    def _candidate_keys(self, keys, header, alg):
        kid = header.get("kid")
        candidates = []
        for entry in keys:
            if kid and entry.get("kid") and entry.get("kid") != kid:
                continue
            key_alg = entry.get("algorithm")
            if key_alg and key_alg != alg:
                continue
            candidates.append(entry)
        return candidates

    def _is_algorithm_allowed(self, alg):
        return bool(alg) and not is_forbidden_algorithm(alg) and alg in self.allowed_algorithms

    @staticmethod
    def _decode_header(part1):
        try:
            padded = part1 + "=" * (-len(part1) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            _logger.exception("Failed to decode JWS protected header")
            return None

    @staticmethod
    def _canonical(payload) -> bytes:
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, str):
            return payload.encode()
        return orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)

    @staticmethod
    def _b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")
