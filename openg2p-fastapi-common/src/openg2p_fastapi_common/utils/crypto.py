import base64
import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx
import orjson
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, pkcs12
from cryptography.x509 import load_pem_x509_certificate
from jwt import PyJWS
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

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


# ============================================================================
# Local (Keymanager-free) JWS backend — PyJWT + cryptography.
#
# Drop-in CryptoHelper that does all signing/verification IN-PROCESS, with no
# Keymanager service:
#   * verify_jwt  — verifies a detached JWS (header..signature) sent by a partner
#                   in the "Signature" header, against the partner's public
#                   certificate looked up by km_ref_id (PARTNER_<MNEMONIC>) in the
#                   DB-backed PartnerKeyStore (the partner_keys table).
#   * create_jwt_token — signs a payload with this service's own private key,
#                   loaded from a password-protected PKCS#12 (.p12) keystore, and
#                   returns a detached JWS.
#
# Wire contract (identical to the Keymanager path, so partners need no change):
#   signing input = base64url(protected_header) + "." + base64url(canonical_json(body))
#   canonical_json = compact, UTF-8, sort-keys (orjson OPT_SORT_KEYS).
#
# Selection is via crypto_backend ("keymanager" | "local"); see build_crypto_helper.
# Keymanager (above) is intentionally left untouched.
# ============================================================================

DEFAULT_ALLOWED_ALGORITHMS = ("RS256",)
DEFAULT_SIGNING_ALGORITHM = "RS256"
DEFAULT_PARTNER_KEY_CACHE_TTL_SECONDS = 300


def is_forbidden_algorithm(alg) -> bool:
    """Algorithms that are NEVER allowed regardless of config: ``none`` and the
    HMAC family (HS*) — accepting a symmetric alg against an asymmetric key store
    is the classic JWS algorithm-confusion attack."""
    if not alg or str(alg).lower() == "none":
        return True
    return str(alg).upper().startswith("HS")


class PartnerKeyStore:
    """DB-backed store of partner public certs for inbound JWS verification.

    Looks up active, currently-valid certs for a ``reference_id`` in the
    ``partner_keys`` table and returns lightweight dicts (kid / algorithm /
    public_key_pem). Results are cached per reference_id for a short TTL so a high
    request rate does not hit the DB on every check; rotation/revocation propagate
    within one TTL window. A ``session_maker`` may be injected (tests); otherwise
    one is built lazily from the process-wide async engine.
    """

    def __init__(
        self,
        session_maker=None,
        cache_ttl_seconds=DEFAULT_PARTNER_KEY_CACHE_TTL_SECONDS,
        clock=time.monotonic,
    ):
        self._session_maker = session_maker
        self._ttl = cache_ttl_seconds
        self._clock = clock
        self._cache = {}  # reference_id -> (expiry_monotonic, list[dict])
        self._lock = threading.Lock()

    def _maker(self):
        if self._session_maker is not None:
            return self._session_maker
        from ..context import dbengine

        return async_sessionmaker(dbengine.get(), expire_on_commit=False)

    async def get_keys(self, reference_id):
        """Return active partner key dicts for ``reference_id``, or None if unknown."""
        if not reference_id:
            return None
        now = self._clock()
        with self._lock:
            cached = self._cache.get(reference_id)
            if cached and cached[0] > now:
                return cached[1] or None

        try:
            from ..models import PartnerKey

            maker = self._maker()
            async with maker() as session:
                result = await session.execute(
                    select(PartnerKey).where(
                        PartnerKey.reference_id == reference_id,
                        PartnerKey.status == "active",
                    )
                )
                rows = result.scalars().all()
        except Exception:
            _logger.exception("Failed to load partner keys for '%s'", reference_id)
            return None

        wall_now = datetime.now()
        keys = []
        for row in rows:
            if row.valid_from and row.valid_from > wall_now:
                continue
            if row.valid_to and row.valid_to < wall_now:
                continue
            if not row.public_key:
                continue
            keys.append(
                {"kid": row.kid, "algorithm": row.algorithm or "RS256", "public_key_pem": row.public_key}
            )

        with self._lock:
            self._cache[reference_id] = (now + self._ttl, keys)
        if not keys:
            _logger.warning("No active partner keys for reference id '%s'", reference_id)
            return None
        return keys

    def invalidate(self, reference_id=None):
        with self._lock:
            if reference_id is None:
                self._cache.clear()
            else:
                self._cache.pop(reference_id, None)


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

    # ------------------------------ verify (inbound) ------------------------------

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
        keys = await self._partner_key_store.get_keys(km_ref_id)
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

    # ------------------------------- sign (outbound) ------------------------------

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

    # ---------------------------------- helpers -----------------------------------

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


def _cert_thumbprint(pem):
    pem_bytes = pem.encode() if isinstance(pem, str) else pem
    cert = load_pem_x509_certificate(pem_bytes)
    return base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).decode().rstrip("=")


async def seed_partner_certs(certs, session_maker=None):
    """Upsert partner public certs into the partner_keys table (idempotent).

    Seed-based onboarding for the local backend. Each entry is a dict:
    ``{"reference_id": "PARTNER_<MNEMONIC>", "public_key": "<PEM>",
    "kid": "<optional>", "algorithm": "RS256"}``. kid defaults to the cert's
    SHA-256 thumbprint. An entry whose (reference_id, kid) already exists is left
    untouched, so re-running migrate on upgrade is safe.

    TODO (runtime onboarding): expose an authenticated admin API to register/revoke
    partner certs at runtime instead of (or in addition to) this install-time seed.
    """
    if not certs:
        return
    from ..models import PartnerKey

    if session_maker is None:
        from ..context import dbengine

        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)

    added = 0
    async with session_maker() as session:
        for entry in certs:
            reference_id = entry.get("reference_id")
            public_key = entry.get("public_key")
            if not reference_id or not public_key:
                _logger.warning("Skipping partner cert with missing reference_id/public_key")
                continue
            try:
                kid = entry.get("kid") or _cert_thumbprint(public_key)
            except Exception:
                _logger.exception("Invalid partner cert PEM for '%s'; skipping", reference_id)
                continue
            algorithm = entry.get("algorithm") or "RS256"
            existing = await session.execute(
                select(PartnerKey).where(PartnerKey.reference_id == reference_id, PartnerKey.kid == kid)
            )
            if existing.scalars().first():
                continue
            session.add(
                PartnerKey(
                    reference_id=reference_id,
                    public_key=public_key,
                    kid=kid,
                    algorithm=algorithm,
                    status="active",
                )
            )
            added += 1
        if added:
            await session.commit()
    _logger.info("Seeded %d partner cert(s) into partner_keys", added)


def build_crypto_helper(name="", backend=None, **kwargs) -> CryptoHelper:
    """Register the configured CryptoHelper backend.

    ``crypto_backend`` (config) selects:
      * "keymanager" (default) -> KeymanagerCryptoHelper (unchanged remote service).
      * "local"                -> PyJWTCryptoHelper (in-process PyJWT, no Keymanager).
    ``backend`` overrides the config when given. Extra kwargs pass through to the
    chosen helper (e.g. name= for a dedicated signing instance).
    """
    backend = backend or _config.crypto_backend
    if backend == "local":
        return PyJWTCryptoHelper(name=name, **kwargs)
    return KeymanagerCryptoHelper(name=name, **kwargs)
