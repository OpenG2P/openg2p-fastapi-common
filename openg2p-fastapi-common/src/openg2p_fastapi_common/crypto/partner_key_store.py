import logging
import threading
import time
from datetime import datetime

from sqlalchemy import select

from ..config import Settings
from .constants import DEFAULT_PARTNER_KEY_CACHE_TTL_SECONDS

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


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
        from ..context import get_async_session_maker

        return get_async_session_maker()

    async def get_keys(self, reference_id, wanted_kid=None):
        """Return active partner key dicts for ``reference_id``, or None if unknown.

        ``wanted_kid`` is accepted for interface parity with PartnerMgmtKeyStore
        (which uses it for refresh-on-unknown-kid); the DB store already returns
        every active key, so it is ignored here.
        """
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
