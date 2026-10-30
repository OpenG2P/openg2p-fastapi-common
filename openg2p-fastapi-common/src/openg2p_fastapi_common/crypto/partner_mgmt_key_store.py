import asyncio
import logging
import threading
import time
from urllib.parse import quote

import httpx

from ..config import Settings
from .constants import PARTNER_KEY_MIN_TTL_SECONDS

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class _RemoteCacheEntry:
    __slots__ = ("keys", "fetched_at", "last_attempt", "ttl")

    def __init__(self, keys, fetched_at, last_attempt, ttl):
        # keys is None for a "not available" (404) negative entry.
        self.keys = keys
        self.fetched_at = fetched_at  # monotonic time of last SUCCESSFUL fetch
        self.last_attempt = last_attempt  # monotonic time of last fetch attempt
        self.ttl = ttl  # effective soft TTL for this entry


class PartnerMgmtKeyStore:
    """Partner public keys fetched from the Partner Management service (partner-api).

    Drop-in alternative to ``PartnerKeyStore`` for the ``partner-mgmt`` crypto
    backend: same ``get_keys(reference_id, wanted_kid=...)`` contract, but the
    source is ``GET {partner_mgmt_api_url}/keys/{reference_id}`` instead of a
    local ``partner_keys`` table. So other OpenG2P modules can verify partner
    signatures without seeding keys locally and without an HTTP call per request.

    Cache policy (all TTLs configurable):
      * Soft TTL — refresh window; also the min(client, server ``Cache-Control``)
        that bounds how long a revoked key / disabled partner stays trusted.
      * Hard TTL — if PM is unreachable, keep serving the last-known-good keys up
        to this age (logged at WARNING), then fail closed.
      * Negative cache — a 404 ("not available", e.g. disabled/unknown partner)
        is remembered briefly so a disabled partner does not trigger a fetch per
        request; still fails closed.
      * Refresh-on-unknown-kid — a request presenting a kid absent from the cache
        (a just-rotated partner) forces one refresh, rate-limited by a cooldown.
      * Single-flight — concurrent misses for the same partner collapse into one
        HTTP call.
    """

    def __init__(
        self,
        api_url=None,
        *,
        soft_ttl=None,
        hard_ttl=None,
        negative_ttl=None,
        refresh_cooldown=None,
        timeout=None,
        transport=None,
        clock=time.monotonic,
    ):
        self._api_url = (api_url if api_url is not None else _config.partner_mgmt_api_url or "").rstrip("/")
        self._soft_ttl = soft_ttl if soft_ttl is not None else _config.partner_key_cache_ttl_seconds
        self._hard_ttl = hard_ttl if hard_ttl is not None else _config.partner_key_hard_ttl_seconds
        self._negative_ttl = (
            negative_ttl if negative_ttl is not None else _config.partner_key_negative_ttl_seconds
        )
        self._refresh_cooldown = (
            refresh_cooldown if refresh_cooldown is not None else _config.partner_key_refresh_cooldown_seconds
        )
        self._timeout = timeout if timeout is not None else _config.partner_key_fetch_timeout_seconds
        self._transport = transport  # injectable httpx transport for tests
        self._clock = clock
        self._cache = {}  # reference_id -> _RemoteCacheEntry
        self._cache_lock = threading.Lock()
        self._flight_locks = {}  # reference_id -> asyncio.Lock (single-flight)

    async def get_keys(self, reference_id, wanted_kid=None):
        """Return active partner key dicts for ``reference_id``, or None."""
        if not reference_id:
            return None
        if not self._api_url:
            _logger.error("partner_mgmt_api_url is not configured; cannot fetch partner keys")
            return None

        now = self._clock()
        entry = self._get_cached(reference_id)
        if entry is not None and not self._needs_fetch(entry, now, wanted_kid):
            return entry.keys  # fresh (positive keys, or a fresh negative -> None)

        # Single-flight: one in-flight fetch per partner; others await and reuse it.
        async with self._flight_lock(reference_id):
            now = self._clock()
            entry = self._get_cached(reference_id)
            if entry is not None and not self._needs_fetch(entry, now, wanted_kid):
                return entry.keys
            return await self._fetch_and_cache(reference_id, entry, now)

    def invalidate(self, reference_id=None):
        with self._cache_lock:
            if reference_id is None:
                self._cache.clear()
            else:
                self._cache.pop(reference_id, None)

    def _get_cached(self, reference_id):
        with self._cache_lock:
            return self._cache.get(reference_id)

    def _store(self, reference_id, entry):
        with self._cache_lock:
            self._cache[reference_id] = entry

    def _flight_lock(self, reference_id):
        with self._cache_lock:
            lock = self._flight_locks.get(reference_id)
            if lock is None:
                lock = asyncio.Lock()
                self._flight_locks[reference_id] = lock
            return lock

    def _needs_fetch(self, entry, now, wanted_kid):
        # Never attempt more often than the cooldown — this throttles both
        # unknown-kid refreshes and refetch storms during a PM outage.
        if (now - entry.last_attempt) < self._refresh_cooldown:
            return False
        if entry.keys is None:  # negative entry
            return (now - entry.fetched_at) >= self._negative_ttl
        if (now - entry.fetched_at) >= entry.ttl:  # stale -> refresh
            return True
        if wanted_kid and not self._has_kid(entry.keys, wanted_kid):  # rotation
            return True
        return False

    @staticmethod
    def _has_kid(keys, kid):
        return any(k.get("kid") == kid for k in keys)

    async def _fetch_and_cache(self, reference_id, prev, now):
        url = f"{self._api_url}/keys/{quote(reference_id, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
                resp = await client.get(url)
        except Exception as e:
            return self._on_error(reference_id, prev, now, f"request failed: {e!r}")

        if resp.status_code == 404:
            self._store(reference_id, _RemoteCacheEntry(None, now, now, self._negative_ttl))
            _logger.info(
                "Partner '%s' not available (404 from PM); negative-cached for %ss",
                reference_id,
                self._negative_ttl,
            )
            return None
        if resp.status_code != 200:
            return self._on_error(reference_id, prev, now, f"HTTP {resp.status_code}")

        try:
            keys = self._parse(resp.json())
        except Exception as e:
            return self._on_error(reference_id, prev, now, f"bad response body: {e!r}")

        if not keys:
            self._store(reference_id, _RemoteCacheEntry(None, now, now, self._negative_ttl))
            _logger.warning("PM returned no usable keys for partner '%s'", reference_id)
            return None

        ttl = self._effective_ttl(resp)
        self._store(reference_id, _RemoteCacheEntry(keys, now, now, ttl))
        _logger.info(
            "Fetched %d key(s) for partner '%s' from PM (soft_ttl=%ss)", len(keys), reference_id, ttl
        )
        return keys

    def _on_error(self, reference_id, prev, now, why):
        # Serve last-known-good keys within the hard TTL; otherwise fail closed.
        if prev is not None and prev.keys is not None and (now - prev.fetched_at) < self._hard_ttl:
            _logger.warning(
                "PM key fetch for '%s' failed (%s); serving STALE keys (age=%.0fs, hard_ttl=%ss)",
                reference_id,
                why,
                now - prev.fetched_at,
                self._hard_ttl,
            )
            # Bump only last_attempt so we don't retry until the next cooldown.
            self._store(reference_id, _RemoteCacheEntry(prev.keys, prev.fetched_at, now, prev.ttl))
            return prev.keys
        _logger.error(
            "PM key fetch for '%s' failed (%s) and no usable cached keys; failing closed",
            reference_id,
            why,
        )
        # Record the attempt so a hard-down PM is retried at most once per cooldown.
        self._store(reference_id, _RemoteCacheEntry(None, 0.0, now, self._negative_ttl))
        return None

    @staticmethod
    def _parse(data):
        out = []
        for k in (data or {}).get("keys", []):
            pem = k.get("public_key")
            if not pem:
                continue
            out.append(
                {
                    "kid": k.get("kid"),
                    "algorithm": k.get("algorithm") or "RS256",
                    "public_key_pem": pem,
                }
            )
        return out

    def _effective_ttl(self, resp):
        ttl = self._soft_ttl
        server = self._parse_max_age(resp.headers.get("Cache-Control"))
        if server is not None:
            ttl = min(ttl, server)
        # Floor, but never above the operator's configured soft TTL.
        return max(ttl, min(self._soft_ttl, PARTNER_KEY_MIN_TTL_SECONDS))

    @staticmethod
    def _parse_max_age(cache_control):
        if not cache_control:
            return None
        for part in cache_control.split(","):
            part = part.strip().lower()
            if part.startswith("max-age="):
                try:
                    return int(part.split("=", 1)[1])
                except ValueError:
                    return None
        return None
