"""Tests for PartnerMgmtKeyStore — the ``partner-mgmt`` crypto backend's key
source that fetches partner public keys from the Partner Management partner-api
and caches them in-process (soft/hard TTL, negative cache, unknown-kid refresh,
single-flight). Uses an injectable httpx MockTransport + a fake clock so no real
HTTP or wall-clock is involved.
"""

import asyncio

import httpx
import pytest
from openg2p_fastapi_common.utils.crypto import PartnerMgmtKeyStore

PEM1 = "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----"
PEM2 = "-----BEGIN PUBLIC KEY-----\nBBB\n-----END PUBLIC KEY-----"


def _resp(keys, max_age=300, status=200):
    headers = {"Cache-Control": f"public, max-age={max_age}"} if max_age is not None else {}
    if status == 404:
        return httpx.Response(404, json={"errors": [{"code": "PM-KEY-404"}]})
    return httpx.Response(status, json={"partner_id": "P", "keys": keys}, headers=headers)


class Handler:
    """Programmable, counting MockTransport handler."""

    def __init__(self, fn):
        self.calls = 0
        self.fn = fn

    def __call__(self, request):
        self.calls += 1
        return self.fn(request)


def _store(handler, **kw):
    clk = {"t": 0.0}
    defaults = {"soft_ttl": 300, "hard_ttl": 6000, "negative_ttl": 30, "refresh_cooldown": 10}
    defaults.update(kw)
    store = PartnerMgmtKeyStore(
        api_url="http://pm",
        transport=httpx.MockTransport(handler),
        clock=lambda: clk["t"],
        **defaults,
    )
    return store, clk


@pytest.mark.asyncio
async def test_cache_hit_then_soft_ttl_refresh():
    h = Handler(lambda r: _resp([{"kid": "k1", "algorithm": "RS256", "public_key": PEM1}]))
    store, clk = _store(h)

    r1 = await store.get_keys("P")
    assert h.calls == 1 and r1[0]["public_key_pem"] == PEM1 and r1[0]["kid"] == "k1"

    clk["t"] = 100  # within soft TTL -> served from cache, no HTTP
    await store.get_keys("P")
    assert h.calls == 1

    clk["t"] = 400  # past soft TTL -> refresh
    await store.get_keys("P")
    assert h.calls == 2


@pytest.mark.asyncio
async def test_cache_control_shortens_ttl():
    # Server max-age=50 < client soft_ttl=300 -> effective TTL is 50.
    h = Handler(lambda r: _resp([{"kid": "k1", "algorithm": "RS256", "public_key": PEM1}], max_age=50))
    store, clk = _store(h, soft_ttl=300)

    await store.get_keys("P")
    clk["t"] = 40  # < 50 -> cached
    await store.get_keys("P")
    assert h.calls == 1
    clk["t"] = 60  # > 50 (honored server max-age) -> refetch
    await store.get_keys("P")
    assert h.calls == 2


@pytest.mark.asyncio
async def test_404_negative_cached_then_refetched():
    h = Handler(lambda r: _resp(None, status=404))
    store, clk = _store(h, negative_ttl=30)

    assert await store.get_keys("GONE") is None and h.calls == 1
    clk["t"] = 10  # within negative TTL -> no HTTP
    assert await store.get_keys("GONE") is None and h.calls == 1
    clk["t"] = 45  # past negative TTL -> retry
    await store.get_keys("GONE")
    assert h.calls == 2


@pytest.mark.asyncio
async def test_unknown_kid_forces_refresh_rate_limited():
    state = {"keys": [{"kid": "k1", "algorithm": "RS256", "public_key": PEM1}]}
    h = Handler(lambda r: _resp(state["keys"]))
    store, clk = _store(h, soft_ttl=300, refresh_cooldown=10)

    await store.get_keys("P")  # caches k1
    assert h.calls == 1

    # partner rotated to k2; a request presenting k2 within the cooldown does NOT refetch
    clk["t"] = 5
    await store.get_keys("P", wanted_kid="k2")
    assert h.calls == 1

    # after the cooldown, the unknown kid forces one refresh; PM now returns k1+k2
    state["keys"] = [
        {"kid": "k1", "algorithm": "RS256", "public_key": PEM1},
        {"kid": "k2", "algorithm": "RS256", "public_key": PEM2},
    ]
    clk["t"] = 20
    r = await store.get_keys("P", wanted_kid="k2")
    assert h.calls == 2 and any(k["kid"] == "k2" for k in r)

    clk["t"] = 25  # k2 now known -> no more fetches
    await store.get_keys("P", wanted_kid="k2")
    assert h.calls == 2


@pytest.mark.asyncio
async def test_stale_served_on_error_then_fail_closed_past_hard_ttl():
    ok = [{"kid": "k1", "algorithm": "RS256", "public_key": PEM1}]
    mode = {"fail": False}

    def fn(request):
        if mode["fail"]:
            raise httpx.ConnectError("PM down")
        return _resp(ok)

    h = Handler(fn)
    store, clk = _store(h, soft_ttl=300, hard_ttl=500, refresh_cooldown=10)

    assert (await store.get_keys("P"))[0]["public_key_pem"] == PEM1  # warm cache
    mode["fail"] = True

    clk["t"] = 350  # stale + PM down, within hard TTL -> serve stale
    assert (await store.get_keys("P"))[0]["public_key_pem"] == PEM1
    calls_after_stale = h.calls

    clk["t"] = 355  # within cooldown -> no new attempt, still stale
    assert (await store.get_keys("P"))[0]["public_key_pem"] == PEM1
    assert h.calls == calls_after_stale

    clk["t"] = 600  # past hard TTL + PM still down -> fail closed
    assert await store.get_keys("P") is None


@pytest.mark.asyncio
async def test_single_flight_collapses_concurrent_misses():
    async def slow_fn(request):
        return _resp([{"kid": "k1", "algorithm": "RS256", "public_key": PEM1}])

    # httpx MockTransport handler is sync; simulate concurrency at the get_keys level.
    h = Handler(lambda r: _resp([{"kid": "k1", "algorithm": "RS256", "public_key": PEM1}]))
    store, _ = _store(h)

    results = await asyncio.gather(*[store.get_keys("P") for _ in range(10)])
    assert all(r[0]["public_key_pem"] == PEM1 for r in results)
    assert h.calls == 1  # single-flight: 10 concurrent misses -> 1 HTTP call
