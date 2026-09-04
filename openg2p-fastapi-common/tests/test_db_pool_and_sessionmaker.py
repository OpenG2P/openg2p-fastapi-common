"""Unit tests for connection-pool settings and the process-wide sessionmaker."""

from unittest.mock import AsyncMock, MagicMock, patch

import openg2p_fastapi_common.app as app_mod
import pytest
from openg2p_fastapi_common.app import Initializer
from openg2p_fastapi_common.config import Settings
from openg2p_fastapi_common.context import (
    async_session_maker,
    dbengine,
    get_async_session_maker,
)
from sqlalchemy.ext.asyncio import async_sessionmaker


def _reset_db_globals():
    async_session_maker.set(None)
    dbengine.set(None)


@pytest.fixture(autouse=True)
def reset_db_globals():
    _reset_db_globals()
    yield
    _reset_db_globals()


def test_pool_settings_defaults_match_sqlalchemy():
    settings = Settings(_env_file=None)
    assert settings.db_pool_size == 5
    assert settings.db_pool_max_overflow == 10
    assert settings.db_pool_pre_ping is True
    assert settings.db_pool_recycle == 1800


def test_pool_settings_read_common_env(monkeypatch):
    monkeypatch.setenv("COMMON_DB_POOL_SIZE", "8")
    monkeypatch.setenv("COMMON_DB_POOL_MAX_OVERFLOW", "16")
    monkeypatch.setenv("COMMON_DB_POOL_PRE_PING", "false")
    monkeypatch.setenv("COMMON_DB_POOL_RECYCLE", "900")
    settings = Settings(_env_file=None)
    assert settings.db_pool_size == 8
    assert settings.db_pool_max_overflow == 16
    assert settings.db_pool_pre_ping is False
    assert settings.db_pool_recycle == 900


def test_get_async_session_maker_requires_engine():
    with pytest.raises(RuntimeError, match="Database engine is not initialized"):
        get_async_session_maker()


def test_get_async_session_maker_reuses_one_factory():
    dbengine.set(MagicMock(name="engine"))
    first = get_async_session_maker()
    second = get_async_session_maker()
    assert first is second
    assert isinstance(first, async_sessionmaker)
    assert callable(first)


def test_get_async_session_maker_returns_stored_factory_without_rebuilding():
    stored = MagicMock(name="stored_sessionmaker")
    async_session_maker.set(stored)
    dbengine.set(MagicMock(name="unused_engine"))
    assert get_async_session_maker() is stored


def test_init_db_passes_pool_kwargs_for_postgres(monkeypatch):
    captured = {}

    def fake_create(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return MagicMock(name="engine")

    monkeypatch.setattr(app_mod, "create_async_engine", fake_create)
    monkeypatch.setattr(app_mod._config, "db_datasource", "postgresql+asyncpg://u:p@localhost/db")
    monkeypatch.setattr(app_mod._config, "db_logging", False)
    monkeypatch.setattr(app_mod._config, "db_pool_pre_ping", True)
    monkeypatch.setattr(app_mod._config, "db_pool_recycle", 1800)
    monkeypatch.setattr(app_mod._config, "db_pool_size", 5)
    monkeypatch.setattr(app_mod._config, "db_pool_max_overflow", 10)

    Initializer.__new__(Initializer).init_db()

    assert captured["url"] == "postgresql+asyncpg://u:p@localhost/db"
    assert captured["kwargs"] == {
        "echo": False,
        "pool_pre_ping": True,
        "pool_recycle": 1800,
        "pool_size": 5,
        "max_overflow": 10,
    }
    engine = dbengine.get()
    maker = async_session_maker.get()
    assert engine is not None
    assert maker is not None
    assert maker.kw.get("expire_on_commit") is False
    assert get_async_session_maker() is maker


def test_init_db_omits_pool_kwargs_for_sqlite(monkeypatch):
    captured = {}

    def fake_create(url, **kwargs):
        captured["kwargs"] = kwargs
        return MagicMock(name="engine")

    monkeypatch.setattr(app_mod, "create_async_engine", fake_create)
    monkeypatch.setattr(app_mod._config, "db_datasource", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setattr(app_mod._config, "db_logging", True)

    Initializer.__new__(Initializer).init_db()

    assert captured["kwargs"] == {"echo": True}


def test_init_db_skips_when_datasource_missing(monkeypatch):
    monkeypatch.setattr(app_mod._config, "db_datasource", "")
    with patch.object(app_mod, "create_async_engine") as create_engine:
        Initializer.__new__(Initializer).init_db()
    create_engine.assert_not_called()
    assert dbengine.get() is None
    assert async_session_maker.get() is None


@pytest.mark.asyncio
async def test_shutdown_disposes_engine_and_clears_sessionmaker():
    engine = MagicMock()
    engine.dispose = AsyncMock()
    dbengine.set(engine)
    async_session_maker.set(MagicMock(name="sessionmaker"))

    await Initializer.__new__(Initializer).fastapi_app_shutdown(MagicMock())

    engine.dispose.assert_awaited_once()
    assert dbengine.get() is None
    assert async_session_maker.get() is None
