"""Module for initializing Contexts"""

from contextvars import ContextVar
from typing import TYPE_CHECKING, Generic, List, Optional, TypeVar

from fastapi import FastAPI
from pydantic_settings import BaseSettings
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

if TYPE_CHECKING:
    from .component import BaseComponent

T = TypeVar("T")


class GlobalVar(Generic[T]):
    """A simple wrapper that mimics ContextVar interface but stores value globally"""

    def __init__(self, name: str, default: Optional[T] = None):
        self._name = name
        self._value: Optional[T] = default

    def get(self) -> Optional[T]:
        return self._value

    def set(self, value: T) -> None:
        self._value = value


app_registry: GlobalVar[FastAPI] = GlobalVar("app_registry", default=None)

config_registry: ContextVar[list[BaseSettings]] = ContextVar("config_registry", default=None)

# Changed from ContextVar to a regular list for global singleton registry
component_registry: List["BaseComponent"] = []

dbengine: GlobalVar[AsyncEngine] = GlobalVar("dbengine", default=None)
async_session_maker: GlobalVar[async_sessionmaker] = GlobalVar("async_session_maker", default=None)


def get_async_session_maker() -> async_sessionmaker:
    """Return the process-wide session factory, creating it lazily if needed.

    ``async_sessionmaker`` is a factory, not a session — callers still do
    ``async with get_async_session_maker()() as session``.
    """
    maker = async_session_maker.get()
    if maker is not None:
        return maker
    engine = dbengine.get()
    if engine is None:
        raise RuntimeError("Database engine is not initialized")
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async_session_maker.set(maker)
    return maker
