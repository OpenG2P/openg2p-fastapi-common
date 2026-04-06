"""Module for initializing Contexts"""

from contextvars import ContextVar
from typing import TYPE_CHECKING, Generic, List, Optional, TypeVar

from fastapi import FastAPI
from pydantic_settings import BaseSettings
from sqlalchemy.ext.asyncio import AsyncEngine

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
