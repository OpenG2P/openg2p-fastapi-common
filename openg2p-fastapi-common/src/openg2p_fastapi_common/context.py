"""Module for initializing Contexts"""

from contextvars import ContextVar
from typing import TYPE_CHECKING

from fastapi import FastAPI
from pydantic_settings import BaseSettings
from sqlalchemy.ext.asyncio import AsyncEngine

if TYPE_CHECKING:
    from .component import BaseComponent

app_registry: ContextVar[FastAPI] = ContextVar("app_registry", default=None)

config_registry: ContextVar[list[BaseSettings]] = ContextVar("config_registry", default=None)

component_registry: ContextVar[list["BaseComponent"]] = ContextVar("component_registry", default=None)

dbengine: ContextVar[AsyncEngine] = ContextVar("dbengine", default=None)
