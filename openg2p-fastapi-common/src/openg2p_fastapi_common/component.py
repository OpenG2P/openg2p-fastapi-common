"""Module from initializing Component Class"""

from collections.abc import Callable
from functools import cached_property
from typing import Any, Self, Type

from .context import component_registry


class BaseComponent:
    def __init__(self, name=""):
        self.name = name
        component_registry.get().append(self)

    @classmethod
    def get_component(cls: Type[Self], name="", strict=False) -> Self:
        for component in component_registry.get():
            result = None
            if strict:
                if cls is type(component):
                    result = component
            else:
                if isinstance(component, cls):
                    result = component

            if result:
                if name:
                    if name == result.name:
                        return result
                else:
                    return result
        return None

    @classmethod
    def get_cached_component(
        cls: Type[Self], name="", strict=False, **kw
    ) -> cached_property[Callable[[Any], Self]]:
        return cached_property(lambda _: cls.get_component(name=name, strict=strict, **kw))
