"""Module from initializing Component Class"""

import sys
from collections.abc import Callable
from functools import cached_property
from typing import Any

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from .context import component_registry


class BaseComponent:
    def __init__(self, name=""):
        self.name = name
        cr = component_registry.get()
        if not cr:
            cr = []
            component_registry.set(cr)
        cr.append(self)

    @classmethod
    def get_component(cls, name="", strict=False) -> Self:
        cr = component_registry.get() or []
        for component in cr:
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
    def get_cached_component(cls, name="", strict=False, **kw) -> cached_property[Callable[[Any], Self]]:
        return cached_property(lambda _: cls.get_component(name=name, strict=strict, **kw))
