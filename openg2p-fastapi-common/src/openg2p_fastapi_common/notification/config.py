import importlib


def load_impl(dotted_path: str):
    """Import 'pkg.module.ClassName' and return the class (config-driven selection)."""
    module_path, _, class_name = dotted_path.rpartition(".")
    return getattr(importlib.import_module(module_path), class_name)
