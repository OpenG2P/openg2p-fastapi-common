from contextvars import ContextVar
from typing import Any, Dict, List, Optional

auth_id_type_config_cache: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
    "auth_id_type_config_cache", default=None
)

user_fields_cache: ContextVar[Optional[List[str]]] = ContextVar("user_fields_cache", default=None)
