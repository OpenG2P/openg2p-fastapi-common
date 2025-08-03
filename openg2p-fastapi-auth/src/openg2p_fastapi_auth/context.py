from contextvars import ContextVar

# TODO: Handle JWKs Cache properly
jwks_cache: ContextVar[dict] = ContextVar("jwks_cache", default=None)
