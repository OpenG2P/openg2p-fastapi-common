DEFAULT_ALLOWED_ALGORITHMS = ("RS256",)
DEFAULT_SIGNING_ALGORITHM = "RS256"
DEFAULT_PARTNER_KEY_CACHE_TTL_SECONDS = 300
# Absolute lower bound for the partner-mgmt cache TTL, so a tiny/absent server
# max-age can never make the client refetch on effectively every request.
PARTNER_KEY_MIN_TTL_SECONDS = 30


def is_forbidden_algorithm(alg) -> bool:
    """Algorithms that are NEVER allowed regardless of config: ``none`` and the
    HMAC family (HS*) — accepting a symmetric alg against an asymmetric key store
    is the classic JWS algorithm-confusion attack."""
    if not alg or str(alg).lower() == "none":
        return True
    return str(alg).upper().startswith("HS")
