import base64
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from sqlalchemy import select

from ..config import Settings

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


def _cert_thumbprint(pem):
    pem_bytes = pem.encode() if isinstance(pem, str) else pem
    cert = load_pem_x509_certificate(pem_bytes)
    return base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).decode().rstrip("=")


async def seed_partner_certs(certs, session_maker=None):
    """Upsert partner public certs into the partner_keys table (idempotent).

    Seed-based onboarding for the local / pyjwt backend. Each entry is a dict:
    ``{"reference_id": "PARTNER_<MNEMONIC>", "public_key": "<PEM>",
    "kid": "<optional>", "algorithm": "RS256"}``. kid defaults to the cert's
    SHA-256 thumbprint. An entry whose (reference_id, kid) already exists is left
    untouched, so re-running migrate on upgrade is safe.
    """
    if not certs:
        return
    from ..models import PartnerKey

    if session_maker is None:
        from ..context import get_async_session_maker

        session_maker = get_async_session_maker()

    added = 0
    async with session_maker() as session:
        for entry in certs:
            reference_id = entry.get("reference_id")
            public_key = entry.get("public_key")
            if not reference_id or not public_key:
                _logger.warning("Skipping partner cert with missing reference_id/public_key")
                continue
            try:
                kid = entry.get("kid") or _cert_thumbprint(public_key)
            except Exception:
                _logger.exception("Invalid partner cert PEM for '%s'; skipping", reference_id)
                continue
            algorithm = entry.get("algorithm") or "RS256"
            existing = await session.execute(
                select(PartnerKey).where(PartnerKey.reference_id == reference_id, PartnerKey.kid == kid)
            )
            if existing.scalars().first():
                continue
            session.add(
                PartnerKey(
                    reference_id=reference_id,
                    public_key=public_key,
                    kid=kid,
                    algorithm=algorithm,
                    status="active",
                )
            )
            added += 1
        if added:
            await session.commit()
    _logger.info("Seeded %d partner cert(s) into partner_keys", added)
