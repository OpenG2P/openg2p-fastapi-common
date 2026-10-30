from ..config import Settings
from .interface import CryptoHelper
from .keymanager import KeymanagerCryptoHelper
from .partner_mgmt_key_store import PartnerMgmtKeyStore
from .pyjwt import PyJWTCryptoHelper

_PYJWT_BACKENDS = frozenset({"pyjwt", "local", "jwt"})
_KEYMANAGER_BACKENDS = frozenset({"keymanager"})
_PARTNER_MGMT_BACKENDS = frozenset({"partner-mgmt", "partner_mgmt", "partnermgmt"})


class CryptoFactory:
    """Select a ``CryptoHelper`` implementation from ``crypto_backend``.

    ``crypto_backend`` (config) selects, unless ``backend`` is passed to ``build``:
      * ``pyjwt`` (default) / ``local`` — in-process PyJWT JWS via
        ``PyJWTCryptoHelper`` and a DB-backed ``PartnerKeyStore``.
      * ``partner-mgmt`` — same PyJWT helper, keys from Partner Management
        (``PartnerMgmtKeyStore``).
      * ``keymanager`` — remote Keymanager service (``KeymanagerCryptoHelper``).
    Extra kwargs pass through to the chosen helper.
    """

    @classmethod
    def build(cls, name="", backend=None, **kwargs) -> CryptoHelper:
        cfg = Settings.get_config(strict=False)
        selected = (backend if backend is not None else cfg.crypto_backend) or "pyjwt"
        selected = str(selected).strip().lower()
        if selected in _KEYMANAGER_BACKENDS:
            return KeymanagerCryptoHelper(name=name, **kwargs)
        if selected in _PARTNER_MGMT_BACKENDS:
            store = kwargs.pop("partner_key_store", None) or PartnerMgmtKeyStore()
            return PyJWTCryptoHelper(name=name, partner_key_store=store, **kwargs)
        if selected in _PYJWT_BACKENDS:
            return PyJWTCryptoHelper(name=name, **kwargs)
        raise ValueError(
            f"Unknown crypto_backend {selected!r}; expected pyjwt, local, partner-mgmt, or keymanager"
        )

    @classmethod
    def get(cls, name="", **kwargs) -> CryptoHelper:
        """Return the registered ``CryptoHelper``, or build one from config."""
        existing = CryptoHelper.get_component(name=name)
        if existing is not None:
            return existing
        return cls.build(name=name, **kwargs)
