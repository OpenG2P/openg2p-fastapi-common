"""Unit tests for the local (Keymanager-free) JWS backend in crypto.

Exercises ``PyJWTCryptoHelper`` (.p12 signing + DB-backed cert verification via
``PartnerKeyStore`` over an in-memory SQLite ``partner_keys`` table),
``seed_partner_certs`` (idempotent seed-based onboarding), and the
``CryptoFactory`` backend selection. Default backend is ``pyjwt``.
``KeymanagerCryptoHelper`` is selected by ``crypto_backend="keymanager"``.
"""

import base64
import datetime

import orjson
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12
from cryptography.x509.oid import NameOID
from openg2p_fastapi_common.crypto import (
    CryptoFactory,
    CryptoHelper,
    KeymanagerCryptoHelper,
    PartnerKeyStore,
    PyJWTCryptoHelper,
    is_forbidden_algorithm,
    seed_partner_certs,
)
from openg2p_fastapi_common.models import BaseORMModelWithId
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

P12_PASSWORD = b"unit-test"
BODY = {"request_header": {"sender_app_mnemonic": "my-psp"}, "amount": 100, "z": 1, "a": 2}


def _make_keypair(cn="unit-test"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2020, 1, 1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _cert_pem(cert):
    return cert.public_bytes(Encoding.PEM).decode()


def _thumbprint(cert):
    return base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).decode().rstrip("=")


def _write_p12(path, key, cert, password=P12_PASSWORD):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    path.write_bytes(pkcs12.serialize_key_and_certificates(b"t", key, cert, None, enc))
    return str(path)


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(BaseORMModelWithId.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _helper(maker, key, cert, tmp_path, password=P12_PASSWORD.decode()):
    return PyJWTCryptoHelper(
        partner_key_store=PartnerKeyStore(session_maker=maker, cache_ttl_seconds=0),
        signing_key_path=_write_p12(tmp_path / "s.p12", key, cert),
        signing_key_password=password,
        allowed_algorithms=["RS256"],
    )


def test_forbidden_algorithms():
    assert is_forbidden_algorithm("none") is True
    assert is_forbidden_algorithm("HS256") is True
    assert is_forbidden_algorithm("") is True
    assert is_forbidden_algorithm("RS256") is False


def test_factory_selects_backend():
    assert isinstance(CryptoFactory.build(allowed_algorithms=["RS256"]), PyJWTCryptoHelper)
    assert isinstance(CryptoFactory.build(backend="pyjwt", allowed_algorithms=["RS256"]), PyJWTCryptoHelper)
    assert isinstance(CryptoFactory.build(backend="local", allowed_algorithms=["RS256"]), PyJWTCryptoHelper)
    assert isinstance(CryptoFactory.build(backend="keymanager"), KeymanagerCryptoHelper)
    helper = CryptoFactory.build(backend="partner-mgmt", allowed_algorithms=["RS256"])
    assert isinstance(helper, PyJWTCryptoHelper)
    try:
        CryptoFactory.build(backend="unknown")
        raise AssertionError("expected ValueError for unknown backend")
    except ValueError:
        pass


def test_get_crypto_helper_uses_interface_and_reuses_instance():
    helper = CryptoFactory.get(allowed_algorithms=["RS256"])
    assert isinstance(helper, CryptoHelper)
    assert CryptoFactory.get() is helper


@pytest.mark.asyncio
async def test_sign_then_verify(db, tmp_path):
    key, cert = _make_keypair()
    await seed_partner_certs(
        [{"reference_id": "PARTNER_MY_PSP", "public_key": _cert_pem(cert)}], session_maker=db
    )
    helper = _helper(db, key, cert, tmp_path)
    sig = await helper.create_jwt_token(BODY)
    assert await helper.verify_jwt(sig, payload=BODY, km_ref_id="PARTNER_MY_PSP") is True


@pytest.mark.asyncio
async def test_tampered_rejected(db, tmp_path):
    key, cert = _make_keypair()
    await seed_partner_certs(
        [{"reference_id": "PARTNER_MY_PSP", "public_key": _cert_pem(cert)}], session_maker=db
    )
    helper = _helper(db, key, cert, tmp_path)
    sig = await helper.create_jwt_token(BODY)
    assert await helper.verify_jwt(sig, payload={**BODY, "amount": 9}, km_ref_id="PARTNER_MY_PSP") is False


@pytest.mark.asyncio
async def test_unknown_partner_rejected(db, tmp_path):
    key, cert = _make_keypair()
    await seed_partner_certs(
        [{"reference_id": "PARTNER_MY_PSP", "public_key": _cert_pem(cert)}], session_maker=db
    )
    helper = _helper(db, key, cert, tmp_path)
    sig = await helper.create_jwt_token(BODY)
    assert await helper.verify_jwt(sig, payload=BODY, km_ref_id="PARTNER_NOPE") is False


@pytest.mark.asyncio
async def test_hmac_and_none_rejected(db, tmp_path):
    key, cert = _make_keypair()
    await seed_partner_certs(
        [{"reference_id": "PARTNER_MY_PSP", "public_key": _cert_pem(cert)}], session_maker=db
    )
    helper = _helper(db, key, cert, tmp_path)
    for alg in ("HS256", "none"):
        header = base64.urlsafe_b64encode(orjson.dumps({"alg": alg})).decode().rstrip("=")
        assert await helper.verify_jwt(f"{header}..x", payload=BODY, km_ref_id="PARTNER_MY_PSP") is False


@pytest.mark.asyncio
async def test_seed_is_idempotent(db):
    _key, cert = _make_keypair()
    entry = [{"reference_id": "PARTNER_MY_PSP", "public_key": _cert_pem(cert)}]
    await seed_partner_certs(entry, session_maker=db)
    await seed_partner_certs(entry, session_maker=db)
    store = PartnerKeyStore(session_maker=db, cache_ttl_seconds=0)
    keys = await store.get_keys("PARTNER_MY_PSP")
    assert keys is not None and len(keys) == 1
    assert keys[0]["kid"] == _thumbprint(cert)
